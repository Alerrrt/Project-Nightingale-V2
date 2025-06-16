import json
import uuid # Import uuid for generating unique IDs
from datetime import datetime # Import datetime
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel # Removed HttpUrl import as it's no longer needed here
from pydantic.networks import Url # Import Url to specifically convert it
from typing import Optional, Dict, Any, List, Union
import asyncio # Import asyncio

from backend.types.models import ScanInput, Finding, Severity, ModuleStatus, HistoricalScanSummary, RequestLog # Import all necessary models
from backend.api.realtime import send_realtime_update, send_progress_update, send_new_finding, active_connections, send_module_status_update # Import real-time update functions and active_connections
from backend.shared_state import historical_scans_db # Import historical_scans_db

# Remove direct imports of plugin_manager and scanner_engine from backend.main
# from backend.main import plugin_manager, scanner_engine # REMOVED

# class HistoricalScanSummary(BaseModel):
#     scan_id: str
#     target: str
#     start_time: str # Use a string for simplicity, datetime in real app
#     status: str # e.g., "completed", "running", "failed"
#     finding_count: int
#     severity_counts: dict[str, int] # e.g., {"Critical": 2, "High": 5}
#     overall_score: float

# Placeholder for storing scan results by ID in memory
scan_results_db: Dict[str, List[Finding]] = {}
# Placeholder for historical scan data in memory
# historical_scans_db: List[HistoricalScanSummary] = [] # REMOVED: Now imported from shared_state.py

def convert_urls_to_strings(data: Union[Dict, List, Any]) -> Union[Dict, List, Any]:
    """
    Recursively converts Pydantic Url objects to strings within a dictionary or list.
    """
    if isinstance(data, dict):
        return {k: convert_urls_to_strings(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [convert_urls_to_strings(elem) for elem in data]
    elif isinstance(data, Url):
        return str(data) # Convert any Pydantic Url type to string
    return data

# Define the router within a function that accepts dependencies
def create_scans_router(scanner_engine_instance, plugin_manager_instance):
    router = APIRouter(prefix="/scans")

    # Use the passed instances instead of globally declared ones
    plugin_manager = plugin_manager_instance
    scanner_engine = scanner_engine_instance

    class StartScanResponse(BaseModel):
        scan_id: str
        message: str

    async def _run_scan_task(scan_id: str, scan_input: ScanInput):
        """
        Background task to run the actual scan and send real-time updates.
        """
        # Callback function for scanner engine to send updates
        async def update_callback(update_data: Dict[str, Any]):
            # Ensure update_data contains scan_id and is correctly formatted
            if "scan_id" in update_data and update_data["scan_id"] == scan_id:
                update_type = update_data.get("type")
                data = update_data.get("data")

                if update_type == "scan_progress":
                    # data should already be a dictionary from ScannerEngine's _send_progress_update
                    if isinstance(data, dict):
                        await send_progress_update(scan_id, data)
                    else:
                        print(f"Warning: Unexpected data format for scan_progress update: {data}")
                elif update_type == "new_finding":
                    print(f"Debug [scans.py]: update_callback received new_finding. Raw data type: {type(data)}")
                    if isinstance(data, Finding):
                        finding_dict = data.model_dump()
                        json_serializable_finding = convert_urls_to_strings(finding_dict)
                        print(f"Debug [scans.py]: After model_dump() and URL conversion. Data type: {type(json_serializable_finding)}, first 100 chars: {str(json_serializable_finding)[:100]}")
                        await send_new_finding(scan_id, json_serializable_finding)
                    else:
                        json_serializable_finding = convert_urls_to_strings(data)
                        print(f"Debug [scans.py]: After URL conversion (non-Finding). Data type: {type(json_serializable_finding)}, first 100 chars: {str(json_serializable_finding)[:100]}")
                        await send_new_finding(scan_id, json_serializable_finding)
                elif update_type == "module_status":
                    # data should already be a dictionary from ModuleStatus.model_dump()
                    await send_module_status_update(scan_id, ModuleStatus(**data))

        # Register the callback with the scanner engine immediately
        scanner_engine.register_update_callback(update_callback)

        # Add initial scan summary to historical_scans_db with "started" status immediately
        historical_scans_db.append(
            HistoricalScanSummary(
                scan_id=scan_id,
                target=str(scan_input.target),
                start_time=str(datetime.now()),
                status="started", # Set initial status to "started"
                finding_count=0,
                severity_counts={},
                overall_score=0.0
            )
        )

        try:
            print(f"Background scan task started for ID: {scan_id} target: {scan_input.target}")

            # Wait for WebSocket connection to be established before starting real-time updates from scanner_engine
            # This wait is now primarily to ensure frontend is ready to receive initial status messages,
            # as updates will be queued by send_realtime_update even if WS is not yet active.
            max_wait_time = 20 # Increased from 10 to 20 seconds
            wait_interval = 0.1 # seconds
            waited_time = 0
            while scan_id not in active_connections and waited_time < max_wait_time:
                print(f"_run_scan_task: Waiting for WebSocket connection for scan_id: {scan_id}...")
                await asyncio.sleep(wait_interval)
                waited_time += wait_interval

            if scan_id not in active_connections:
                print(f"_run_scan_task: WebSocket connection for scan_id {scan_id} not established within {max_wait_time} seconds. Updates might be missed, continuing scan...") # Added more context
            else:
                # Send initial status update only if WebSocket is active
                await send_realtime_update(scan_id, "status", "started")

            # Perform the actual scan
            final_findings = await scanner_engine.run_scan(scan_input, scan_id=scan_id)

            print(f"Final findings from scan_engine for scan ID {scan_id}: {final_findings}") # Debug print
            scan_results_db[scan_id] = final_findings

            # Calculate summary for historical record
            severity_counts = {sev.value: 0 for sev in Severity}
            overall_score = 0.0
            if final_findings:
                for finding in final_findings:
                    severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
                # Calculate overall score based on processed findings
                overall_score = sum(f.score for f in final_findings if f.score is not None) / len(final_findings)

            # Find the existing entry in historical_scans_db and update it
            for i, scan_summary in enumerate(historical_scans_db):
                if scan_summary.scan_id == scan_id:
                    historical_scans_db[i] = HistoricalScanSummary(
                        scan_id=scan_id,
                        target=str(scan_input.target),
                        start_time=scan_summary.start_time,
                        status="completed",
                        finding_count=len(final_findings),
                        severity_counts=severity_counts,
                        overall_score=round(overall_score, 2)
                    )
                    break
            else: # If scan_id not found, append (shouldn't happen with immediate add)
                historical_scans_db.append(
                    HistoricalScanSummary(
                        scan_id=scan_id,
                        target=str(scan_input.target),
                        start_time=str(datetime.now()), # Fallback if not found
                        status="completed",
                        finding_count=len(final_findings),
                        severity_counts=severity_counts,
                        overall_score=round(overall_score, 2)
                    )
                )

            # Send completion status
            await send_realtime_update(scan_id, "status", "completed")
            print(f"Background scan task completed for ID: {scan_id}")

        except Exception as e:
            print(f"Background scan task failed for ID: {scan_id}: {e}")
            # Send a failure status update
            await send_realtime_update(scan_id, "status", f"failed: {e}")
            # Update historical scan status to failed
            for scan_summary in historical_scans_db:
                if scan_summary.scan_id == scan_id:
                    scan_summary.status = "failed"
                    scan_summary.overall_score = 0.0 # Set score to 0 on failure
                    break

    @router.post("/start", response_model=StartScanResponse)
    async def start_scan(scan_input: ScanInput, background_tasks: BackgroundTasks):
        """
        Starts a new scan for the provided target as a background task.
        """
        if not scan_input.target:
            raise HTTPException(status_code=400, detail="Target URL is required")

        scan_id = str(uuid.uuid4()) # Generate a unique scan ID

        # Add the scan task to background tasks
        background_tasks.add_task(_run_scan_task, scan_id, scan_input)

        print(f"Scan initiation request received for target: {scan_input.target}, Scan ID: {scan_id}")
        return StartScanResponse(scan_id=scan_id, message="Scan initiated successfully.")
    
    @router.get("/history", response_model=List[HistoricalScanSummary])
    async def get_historical_scans(): # type: ignore
        """
        Retrieves a list of historical scan summaries.
        """
        return historical_scans_db


    @router.get("/{scan_id}/results", response_model=List[Finding])
    async def get_scan_results(scan_id: str): # type: ignore
        """
        Retrieves the full scan results for a specific scan ID.
        """
        if scan_id not in scan_results_db:
            raise HTTPException(status_code=404, detail=f"Scan results for ID {scan_id} not found")
        return scan_results_db[scan_id]

    @router.get("/scanners", response_model=Dict[str, dict])
    async def list_scanners():
        """
        Lists all registered scanners and their metadata.
        """
        from backend.scanners.scanner_registry import ScannerRegistry
        return ScannerRegistry.get_instance().get_all_scanner_metadata()

    # You would also need endpoints for:
    # - Getting scan status (/scans/{scan_id}/status)
    # - Connecting to real-time updates (/scans/{scan_id}/realtime)

    # Note: The real-time updates would likely be handled by a separate
    # WebSocket or SSE endpoint, potentially in a different module (e.g., backend/api/realtime.py)

    return router