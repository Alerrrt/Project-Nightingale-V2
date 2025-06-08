# backend/app/tasks/scan_tasks.py
import subprocess
import json
from ..core.celery_app import celery_app
from ..database.session import SessionLocal
from ..database.models import Scan, Vulnerability

@celery_app.task
def run_full_scan(scan_id: int):
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return

    # --- 1. Update Scan Status ---
    scan.status = "RUNNING"
    db.commit()

    target_domain = scan.target.domain
    results_dir = f"/tmp/scan_{scan_id}"
    subprocess.run(["mkdir", "-p", results_dir])

    try:
        # --- 2. Subdomain Enumeration ---
        print(f"[{scan_id}] Running subfinder...")
        subdomains_file = f"{results_dir}/subdomains.txt"
        subprocess.run(
            ["subfinder", "-d", target_domain, "-o", subdomains_file],
            check=True, capture_output=True
        )

        # --- 3. Live Host Discovery ---
        print(f"[{scan_id}] Running httpx...")
        live_hosts_file = f"{results_dir}/live_hosts.txt"
        subprocess.run(
            ["httpx", "-l", subdomains_file, "-o", live_hosts_file],
            check=True, capture_output=True
        )
        
        # --- 4. Vulnerability Scanning with Nuclei ---
        print(f"[{scan_id}] Running nuclei...")
        nuclei_results_file = f"{results_dir}/nuclei.json"
        subprocess.run(
            ["nuclei", "-l", live_hosts_file, "-json", "-o", nuclei_results_file],
            check=True, capture_output=True
        )

        # --- 5. Process and Store Results ---
        with open(nuclei_results_file, 'r') as f:
            for line in f:
                result = json.loads(line)
                new_vuln = Vulnerability(
                    scan_id=scan_id,
                    host=result.get('host'),
                    name=result['info'].get('name'),
                    severity=result['info'].get('severity'),
                    description=result['info'].get('description', 'N/A'),
                    details=result
                )
                db.add(new_vuln)
        
        scan.status = "COMPLETED"
        db.commit()

    except subprocess.CalledProcessError as e:
        scan.status = "FAILED"
        db.commit()
        print(f"Error during scan {scan_id}: {e.stderr.decode()}")
    finally:
        db.close()