import asyncio
import json
from typing import List, Optional, Any, Dict, Type, Callable
import importlib.util
import sys # Import sys to manage sys.path
import uuid # Import uuid for generating IDs
import logging
import pkgutil
from backend.plugins.base_plugin import BasePlugin
from backend.utils.logging_config import get_context_logger
from backend.utils.circuit_breaker import circuit_breaker
from backend.utils.resource_monitor import ResourceMonitor

from backend.config_types.models import Finding, ScanInput, PluginConfig, Severity, OwaspCategory, RequestLog, ModuleStatus # Import all necessary models
from pydantic import validate_call

logger = get_context_logger(__name__)

class NucleiPlugin:
    @validate_call
    def __init__(self, nuclei_path: str = "nuclei"):
        self.nuclei_path = nuclei_path

    @validate_call
    async def _perform_nuclei_scan(self, scan_input: ScanInput, config: Optional[PluginConfig] = None) -> List[Finding]:
        """
        Runs a Nuclei scan against the target.
        Note: This is a basic implementation. More advanced features like
        template selection, rate limiting, etc., would be added here.
        """
        print(f"Starting Nuclei scan for target: {scan_input.target}")

        # Construct the basic Nuclei command
        command = [self.nuclei_path, "-u", scan_input.target, "-json"] # Convert HttpUrl to string

        # Add templates from config if provided
        if config and config.options and config.options.get("templates"):
            command.extend(["-t", config.options["templates"]])

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                print(f"Nuclei scan failed: {stderr.decode()}")
                return []

            # Parse Nuclei's JSON output line by line
            findings: List[Finding] = []
            for line in stdout.decode().splitlines():
                try:
                    nuclei_finding = json.loads(line)
                    
                    # Normalize Nuclei output to the Finding model fields.
                    # This is a more comprehensive mapping than before.
                    
                    # Map Nuclei severity to our Severity enum
                    severity_map = {
                        "critical": Severity.CRITICAL,
                        "high": Severity.HIGH,
                        "medium": Severity.MEDIUM,
                        "low": Severity.LOW,
                        "info": Severity.INFO,
                        "unknown": Severity.INFO # Default for unknown
                    }
                    nuclei_severity = nuclei_finding.get("info", {}).get("severity", "unknown").lower()
                    mapped_severity = severity_map.get(nuclei_severity, Severity.INFO)

                    # Map Nuclei tags/info to OWASP categories (example, needs comprehensive mapping)
                    owasp_category = OwaspCategory.UNKNOWN
                    if "cve" in nuclei_finding.get("info", {}).get("tags", []):
                        owasp_category = OwaspCategory.A06_VULNERABLE_AND_OUTDATED_COMPONENTS
                    elif "sqli" in nuclei_finding.get("info", {}).get("tags", []):
                        owasp_category = OwaspCategory.A03_INJECTION
                    # Add more specific mappings based on Nuclei template tags or info fields

                    # Adapt to engine normalization pipeline expected fields
                    normalized: Dict[str, Any] = {
                        "title": nuclei_finding.get("info", {}).get("name", "Nuclei Finding"),
                        "severity": mapped_severity.value if hasattr(mapped_severity, "value") else str(mapped_severity),
                        "description": nuclei_finding.get("info", {}).get("description", "No description provided."),
                        "remediation": nuclei_finding.get("info", {}).get("remediation", "See Nuclei template information."),
                        "location": str(nuclei_finding.get("matched-at", scan_input.target)),
                        "owasp_category": owasp_category.value if hasattr(owasp_category, "value") else str(owasp_category),
                        "evidence": json.dumps(nuclei_finding, indent=2),
                    }
                    # Attach CWE when provided by Nuclei template
                    cwe_id = nuclei_finding.get("info", {}).get("cwe-id")
                    if cwe_id:
                        normalized["cwe"] = cwe_id if isinstance(cwe_id, str) else str(cwe_id)

                    findings.append(normalized)  # Engine will transform
                except json.JSONDecodeError:
                    print(f"Could not decode Nuclei JSON output line: {line}")
                except Exception as e:
                    print(f"Error processing Nuclei finding: {e}")

            return findings
        except FileNotFoundError:
            print(f"Error: Nuclei executable not found at {self.nuclei_path}. Is Nuclei installed and in your PATH or specified correctly?")
            return []
        except Exception as e:
            print(f"Error running Nuclei scan: {e}")
            return []

def load_plugin():
    """Function required by PluginManager to load the plugin."""
    return NucleiPlugin()

class PluginManager:
    """Manager for security scanner plugins."""

    def __init__(self):
        self._plugins: Dict[str, Type[BasePlugin]] = {}
        self._instances: Dict[str, BasePlugin] = {}
        self._config: Optional[Dict] = None
        self._resource_monitor: Optional[ResourceMonitor] = None
        self._metrics: Dict[str, Any] = {
            "total_plugins": 0,
            "active_plugins": 0,
            "plugin_errors": 0
        }
        self.loaded_plugins = {}
        self._update_callback: Optional[Callable] = None

    def configure(self, config: Dict):
        """Configure the plugin manager."""
        self._config = config
        if "resource_limits" in config:
            self._resource_monitor = ResourceMonitor(config["resource_limits"])
        logger.info(
            "Plugin manager configured",
            extra={"config": config}
        )

    @circuit_breaker(failure_threshold=3, recovery_timeout=30.0, name="plugin_manager")
    async def load_plugins(self):
        """Load all available plugins."""
        try:
            # Import plugin modules
            import backend.plugins
            
            # Find all plugin modules
            for _, name, _ in pkgutil.iter_modules(backend.plugins.__path__):
                if name != "base_plugin":
                    try:
                        # Import module
                        module = importlib.import_module(f"backend.plugins.{name}")
                        
                        # Find plugin class
                        for item_name in dir(module):
                            item = getattr(module, item_name)
                            if (
                                isinstance(item, type)
                                and issubclass(item, BasePlugin)
                                and item != BasePlugin
                            ):
                                # Register plugin
                                self._plugins[name] = item
                                self.loaded_plugins[name] = item() # Instantiate and store for direct use
                                logger.info(
                                    "Plugin registered and instantiated",
                                    extra={
                                        "plugin_name": name,
                                        "class": item.__name__
                                    }
                                )
                    except ModuleNotFoundError as e:
                        missing = e.name
                        logger.warning(
                            "Skipping plugin %r: missing dependency %r",
                            name,
                            missing,
                            extra={"plugin": name, "missing_dependency": missing}
                        )
                        continue
                    except Exception as e:
                        logger.error(
                            f"Error loading plugin module: {name}",
                            exc_info=True
                        )
            
            # Update metrics
            self._metrics["total_plugins"] = len(self._plugins)
            
            logger.info(
                "Plugins loaded",
                extra={"plugin_count": len(self._plugins)}
            )
            
        except Exception as e:
            logger.error("Error loading plugins", exc_info=True)
            raise

    async def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin instance by name."""
        return self.loaded_plugins.get(name)

    def get_plugins(self) -> List[str]:
        """Get list of available plugin names."""
        return list(self.loaded_plugins.keys())

    async def check_plugin_health(self, name: str) -> bool:
        """Check health of a plugin."""
        try:
            plugin = await self.get_plugin(name)
            if not plugin:
                return False
            
            # Check health
            return await plugin.check_health()
            
        except Exception as e:
            logger.error(
                f"Error checking plugin health: {name}",
                exc_info=True
            )
            return False

    async def get_plugin_metrics(self, name: str) -> Dict:
        """Get metrics for a plugin."""
        try:
            plugin = await self.get_plugin(name)
            if not plugin:
                return {}
            
            # Get metrics
            return await plugin.get_metrics()
            
        except Exception as e:
            logger.error(
                f"Error getting plugin metrics: {name}",
                exc_info=True
            )
            return {}

    def get_metrics(self) -> Dict:
        """Get plugin manager metrics."""
        return self._metrics

    async def cleanup(self):
        """Cleanup plugin resources."""
        try:
            # Cleanup plugin instances
            for name, instance in self.loaded_plugins.items():
                try:
                    await instance.cleanup()
                except Exception as e:
                    logger.error(
                        f"Error cleaning up plugin: {name}",
                        exc_info=True
                    )
            
            # Clear instances
            self.loaded_plugins.clear()
            
            # Stop resource monitoring
            if self._resource_monitor:
                await self._resource_monitor.stop_monitoring()
            
            # Update metrics
            self._metrics["active_plugins"] = 0
            
            logger.info("Plugin manager cleanup completed")
            
        except Exception as e:
            logger.error("Error during cleanup", exc_info=True)
            raise

    async def run_plugins(
        self, scan_input: ScanInput, scan_id: str, config: Optional[PluginConfig] = None
    ) -> List[Finding]:
        """Executes all loaded plugins in parallel."""
        plugin_tasks = []
        plugin_name_map = {}
        for plugin_name, plugin_instance in self.loaded_plugins.items():
            # Send module started status
            # This was moved to ScannerEngine's _run_scan_task to synchronize with WebSocket connection
            # if self._update_callback:
            #     await self._update_callback({
            #         "scan_id": scan_id,
            #         "type": "module_status",
            #         "data": ModuleStatus(module_name=plugin_name, status="started", progress=0).model_dump()
            #     })
            task = asyncio.create_task(plugin_instance._perform_nuclei_scan(scan_input=scan_input, config=config))
            plugin_tasks.append(task)
            plugin_name_map[task] = plugin_name
        
        all_plugin_findings: List[Finding] = []
        for task in asyncio.as_completed(plugin_tasks):
            plugin_name_of_task = plugin_name_map.get(task, "Unknown Plugin") # Get plugin name from map

            try:
                findings_from_plugin = await task
                if findings_from_plugin:
                    all_plugin_findings.extend(findings_from_plugin)
                # Send module completed status
                # if self._update_callback:
                #     await self._update_callback({
                #         "scan_id": scan_id,
                #         "type": "module_status",
                #         "data": ModuleStatus(module_name=plugin_name_of_task, status="completed", progress=100).model_dump()
                #     })
            except Exception as e:
                print(f"Error in plugin task {plugin_name_of_task}: {e}") # Log errors from individual plugins
                # Send module failed status
                # if self._update_callback:
                #     await self._update_callback({
                #         "scan_id": scan_id,
                #         "type": "module_status",
                #         "data": ModuleStatus(module_name=plugin_name_of_task, status="failed", progress=100).model_dump()
                #     })

        return all_plugin_findings

    async def run_plugin(
        self, plugin_name: str, scan_input: ScanInput, config: Optional[PluginConfig] = None
    ) -> List[Finding]:
        """Executes a loaded plugin with the given scan input and configuration."""
        plugin = self.loaded_plugins.get(plugin_name)
        if not plugin:
            print(f"Error: Plugin '{plugin_name}' not found.")  # Basic logging
            return []

        try:
            if hasattr(plugin, "_perform_nuclei_scan") and callable(plugin._perform_nuclei_scan):
                print(f"Executing plugin: {plugin_name} for target {scan_input.target}")  # Basic logging
                raw_results = await plugin._perform_nuclei_scan(scan_input=scan_input, config=config)
                
                # Expect plugins to return List[Finding] directly
                if isinstance(raw_results, list) and all(isinstance(f, Finding) for f in raw_results):
                    return raw_results
                else:
                    print(f"Warning: Plugin '{plugin_name}' returned unexpected type or non-Finding objects: {type(raw_results)}")
                    return []
            else:
                print(
                    f"Warning: Plugin '{plugin_name}' does not have an async '_perform_nuclei_scan' method or its '_perform_nuclei_scan' method is not callable."
                )
                return []
        except Exception as e:
            print(f"Error executing plugin '{plugin_name}': {e}")  # Basic logging
            return []

    @validate_call
    def register_plugin_config(self, plugin_name: str, config: PluginConfig) -> None:
        """Registers configuration for a specific plugin."""
        if plugin_name in self.loaded_plugins:
            print(f"Configuration registered for plugin: {plugin_name}")
        else:
            print(f"Error: Plugin '{plugin_name}' not found. Cannot register configuration.")

    @validate_call
    async def execute_external_tool(self, command: List[str], cwd: Optional[str] = None) -> str:
        """Executes an external command and captures its output."""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                print(f"Error executing external tool: {stderr.decode()}")
                return ""
            return stdout.decode()
        except Exception as e:
            print(f"Error running external command {command}: {e}")
            return ""
