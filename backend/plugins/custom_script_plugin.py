import importlib.util
import sys
from typing import List, Dict, Any, Optional
from inspect import iscoroutinefunction # Import needed for async check

from backend.plugins.base_plugin import BasePlugin
from backend.config_types.models import Finding, ScanInput


class CustomScriptPlugin(BasePlugin):
    """Custom Script Plugin for running user-defined scanning scripts."""

    def __init__(self, script_path: Optional[str] = None):
        super().__init__()
        self.script_path = script_path

    async def _run_plugin(self, scan_input: ScanInput, config: Dict) -> List[Dict]:
        """Run the custom script plugin."""
        try:
            script_path = config.get('script_path') or self.script_path
            if not script_path:
                return [self._create_error_finding("No script path provided")]

            findings = await run_custom_script(script_path, scan_input, config)
            # Convert Finding objects to dictionaries
            return [self._finding_to_dict(finding) for finding in findings]
        except Exception as e:
            print(f"Custom Script Plugin failed: {e}")
            return [self._create_error_finding(f"Custom Script Plugin failed: {e}")]

    def _finding_to_dict(self, finding: Finding) -> Dict:
        """Convert a Finding object to a dictionary."""
        return {
            "type": finding.vulnerability_type,
            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            "title": finding.vulnerability_type,
            "description": finding.description,
            "location": str(finding.affected_url) if finding.affected_url else "",
            "cwe": "N/A",
            "remediation": finding.remediation,
            "confidence": 75,
            "cvss": 0.0,
            "evidence": str(finding.proof) if finding.proof else "",
            "category": "CUSTOM_SCRIPT"
        }

    def _create_error_finding(self, description: str) -> Dict:
        """Create an error finding."""
        return {
            "type": "error",
            "severity": "INFO",
            "title": "Custom Script Plugin Error",
            "description": description,
            "location": "Plugin",
            "cwe": "N/A",
            "remediation": "N/A",
            "confidence": 0,
            "cvss": 0,
            "evidence": "",
            "category": "CUSTOM_SCRIPT"
        }


class CustomScript:
    """
    Base class for custom scanning scripts.
    Users should inherit from this class and implement the _perform_scan method.
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

    async def _perform_scan(self, scan_input: ScanInput, config: Dict[str, Any]) -> List[Finding]:
        """
        Asynchronous method to perform the custom scan.

        Args:
            scan_input: The input for the scan.
            config: Additional options for the scan.

        Returns:
            A list of Finding objects discovered by the script.
        """
        raise NotImplementedError("Custom script must implement the '_perform_scan' method")


async def run_custom_script(script_path: str, scan_input: ScanInput, config: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """
    Loads and runs a custom scanning script.

    Args:
        script_path: The file path to the custom Python script.
        scan_input: The input for the scan.
        config: Optional configuration dictionary for the script.

    Returns:
        A list of Finding objects from the script's execution.

    Raises:
        FileNotFoundError: If the script file does not exist.
        AttributeError: If the script does not contain a CustomScript class.
        TypeError: If the CustomScript class cannot be instantiated or
                   does not have an async _perform_scan method.
        Exception: For errors during script execution.
    """
    try:
        spec = importlib.util.spec_from_file_location("custom_script_module", script_path)
        if spec is None or spec.loader is None:
            raise FileNotFoundError(f"Could not load script at {script_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules["custom_script_module"] = module
        spec.loader.exec_module(module)

        # Find the CustomScript class in the loaded module
        custom_script_class = None
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and issubclass(obj, CustomScript) and obj is not CustomScript:
                custom_script_class = obj
                break

        if custom_script_class is None:
            raise AttributeError(f"Custom script at {script_path} must contain a class inheriting from CustomScript")

        # Instantiate the custom script and run the scan
        script_instance = custom_script_class(config=config)
        if not hasattr(script_instance, '_perform_scan') or not callable(script_instance._perform_scan):
             raise TypeError(f"Custom script class {custom_script_class.__name__} must have a callable '_perform_scan' method.")

        # Check if the _perform_scan method is asynchronous
        if not iscoroutinefunction(script_instance._perform_scan):
             raise TypeError(f"Custom script class {custom_script_class.__name__}'s '_perform_scan' method must be asynchronous (defined with async def).")


        findings = await script_instance._perform_scan(scan_input, config)

        # Basic validation of findings structure
        if not isinstance(findings, list) or not all(isinstance(f, Finding) for f in findings):
             # Depending on strictness, you might raise an error or log a warning
             print(f"Warning: Custom script {script_path} did not return a list of Finding objects.")
             # Optionally attempt to convert if structure is close, or filter invalid
             # For now, we'll just pass what it returned or an empty list
             if not isinstance(findings, list):
                 findings = []
             else:
                 findings = [f for f in findings if isinstance(f, Finding)]


        return findings

    except FileNotFoundError as e:
        print(f"Error running custom script: {e}")
        raise
    except AttributeError as e:
        print(f"Error running custom script: {e}")
        raise
    except TypeError as e:
        print(f"Error running custom script: {e}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred while running custom script {script_path}: {e}")
        # Log the full traceback in a real application
        raise # Re-raise the exception after logging
    finally:
        # Clean up the imported module from sys.modules to avoid name conflicts
        sys.modules.pop("custom_script_module", None)
