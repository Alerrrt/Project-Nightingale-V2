import re
from typing import List
import httpx
from . import ScanModule, Detection

class SQLiModule:
    id = "sqli"
    description = "Detects SQL injection errors in responses"

    # Common SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"PostgreSQL.*ERROR",
        r"ORA-[0-9][0-9][0-9][0-9]",
        r"Microsoft SQL Server",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
    ]

    async def analyze(self, response: httpx.Response) -> List[Detection]:
        detections = []
        content = response.text.lower()

        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                detections.append(
                    Detection(
                        module_id=self.id,
                        description="SQL Injection Error Detected",
                        details=f"Found SQL error pattern: {pattern}"
                    )
                )

        return detections 