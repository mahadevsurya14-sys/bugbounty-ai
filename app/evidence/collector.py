"""
Evidence Collector.
Collects and redacts HTTP transactions, baseline differentials, and screenshots.
"""

from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict, Optional

from app.core.redactor import SecurityRedactor
from app.database.models import EvidenceItem
from app.database.session import get_db_session


class EvidenceCollector:
    """Collects and redacts test artifacts, generating verifiable EvidenceItem records."""

    @classmethod
    def collect_http_diff(
        cls,
        target_url: str,
        baseline_req: Dict[str, Any],
        baseline_res: Dict[str, Any],
        test_req: Dict[str, Any],
        test_res: Dict[str, Any],
        finding_id: Optional[str] = None,
        test_run_id: Optional[str] = None,
        tool: str = "internal",
    ) -> EvidenceItem:
        """
        Record HTTP request/response baseline differential.
        Applies strict redaction to headers, bodies, and tokens.
        """
        evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"

        sanitized_payload = {
            "target": target_url,
            "tool": tool,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline": {
                "request": SecurityRedactor.redact_dict(baseline_req),
                "response": SecurityRedactor.redact_dict(baseline_res),
            },
            "test": {
                "request": SecurityRedactor.redact_dict(test_req),
                "response": SecurityRedactor.redact_dict(test_res),
            },
            "status_diff": {
                "baseline_status": baseline_res.get("status_code"),
                "test_status": test_res.get("status_code"),
                "changed": baseline_res.get("status_code") != test_res.get("status_code"),
            },
        }

        evidence_entry = EvidenceItem(
            id=evidence_id,
            finding_id=finding_id,
            test_run_id=test_run_id,
            evidence_type="HTTP_DIFF",
            data=json.dumps(sanitized_payload),
            notes="Automatic HTTP baseline differential capture.",
        )

        with get_db_session() as session:
            session.add(evidence_entry)

        return evidence_entry
