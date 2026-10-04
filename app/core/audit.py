"""
Immutable Audit Logging Service.
Logs all events, scope decisions, command executions, and findings to both
an append-only structured JSONL file and the SQLite audit_logs table.
All entries are processed through SecurityRedactor to prevent secret leakage.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.enums import AuditAction, ScopeValidationStatus
from app.core.redactor import SecurityRedactor
from app.database.models import AuditLog
from app.database.session import get_db_session

logger = logging.getLogger("bugbounty.audit")


class AuditLogger:
    """Service to record immutable, redacted audit logs to DB and JSONL file."""

    def __init__(self, log_file: str = "logs/audit.jsonl"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        target: str,
        action: AuditAction,
        scope_result: ScopeValidationStatus,
        program_id: Optional[str] = None,
        approval: str = "AUTO",
        tool: Optional[str] = None,
        result: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Record an immutable audit entry.
        Redacts sensitive tokens/keys before persisting.
        """
        timestamp_dt = datetime.now(timezone.utc)
        timestamp_str = timestamp_dt.isoformat()

        # Sanitize sensitive fields
        sanitized_target = SecurityRedactor.redact_text(target)
        sanitized_details = SecurityRedactor.redact_dict(details or {})

        # 1. Format structured JSON record
        record = {
            "timestamp": timestamp_str,
            "program": program_id or "N/A",
            "target": sanitized_target,
            "action": action.value if isinstance(action, AuditAction) else str(action),
            "scope_result": scope_result.value if isinstance(scope_result, ScopeValidationStatus) else str(scope_result),
            "approval": approval,
            "tool": tool or "internal",
            "result": result,
            "details": sanitized_details,
        }

        # 2. Append to append-only JSONL file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit file: {e}")

        # 3. Store into DB
        db_entry = AuditLog(
            timestamp=timestamp_dt,
            program_id=program_id,
            target=sanitized_target,
            action=action if isinstance(action, AuditAction) else AuditAction(action),
            scope_result=scope_result if isinstance(scope_result, ScopeValidationStatus) else ScopeValidationStatus(scope_result),
            approval=approval,
            tool=tool,
            result=result,
            details=json.dumps(sanitized_details),
        )

        try:
            with get_db_session() as session:
                session.add(db_entry)
                session.flush()
                session.expunge(db_entry)
        except Exception as e:
            logger.error(f"Failed to write audit log to database: {e}")

        return db_entry

    def get_recent_logs(
        self,
        program_id: Optional[str] = None,
        limit: int = 50,
        action: Optional[AuditAction] = None,
    ) -> List[AuditLog]:
        """Query recent audit events from the database."""
        with get_db_session() as session:
            query = session.query(AuditLog)
            if program_id:
                query = query.filter(AuditLog.program_id == program_id)
            if action:
                query = query.filter(AuditLog.action == action)
            results = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
            session.expunge_all()
            return results


# Global audit logger instance
audit_logger = AuditLogger()
