"""
Finding Lifecycle Manager.
Enforces the mandatory progression:
DISCOVERED -> TRIAGE -> SUSPECTED -> VALIDATING -> VERIFIED / FALSE_POSITIVE -> READY_FOR_REPORT -> REPORTED -> RESOLVED
Strict Rule: An unreviewed finding can never jump directly to REPORTED.
"""

from typing import List, Optional
from app.core.enums import FindingStatus
from app.core.exceptions import PolicyViolationError
from app.database.models import Finding
from app.database.session import get_db_session


class FindingManager:
    """Manages finding transitions and human review gates."""

    ALLOWED_TRANSITIONS = {
        FindingStatus.DISCOVERED: [FindingStatus.TRIAGE, FindingStatus.FALSE_POSITIVE],
        FindingStatus.TRIAGE: [FindingStatus.SUSPECTED, FindingStatus.FALSE_POSITIVE],
        FindingStatus.SUSPECTED: [FindingStatus.VALIDATING, FindingStatus.FALSE_POSITIVE],
        FindingStatus.VALIDATING: [FindingStatus.VERIFIED, FindingStatus.FALSE_POSITIVE],
        FindingStatus.VERIFIED: [FindingStatus.READY_FOR_REPORT, FindingStatus.FALSE_POSITIVE],
        FindingStatus.FALSE_POSITIVE: [FindingStatus.TRIAGE],  # Re-evaluate
        FindingStatus.READY_FOR_REPORT: [FindingStatus.REPORTED],
        FindingStatus.REPORTED: [FindingStatus.RESOLVED],
        FindingStatus.RESOLVED: [],
    }

    @classmethod
    def transition(
        cls,
        finding_id: str,
        new_status: FindingStatus,
        human_approved: bool = False,
    ) -> Finding:
        """Advance finding status according to strict transition rules."""
        with get_db_session() as session:
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                raise ValueError(f"Finding '{finding_id}' not found.")

            current_status = finding.status

            # Enforce transition graph
            allowed_next = cls.ALLOWED_TRANSITIONS.get(current_status, [])
            if new_status not in allowed_next:
                raise PolicyViolationError(
                    rule="Finding Lifecycle",
                    details=f"Illegal transition from '{current_status.value}' to '{new_status.value}'.",
                )

            # Safety check: REPORTED requires human review
            if new_status == FindingStatus.REPORTED and not finding.human_reviewed and not human_approved:
                raise PolicyViolationError(
                    rule="Human Review Gate",
                    details="Cannot transition finding to REPORTED without explicit human review.",
                )

            finding.status = new_status
            if human_approved:
                finding.human_reviewed = True

            session.commit()
            session.refresh(finding)
            return finding
