"""
Unit tests for Database Models and Audit Logger.
"""

from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.audit import AuditLogger
from app.core.enums import AuditAction, FindingStatus, OWASPCategory, ScopeValidationStatus, Severity
from app.database.models import Base, Finding, Program, ScopeRule
from app.database.session import init_db
from app.findings.manager import FindingManager


def test_database_models_and_relationships(tmp_path):
    db_file = tmp_path / "test.db"
    test_engine = create_engine(f"sqlite:///{db_file}")
    init_db(test_engine)

    Session = sessionmaker(bind=test_engine)
    with Session() as session:
        prog = Program(
            id="prog_unit_1",
            name="Unit Test Program",
            platform="Local",
        )
        session.add(prog)

        rule = ScopeRule(
            program_id="prog_unit_1",
            rule_type="DOMAIN",
            effect="INCLUDE",
            pattern="unit.test.local",
        )
        session.add(rule)
        session.commit()

        queried = session.query(Program).filter(Program.id == "prog_unit_1").first()
        assert queried is not None
        assert len(queried.scope_rules) == 1
        assert queried.scope_rules[0].pattern == "unit.test.local"


def test_audit_logger_redaction_and_persistence(tmp_path):
    log_file = tmp_path / "test_audit.jsonl"
    logger = AuditLogger(log_file=str(log_file))

    secret_target = "https://user:SuperPassword123@api.example.com"
    secret_details = {"bearer_token": "Bearer sensitive_secret_key_12345"}

    entry = logger.log(
        target=secret_target,
        action=AuditAction.SCOPE_CHECK,
        scope_result=ScopeValidationStatus.ALLOWED,
        program_id="prog_unit_1",
        details=secret_details,
    )

    assert "SuperPassword123" not in entry.target
    assert log_file.exists()
    content = log_file.read_text()
    assert "SuperPassword123" not in content
    assert "sensitive_secret_key_12345" not in content
    assert "[REDACTED_BY_BUGBOUNTY_AI]" in content
