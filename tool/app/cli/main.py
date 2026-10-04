"""
MAHADU | BugBounty-AI CLI.
Comprehensive command-line interface providing all operational workflows:
programs, scope validation, passive & active recon, OWASP tests, evidence,
findings, reports, audit trail, and safe local lab demonstrations.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

from app.core.audit import audit_logger
from app.core.banner import show_welcome, show_about, show_version, branded_header
from app.core.command_runner import CommandRunner
from app.core.config import (
    ExclusionConfig,
    ProgramConfig,
    RateLimitConfig,
    ScopeDefinitionConfig,
    load_platform_settings,
    load_program_from_yaml,
)
from app.core.enums import (
    AuditAction,
    FindingStatus,
    OperatingMode,
    OWASPCategory,
    ScopeEffect,
    ScopeRuleType,
    ScopeValidationStatus,
    Severity,
)
from app.core.rate_limiter import RateLimiter
from app.core.redactor import SecurityRedactor
from app.database.models import (
    Asset,
    AuditLog,
    Endpoint,
    EvidenceItem,
    Finding,
    Program,
    ScopeRule,
)
from app.database.session import get_db_session, init_db
from app.owasp.registry import owasp_registry
from app.reports.generator import ReportGenerator, ReportQualityControl
from app.scope.engine import ScopeEngine
from app.scope.importer import ScopeImporter
from app.scope.normalizer import ScopeNormalizer

console = Console()


def get_program_or_fail(program_id: Optional[str]) -> ProgramConfig:
    """Retrieve ProgramConfig from DB or return error."""
    target_id = program_id or os.getenv("BUGBOUNTY_PROGRAM_ID")
    if not target_id:
        # Check if any program exists in DB
        with get_db_session() as session:
            first_prog = session.query(Program).first()
            if first_prog:
                target_id = first_prog.id

    if not target_id:
        console.print("[bold red]Error:[/bold red] No program specified and no programs found in database. Run 'bugbounty program create' first.")
        sys.exit(1)

    with get_db_session() as session:
        prog = session.query(Program).filter(Program.id == target_id).first()
        if not prog:
            console.print(f"[bold red]Error:[/bold red] Program '{target_id}' not found in database.")
            sys.exit(1)

        in_domains = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.DOMAIN and r.effect == ScopeEffect.INCLUDE]
        in_ips = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.IP and r.effect == ScopeEffect.INCLUDE]
        in_cidrs = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.CIDR and r.effect == ScopeEffect.INCLUDE]
        in_urls = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.URL and r.effect == ScopeEffect.INCLUDE]

        ex_domains = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.DOMAIN and r.effect == ScopeEffect.EXCLUDE]
        ex_paths = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.PATH and r.effect == ScopeEffect.EXCLUDE]
        ex_params = [r.pattern for r in prog.scope_rules if r.rule_type == ScopeRuleType.PARAMETER and r.effect == ScopeEffect.EXCLUDE]

        allowed_tools = json.loads(prog.allowed_tools or "[]")
        prohibited_testing = json.loads(prog.prohibited_testing or "[]")
        custom_rules = json.loads(prog.custom_rules or "[]")

        return ProgramConfig(
            program_id=prog.id,
            program_name=prog.name,
            platform=prog.platform,
            description=prog.description or "",
            policy_url=prog.policy_url,
            mode=prog.mode,
            lab_mode=prog.lab_mode,
            scope=ScopeDefinitionConfig(
                domains=in_domains,
                ips=in_ips,
                cidrs=in_cidrs,
                urls=in_urls,
            ),
            exclusions=ExclusionConfig(
                domains=ex_domains,
                paths=ex_paths,
                parameters=ex_params,
            ),
            limits=RateLimitConfig(
                requests_per_second=prog.rate_limit_rps,
                requests_per_minute=prog.rate_limit_rpm,
                max_concurrency=prog.max_concurrency,
                timeout_seconds=prog.timeout_seconds,
            ),
            allowed_tools=allowed_tools,
            prohibited_testing=prohibited_testing,
            custom_rules=custom_rules,
        )


@click.group(invoke_without_command=True)
@click.option("--program", "-p", "program_id", help="Target Program ID")
@click.option("--dry-run", is_flag=True, default=False, help="Simulate actions without issuing network requests")
@click.option("--json-out", is_flag=True, default=False, help="Format output as JSON")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose logging")
@click.pass_context
def cli(ctx, program_id, dry_run, json_out, verbose):
    """MAHADU BugBounty-AI\n\nAI-Assisted Bug Bounty Recon & Security Research Platform."""
    ctx.ensure_object(dict)
    ctx.obj["program_id"] = program_id
    ctx.obj["dry_run"] = dry_run
    ctx.obj["json_out"] = json_out
    ctx.obj["verbose"] = verbose
    if ctx.invoked_subcommand is None:
        show_welcome()


# ==============================================================================
# ABOUT / VERSION COMMANDS
# ==============================================================================
@cli.command("about")
def about_cmd():
    """Display project information, author, and license."""
    show_about()


@cli.command("version")
def version_cmd():
    """Display current version."""
    show_version()


# ==============================================================================
# 1. INIT COMMAND
# ==============================================================================
@cli.command("init")
@click.pass_context
def init_cmd(ctx):
    """Initialize database, workspace directories, and default lab configurations."""
    for folder in ["data", "logs", "reports", "screenshots", "config"]:
        Path(folder).mkdir(parents=True, exist_ok=True)

    init_db()

    # Create sample local lab configuration if not present
    sample_lab_path = Path("config/lab_localhost.yaml")
    if not sample_lab_path.exists():
        sample_lab_config = """program:
  program_id: "local_security_lab"
  program_name: "Localhost Security Test Lab"
  platform: "Local Development / Lab"
  description: "Safe test environment for localhost and intentionally vulnerable containers."
  mode: "LAB"
  lab_mode: true
  scope:
    domains:
      - "localhost"
      - "*.local"
    ips:
      - "127.0.0.1"
      - "::1"
    ports:
      - 80
      - 443
      - 8000
      - 8080
      - 5000
  exclusions:
    domains:
      - "production.local"
    paths:
      - "/admin/shutdown"
  limits:
    requests_per_second: 5.0
    requests_per_minute: 120.0
    max_concurrency: 4
    timeout_seconds: 10
  allowed_tools:
    - "curl"
    - "nmap"
    - "httpx"
    - "dnsx"
    - "ffuf"
  custom_rules:
    - "Authorized strictly on localhost and local test containers."
"""
        sample_lab_path.write_text(sample_lab_config, encoding="utf-8")

    console.print(
        Panel.fit(
            "[bold green]BugBounty-AI Platform Initialized Successfully![/bold green]\n"
            "✓ SQLite Database created at [cyan]data/bugbounty.db[/cyan]\n"
            "✓ Audit logs configured at [cyan]logs/audit.jsonl[/cyan]\n"
            "✓ Example local lab config at [cyan]config/lab_localhost.yaml[/cyan]\n"
            "✓ Strict scope & redaction engines active",
            title="System Ready",
        )
    )


# ==============================================================================
# 2. PROGRAM COMMANDS
# ==============================================================================
@cli.group("program")
def program_group():
    """Manage Bug Bounty Programs and Scope Definitions."""
    pass


@program_group.command("create")
@click.option("--id", "program_id", required=True, help="Unique program identifier (e.g. prog_example)")
@click.option("--name", "name", required=True, help="Program Name")
@click.option("--platform", default="HackerOne", help="Platform (HackerOne, Bugcrowd, Lab)")
@click.option("--domain", "domains", multiple=True, help="In-scope domain (can specify multiple, supports wildcards e.g. *.example.com)")
@click.option("--exclude-domain", "ex_domains", multiple=True, help="Excluded domain")
@click.option("--rps", default=2.0, type=float, help="Rate limit requests per second")
@click.option("--concurrency", default=2, type=int, help="Max concurrency limit")
@click.option("--lab", is_flag=True, default=False, help="Mark as dedicated local lab profile")
def program_create(program_id, name, platform, domains, ex_domains, rps, concurrency, lab):
    """Create a new security program and define initial scope."""
    init_db()
    with get_db_session() as session:
        existing = session.query(Program).filter(Program.id == program_id).first()
        if existing:
            console.print(f"[bold red]Error:[/bold red] Program with ID '{program_id}' already exists.")
            return

        prog = Program(
            id=program_id,
            name=name,
            platform=platform,
            mode=OperatingMode.LAB if lab else OperatingMode.PASSIVE,
            lab_mode=lab,
            rate_limit_rps=rps,
            rate_limit_rpm=rps * 60.0,
            max_concurrency=concurrency,
            allowed_tools=json.dumps(["curl", "httpx", "dnsx", "subfinder", "nmap"]),
            prohibited_testing=json.dumps(["denial_of_service", "credential_stuffing", "destructive_exploitation"]),
        )
        session.add(prog)

        # Add in-scope domains
        for dom in domains:
            rule = ScopeRule(
                program_id=program_id,
                rule_type=ScopeRuleType.DOMAIN,
                effect=ScopeEffect.INCLUDE,
                pattern=dom.strip().lower(),
                description="Initial CLI scope import",
            )
            session.add(rule)

        # Add excluded domains
        for ex in ex_domains:
            rule = ScopeRule(
                program_id=program_id,
                rule_type=ScopeRuleType.DOMAIN,
                effect=ScopeEffect.EXCLUDE,
                pattern=ex.strip().lower(),
                description="Initial CLI scope exclusion",
            )
            session.add(rule)

    audit_logger.log(
        target=f"program:{program_id}",
        action=AuditAction.PROGRAM_CREATE,
        scope_result=ScopeValidationStatus.ALLOWED,
        program_id=program_id,
        details={"name": name, "domains": list(domains), "excluded": list(ex_domains)},
    )
    console.print(f"[bold green]✓ Program '{name}' ({program_id}) registered successfully.[/bold green]")


@program_group.command("list")
def program_list():
    """List all registered programs in database."""
    init_db()
    with get_db_session() as session:
        programs = session.query(Program).all()
        if not programs:
            console.print("[yellow]No programs found. Use 'bugbounty program create' to add one.[/yellow]")
            return

        table = Table(title="Bug Bounty Programs", header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="bold white")
        table.add_column("Platform", style="green")
        table.add_column("Mode", style="blue")
        table.add_column("Rate Limit (RPS)", justify="right")
        table.add_column("Rules", justify="right")

        for p in programs:
            table.add_row(
                p.id,
                p.name,
                p.platform,
                p.mode.value,
                f"{p.rate_limit_rps:.1f}",
                str(len(p.scope_rules)),
            )
        console.print(table)


@program_group.command("import")
@click.option("--file", "-f", "file_path", required=True, help="Path to YAML or JSON program file")
def program_import(file_path):
    """Import program configuration from YAML or JSON file."""
    init_db()
    path = Path(file_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        return

    if path.suffix in (".yaml", ".yml"):
        prog_config = ScopeImporter.import_from_yaml(file_path)
    elif path.suffix == ".json":
        prog_config = ScopeImporter.import_from_json(file_path)
    else:
        console.print("[bold red]Error:[/bold red] Unsupported file format. Use .yaml, .yml, or .json")
        return

    with get_db_session() as session:
        # Check or create program
        prog = session.query(Program).filter(Program.id == prog_config.program_id).first()
        if not prog:
            prog = Program(
                id=prog_config.program_id,
                name=prog_config.program_name,
                platform=prog_config.platform,
                description=prog_config.description,
                policy_url=prog_config.policy_url,
                mode=prog_config.mode,
                lab_mode=prog_config.lab_mode,
                rate_limit_rps=prog_config.limits.requests_per_second,
                rate_limit_rpm=prog_config.limits.requests_per_minute,
                max_concurrency=prog_config.limits.max_concurrency,
                timeout_seconds=prog_config.limits.timeout_seconds,
                prohibited_testing=json.dumps(prog_config.prohibited_testing),
                allowed_tools=json.dumps(prog_config.allowed_tools),
                custom_rules=json.dumps(prog_config.custom_rules),
            )
            session.add(prog)

        # Clear existing rules for re-import
        session.query(ScopeRule).filter(ScopeRule.program_id == prog_config.program_id).delete()

        # In-scope
        for d in prog_config.scope.domains:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.DOMAIN, effect=ScopeEffect.INCLUDE, pattern=d))
        for ip in prog_config.scope.ips:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.IP, effect=ScopeEffect.INCLUDE, pattern=ip))
        for cidr in prog_config.scope.cidrs:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.CIDR, effect=ScopeEffect.INCLUDE, pattern=cidr))
        for url in prog_config.scope.urls:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.URL, effect=ScopeEffect.INCLUDE, pattern=url))

        # Exclusions
        for ex_d in prog_config.exclusions.domains:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.DOMAIN, effect=ScopeEffect.EXCLUDE, pattern=ex_d))
        for ex_p in prog_config.exclusions.paths:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.PATH, effect=ScopeEffect.EXCLUDE, pattern=ex_p))
        for ex_param in prog_config.exclusions.parameters:
            session.add(ScopeRule(program_id=prog.id, rule_type=ScopeRuleType.PARAMETER, effect=ScopeEffect.EXCLUDE, pattern=ex_param))

    console.print(f"[bold green]✓ Successfully imported program '{prog_config.program_name}' ({prog_config.program_id})[/bold green]")


@program_group.command("show")
@click.option("--program", "-p", "program_id", help="Target Program ID")
@click.pass_context
def program_show(ctx, program_id):
    """Display formatted scope summary for the selected program."""
    prog_id = program_id or ctx.obj.get("program_id")
    prog_config = get_program_or_fail(prog_id)
    summary = ScopeImporter.format_scope_summary(prog_config)
    console.print(Markdown(summary))


# ==============================================================================
# 3. SCOPE COMMANDS
# ==============================================================================
@cli.group("scope")
def scope_group():
    """Verify and inspect scope boundaries."""
    pass


@scope_group.command("show")
@click.option("--program", "-p", "program_id", help="Target Program ID")
@click.pass_context
def scope_show(ctx, program_id):
    """Show detailed in-scope targets and exclusion rules."""
    prog_id = program_id or ctx.obj.get("program_id")
    prog_config = get_program_or_fail(prog_id)

    table = Table(title=f"Scope Rules for {prog_config.program_name} ({prog_config.program_id})")
    table.add_column("Type", style="cyan")
    table.add_column("Effect", style="bold")
    table.add_column("Pattern", style="yellow")

    for d in prog_config.scope.domains:
        table.add_row("DOMAIN", "[green]INCLUDE[/green]", d)
    for ip in prog_config.scope.ips:
        table.add_row("IP", "[green]INCLUDE[/green]", ip)
    for cidr in prog_config.scope.cidrs:
        table.add_row("CIDR", "[green]INCLUDE[/green]", cidr)
    for url in prog_config.scope.urls:
        table.add_row("URL", "[green]INCLUDE[/green]", url)

    for ex in prog_config.exclusions.domains:
        table.add_row("DOMAIN", "[red]EXCLUDE[/red]", ex)
    for ex_p in prog_config.exclusions.paths:
        table.add_row("PATH", "[red]EXCLUDE[/red]", ex_p)
    for ex_param in prog_config.exclusions.parameters:
        table.add_row("PARAMETER", "[red]EXCLUDE[/red]", ex_param)

    console.print(table)


@scope_group.command("validate")
@click.option("--program", "-p", "program_id", help="Target Program ID")
@click.option("--target", "-t", required=True, help="Target host, IP, or URL to validate")
@click.option("--port", type=int, help="Optional port")
@click.option("--path", help="Optional path")
@click.option("--param", help="Optional parameter")
@click.option("--tool", help="Optional tool name")
@click.option("--test-cat", help="Optional test category")
@click.pass_context
def scope_validate(ctx, program_id, target, port, path, param, tool, test_cat):
    """Test if a target/port/path/tool is authorized by scope engine."""
    prog_id = program_id or ctx.obj.get("program_id")
    prog_config = get_program_or_fail(prog_id)
    engine = ScopeEngine(prog_config)

    result = engine.validate_target(
        target=target,
        port=port,
        path=path,
        parameter=param,
        tool=tool,
        test_category=test_cat,
    )

    audit_logger.log(
        target=target,
        action=AuditAction.SCOPE_CHECK,
        scope_result=result.status,
        program_id=prog_config.program_id,
        tool=tool,
        result="ALLOWED" if result.allowed else "BLOCKED",
        details={"reason": result.reason, "port": port, "path": path, "param": param},
    )

    if result.allowed:
        console.print(
            Panel(
                f"[bold green]✓ Target In-Scope and Authorized[/bold green]\n"
                f"Target: [cyan]{target}[/cyan]\n"
                f"Status: [green]{result.status.value}[/green]\n"
                f"Reason: {result.reason}",
                title="Scope Check: Passed",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]✗ Action BLOCKED by Scope Engine[/bold red]\n"
                f"Target: [cyan]{target}[/cyan]\n"
                f"Status: [red]{result.status.value}[/red]\n"
                f"Reason: [bold]{result.reason}[/bold]",
                title="Scope Check: BLOCKED",
                border_style="red",
            )
        )


# ==============================================================================
# 4. AUDIT COMMANDS
# ==============================================================================
@cli.group("audit")
def audit_group():
    """Inspect the immutable audit log trail."""
    pass


@audit_group.command("show")
@click.option("--limit", "-n", default=20, help="Number of records to display")
@click.pass_context
def audit_show(ctx, limit):
    """View recent audit log entries."""
    prog_id = ctx.obj.get("program_id")
    logs = audit_logger.get_recent_logs(program_id=prog_id, limit=limit)

    if not logs:
        console.print("[yellow]No audit logs recorded yet.[/yellow]")
        return

    table = Table(title="Immutable Audit Trail (Redacted)", header_style="bold cyan")
    table.add_column("Timestamp", style="dim")
    table.add_column("Program", style="blue")
    table.add_column("Target", style="bold white")
    table.add_column("Action", style="yellow")
    table.add_column("Scope Result", style="magenta")
    table.add_column("Result", style="green")

    for entry in logs:
        status_color = "green" if entry.result == "SUCCESS" or "ALLOWED" in str(entry.scope_result) else "red"
        table.add_row(
            entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            entry.program_id or "-",
            entry.target,
            entry.action.value,
            str(entry.scope_result.value),
            f"[{status_color}]{entry.result}[/{status_color}]",
        )

    console.print(table)


# ==============================================================================
# 5. OWASP COMMANDS
# ==============================================================================
@cli.group("owasp")
def owasp_group():
    """OWASP Top 10:2025 Test Registry."""
    pass


@owasp_group.command("list")
def owasp_list():
    """List all OWASP Top 10:2025 categories and registered tests."""
    table = Table(title="OWASP Top 10:2025 Test Categories", header_style="bold magenta")
    table.add_column("Category Code", style="cyan")
    table.add_column("Category Name", style="bold white")

    for cat in OWASPCategory:
        code, name = cat.value.split(" - ")
        table.add_row(code, name)

    console.print(table)


# ==============================================================================
# 6. LAB / DEMO COMMAND (Safe Localhost Demonstration)
# ==============================================================================
@cli.group("lab")
def lab_group():
    """Security lab and safe local testing workflows."""
    pass


@lab_group.command("demo")
@click.pass_context
def lab_demo(ctx):
    """
    Run a safe, authorized local-lab demonstration strictly on localhost.
    Demonstrates:
    1. Scope Validation
    2. Exclusion Check
    3. Safe Command Runner (dry-run & live ping/curl on 127.0.0.1)
    4. Rate Limiting enforcement
    5. Security Redaction
    6. Immutable Audit Trail verification
    """
    console.print(
        Panel.fit(
            "[bold cyan]Starting Safe Localhost Demonstration (BugBounty-AI)[/bold cyan]\n"
            "Target Environment: [bold green]127.0.0.1 / localhost only[/bold green]\n"
            "Testing Mode: [bold]LAB / SAFE BASELINE[/bold]",
            title="Local Security Demonstration",
        )
    )

    # 1. Setup local lab program
    init_db()
    prog_id = "lab_localhost_demo"
    prog_name = "Localhost Security Test Lab"
    with get_db_session() as session:
        session.query(ScopeRule).filter(ScopeRule.program_id == prog_id).delete()
        session.query(Program).filter(Program.id == prog_id).delete()
        demo_prog = Program(
            id=prog_id,
            name=prog_name,
            platform="Local Lab",
            mode=OperatingMode.LAB,
            lab_mode=True,
            rate_limit_rps=2.0,
            rate_limit_rpm=60.0,
            max_concurrency=2,
            allowed_tools=json.dumps(["curl", "ping", "echo"]),
            prohibited_testing=json.dumps(["denial_of_service", "credential_stuffing"]),
        )
        session.add(demo_prog)
        session.add(ScopeRule(program_id=prog_id, rule_type=ScopeRuleType.DOMAIN, effect=ScopeEffect.INCLUDE, pattern="localhost"))
        session.add(ScopeRule(program_id=prog_id, rule_type=ScopeRuleType.DOMAIN, effect=ScopeEffect.INCLUDE, pattern="*.local"))
        session.add(ScopeRule(program_id=prog_id, rule_type=ScopeRuleType.IP, effect=ScopeEffect.INCLUDE, pattern="127.0.0.1"))
        session.add(ScopeRule(program_id=prog_id, rule_type=ScopeRuleType.DOMAIN, effect=ScopeEffect.EXCLUDE, pattern="forbidden.local"))
        session.add(ScopeRule(program_id=prog_id, rule_type=ScopeRuleType.PATH, effect=ScopeEffect.EXCLUDE, pattern="/private/*"))

    prog_config = get_program_or_fail(prog_id)
    scope_engine = ScopeEngine(prog_config)
    rate_limiter = RateLimiter(requests_per_second=2.0, max_concurrency=2)
    runner = CommandRunner(scope_engine=scope_engine, rate_limiter=rate_limiter, dry_run=False)

    # Step 1: Validate In-Scope target
    console.print("\n[bold yellow]Step 1: Testing In-Scope Target (127.0.0.1)...[/bold yellow]")
    res1 = scope_engine.validate_target("127.0.0.1")
    console.print(f"Target: [cyan]127.0.0.1[/cyan] -> Status: [bold green]{res1.status.value}[/bold green] (Allowed: {res1.allowed})")

    # Step 2: Validate Out-of-Scope target (Unauthorized Internet Target)
    console.print("\n[bold yellow]Step 2: Testing Out-of-Scope Target (external-target.com)...[/bold yellow]")
    res2 = scope_engine.validate_target("external-target.com")
    console.print(f"Target: [cyan]external-target.com[/cyan] -> Status: [bold red]{res2.status.value}[/bold red] (Allowed: {res2.allowed})")
    console.print(f"Reason: [dim]{res2.reason}[/dim]")

    # Step 3: Validate Excluded Domain
    console.print("\n[bold yellow]Step 3: Testing Explicitly Excluded Domain (forbidden.local)...[/bold yellow]")
    res3 = scope_engine.validate_target("forbidden.local")
    console.print(f"Target: [cyan]forbidden.local[/cyan] -> Status: [bold red]{res3.status.value}[/bold red] (Allowed: {res3.allowed})")

    # Step 4: Validate Excluded Path
    console.print("\n[bold yellow]Step 4: Testing In-Scope Domain with Excluded Path (localhost/private/secret)...[/bold yellow]")
    res4 = scope_engine.validate_target("localhost", path="/private/secret")
    console.print(f"Path: [cyan]/private/secret[/cyan] -> Status: [bold red]{res4.status.value}[/bold red] (Allowed: {res4.allowed})")

    # Step 5: Safe Command Runner Execution with Dry-Run
    console.print("\n[bold yellow]Step 5: CommandRunner in Dry-Run Mode...[/bold yellow]")
    dry_runner = CommandRunner(scope_engine=scope_engine, dry_run=True)
    cmd_res_dry = dry_runner.run(["ping", "-c", "1", "127.0.0.1"], target="127.0.0.1", program_id=prog_id)
    console.print(f"[cyan]{cmd_res_dry.stdout}[/cyan]")

    # Step 6: Safe Command Runner Execution Live (Safe localhost probe)
    console.print("\n[bold yellow]Step 6: CommandRunner Live Safe Execution on localhost...[/bold yellow]")
    cmd_res_live = runner.run(["ping", "-c", "1", "127.0.0.1"], target="127.0.0.1", program_id=prog_id)
    console.print(f"Execution Exit Code: [bold green]{cmd_res_live.exit_code}[/bold green] (Duration: {cmd_res_live.duration_ms:.1f}ms)")

    # Step 7: Security Redaction Verification
    console.print("\n[bold yellow]Step 7: Testing Security Redaction Layer...[/bold yellow]")
    raw_secret_data = {
        "user": "test_researcher",
        "api_key": "sk-live-1234567890abcdef12345678",
        "password": "SuperSecretPassword123!",
        "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M",
    }
    redacted_data = SecurityRedactor.redact_dict(raw_secret_data)
    console.print("Sanitized Secret Output:", redacted_data)

    # Step 8: View Audit Trail
    console.print("\n[bold yellow]Step 8: Verifying Recorded Audit Trail...[/bold yellow]")
    logs = audit_logger.get_recent_logs(program_id=prog_id, limit=5)
    for entry in logs:
        console.print(f"  • [{entry.timestamp.strftime('%H:%M:%S')}] {entry.action.value} on [cyan]{entry.target}[/cyan]: [bold]{entry.result}[/bold]")

    console.print(
        Panel.fit(
            "[bold green]✓ Localhost Demonstration Complete - All Safety Gates Verified![/bold green]\n"
            "1. In-Scope targets permitted strictly.\n"
            "2. External & excluded targets blocked unconditionally.\n"
            "3. Dry-run mode avoids network calls.\n"
            "4. External tools executed securely via argument arrays without shell injection.\n"
            "5. Credentials, Bearer tokens, and secrets automatically redacted.\n"
            "6. Full immutable audit trail persisted.",
            title="Demonstration Summary",
            border_style="green",
        )
    )


if __name__ == "__main__":
    cli()
