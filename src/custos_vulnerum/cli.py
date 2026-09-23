"""``custos`` — the local vulnerability lifecycle CLI.

launch → verify → controlled PoC → evidence → detect → ATT&CK → mitigate → retest →
report. Every command is backed by ``custos_vulnerum`` modules; see
``specs/001-vulnerum-core/contracts/cli.md`` for the command contract.
"""

from __future__ import annotations

from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import (
    attack as attack_mod,
)
from . import (
    checks as checks_mod,
)
from . import (
    detection as detection_mod,
)
from . import (
    evidence as evidence_mod,
)
from . import (
    lifecycle as lifecycle_mod,
)
from . import (
    pocs as pocs_mod,
)
from . import (
    report as report_mod,
)
from . import (
    safety as safety_mod,
)
from .catalog import LoadedLab, discover_labs, get_lab
from .config import Paths
from .errors import CustosError
from .models import DetectionMatch

app = typer.Typer(
    help=(
        "Vulnerum — local vulnerability lifecycle: "
        "launch, verify, run a controlled PoC, collect evidence, detect with Sigma, "
        "map MITRE ATT&CK, mitigate and retest. Labs bind to 127.0.0.1 only."
    ),
    no_args_is_help=True,
)
lab_app = typer.Typer(help="Launch and tear down lab environments.", no_args_is_help=True)
app.add_typer(lab_app, name="lab")

console = Console(emoji=False)
err_console = Console(stderr=True, emoji=False)


def _cell(value: object) -> Text:
    """Render data verbatim (no Rich markup/emoji reinterpretation of user data)."""
    return Text(str(value))


def _paths() -> Paths:
    return Paths.resolve()


def _fail(message: str, code: int = 1) -> None:
    err_console.print(f"[red]error[/red] {message}")
    raise typer.Exit(code=code)


def _status(lab: LoadedLab) -> str:
    try:
        states = {name: env.is_running() for name, env in lifecycle_mod.environments(lab).items()}
    except CustosError:
        return "unknown (Docker unavailable?)"
    running = [name for name, up in states.items() if up]
    return "running (" + "/".join(running) + ")" if running else "down"


@app.command("list")
def list_labs() -> None:
    """List available labs with their current status."""
    try:
        paths = _paths()
        labs = discover_labs(paths)
    except CustosError as exc:
        _fail(str(exc))
        return
    table = Table(title="Vulnerum labs", show_header=True)
    for column in ("ID", "CVE", "Severity", "Component", "Port", "Status"):
        table.add_column(column)
    for lab in labs:
        table.add_row(
            _cell(lab.id),
            _cell(lab.meta.cve),
            _cell(lab.meta.severity),
            _cell(f"{lab.meta.component} ({lab.meta.affected_versions})"),
            _cell(f"127.0.0.1:{lab.meta.compose.port}"),
            _cell(_status(lab)),
        )
    console.print(table)


@lab_app.command("up")
def lab_up(
    lab_id: str,
    mitigated: bool = typer.Option(
        False, "--mitigated", help="Launch the mitigated (patched) variant instead."
    ),
) -> None:
    """Launch a lab in Docker and wait until it answers on loopback.

    One variant runs at a time (both publish the same loopback port): launching one
    tears the other down first.
    """
    try:
        lab = get_lab(_paths(), lab_id)
        env = lifecycle_mod.LabEnvironment(lab, "mitigated" if mitigated else "vulnerable")
        other = lifecycle_mod.LabEnvironment(lab, "vulnerable" if mitigated else "mitigated")
        if other.is_running():
            other.down()
            console.print(f"[yellow]replace[/yellow] stopped {lab.id} ({other.variant})")
        env.up()
        env.wait_ready()
    except CustosError as exc:
        _fail(str(exc))
        return
    console.print(
        f"[green]up[/green] {lab.id} ({env.variant}) at {env.base_url} [project {env.project}]"
    )


@lab_app.command("down")
def lab_down(lab_id: str) -> None:
    """Tear down all Docker resources of a lab (both variants)."""
    try:
        lab = get_lab(_paths(), lab_id)
    except CustosError as exc:
        _fail(str(exc))
        return
    failed = False
    for env in lifecycle_mod.environments(lab).values():
        try:
            env.down()
            console.print(f"[green]down[/green] {lab.id} ({env.variant})")
        except CustosError as exc:
            failed = True
            err_console.print(f"[red]error[/red] {lab.id} ({env.variant}): {exc}")
    if failed:
        raise typer.Exit(code=1)


@app.command("verify")
def verify(
    lab_id: str,
    mitigated: bool = typer.Option(False, "--mitigated", help="Verify the mitigated variant."),
) -> None:
    """Verify the lab is up, has the expected version markers and is loopback-only."""
    try:
        paths = _paths()
        lab = get_lab(paths, lab_id)
        env = lifecycle_mod.LabEnvironment(lab, "mitigated" if mitigated else "vulnerable")
        record = checks_mod.run_verification(lab, env)
        evidence_mod.write_verification(paths, record)
    except CustosError as exc:
        _fail(str(exc))
        return
    table = Table(title=f"verify {lab.id} ({env.variant})")
    for column in ("Check", "Expected", "Observed", "Pass"):
        table.add_column(column)
    for check in record.checks:
        style = "green" if check.passed else "red"
        table.add_row(
            _cell(check.description),
            _cell(check.expected),
            _cell(check.observed),
            Text("yes" if check.passed else "NO", style=style),
        )
    console.print(table)
    if not record.passed:
        _fail("verification failed")


@app.command("run")
def run_poc(
    lab_id: str,
    retest: bool = typer.Option(
        False,
        "--retest",
        help=(
            "Retest after mitigation: same fixed PoC, expected to fail "
            "(exit 1 if still exploitable)."
        ),
    ),
) -> None:
    """Run the lab's fixed PoC and write normalized evidence under artifacts/."""
    try:
        paths = _paths()
        lab = get_lab(paths, lab_id)
        envs = lifecycle_mod.environments(lab)
        phase = "retest" if retest else "poc"
        if retest:
            env = envs["mitigated"] if envs["mitigated"].is_running() else envs["vulnerable"]
            if env.variant == "vulnerable":
                err_console.print(
                    "[yellow]note[/yellow] mitigated variant is not running — "
                    "retesting against the vulnerable lab"
                )
        else:
            env = envs["vulnerable"]
        target = safety_mod.resolve_target(env)
        run = pocs_mod.run_plan(lab, env, target, phase)
        run_dir = evidence_mod.write_evidence(paths, run)
    except CustosError as exc:
        _fail(str(exc))
        return

    table = Table(title=f"{phase} {lab.id} ({run.environment}) → {run.result}")
    for column in ("Step", "Role", "Expected", "Result", "Indicators"):
        table.add_column(column)
    for step in run.steps:
        observed = (
            f"HTTP {step.response.status}"
            if step.response
            else ("canary hit" if (step.canary and step.canary.matched) else "canary silent")
        )
        style = "green" if step.indicators_met else "white"
        table.add_row(
            _cell(step.name),
            _cell(step.role),
            _cell(step.expected),
            _cell(observed),
            Text("MET" if step.indicators_met else "not met", style=style),
        )
    console.print(table)
    console.print(f"evidence: {run_dir / evidence_mod.EVIDENCE_FILE}")

    if phase == "poc" and run.result != "vulnerable":
        _fail("PoC did not demonstrate exploitability (see evidence)")
    if phase == "retest" and run.result != "not_vulnerable":
        _fail("mitigation NOT effective — the lab is still exploitable (see evidence)")


@app.command("detect")
def detect(
    lab_id: str,
    retest: bool = typer.Option(False, "--retest", help="Detect over the retest run."),
) -> None:
    """Match evidence against Sigma rules and map MITRE ATT&CK techniques."""
    try:
        paths = _paths()
        lab = get_lab(paths, lab_id)
        phase = "retest" if retest else "poc"
        run_path = evidence_mod.find_run(paths, lab_id, phase)
        if run_path is None:
            raise CustosError(
                f"no {phase} evidence for {lab_id} — run `custos run {lab_id}"
                f"{' --retest' if retest else ''}` first"
            )
        run = evidence_mod.read_evidence(run_path)
        events = evidence_mod.derive_events(run, lab.meta.logsource)
        rules = [
            detection_mod.load_rule_file(paths.detection / rel) for rel in lab.meta.detection_rules
        ]
        results = detection_mod.match_events(rules, events)
        techniques_db = attack_mod.load_techniques()
        matches = [
            DetectionMatch(
                rule_id=result.rule.rule_id,
                rule_title=result.rule.title,
                rule_level=result.rule.level,
                attack_tags=[t for t in result.rule.tags if t.startswith("attack.")],
                technique_ids=attack_mod.technique_ids_from_tags(result.rule.tags),
                matched_event=dict(result.event),
                matched_identifiers=list(result.matched_identifiers),
            )
            for result in results
        ]
        lab_ids = [ref.technique_id for ref in lab.meta.attack]
        all_ids = sorted({tid for m in matches for tid in m.technique_ids} | set(lab_ids))
        run.detections = matches
        run.attack = attack_mod.resolve(all_ids, techniques_db)
        run_dir = evidence_mod.write_evidence(paths, run)
        evidence_mod.write_detections(run_dir, matches)
    except CustosError as exc:
        _fail(str(exc))
        return

    table = Table(title=f"detect {lab.id} ({phase}) — {len(matches)} match(es)")
    for column in ("Rule", "Level", "Matched identifiers", "ATT&CK"):
        table.add_column(column)
    for match in matches:
        table.add_row(
            match.rule_title,
            match.rule_level,
            ", ".join(match.matched_identifiers),
            ", ".join(match.technique_ids) or "-",
        )
    console.print(table)
    console.print(
        "ATT&CK: "
        + (", ".join(f"{t.technique_id} ({t.tactic_name})" for t in run.attack) or "none")
    )
    console.print(f"detections: {run_dir / evidence_mod.DETECTIONS_FILE}")
    if phase == "poc" and not matches:
        _fail("no Sigma rule matched the exploit evidence — detection gap")


@app.command("report")
def report(lab_id: str) -> None:
    """Render the lifecycle report (Markdown + HTML) from collected evidence."""
    try:
        paths = _paths()
        lab = get_lab(paths, lab_id)
        poc_run = _maybe_run(paths, lab_id, "poc")
        retest_run = _maybe_run(paths, lab_id, "retest")
        if poc_run is None and retest_run is None:
            raise CustosError(f"no evidence for {lab_id} — run `custos run {lab_id}` first")
        verify_vulnerable = evidence_mod.read_verification(paths, lab_id, "vulnerable")
        verify_mitigated = evidence_mod.read_verification(paths, lab_id, "mitigated")
        techniques_db = attack_mod.load_techniques()
        ids = sorted(
            {ref.technique_id for ref in lab.meta.attack}
            | {
                tid
                for run in (poc_run, retest_run)
                if run
                for tid in (t.technique_id for t in run.attack)
            }
        )
        techniques = attack_mod.resolve(ids, techniques_db)
        context = report_mod.build_context(
            lab, poc_run, retest_run, verify_vulnerable, verify_mitigated, techniques
        )
        markdown, html = report_mod.render_reports(context)
        latest = evidence_mod.find_run(paths, lab_id, "retest") or evidence_mod.find_run(
            paths, lab_id, "poc"
        )
        if latest is None:
            raise CustosError(f"no evidence for {lab_id} — run `custos run {lab_id}` first")
        md_path, html_path = report_mod.write_reports(latest, markdown, html)
    except CustosError as exc:
        _fail(str(exc))
        return
    console.print(f"report: {md_path}")
    console.print(f"report: {html_path}")


def _maybe_run(paths: Paths, lab_id: str, phase: str) -> Any:
    run_path = evidence_mod.find_run(paths, lab_id, phase)
    return evidence_mod.read_evidence(run_path) if run_path else None


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
