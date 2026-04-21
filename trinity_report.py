"""
trinity_report.py
=================

POC: Generate a Trinity incident HTML report from real Sentinel MCP data.

This module is intended to be imported into mcp_server.py and registered
as an additional MCP tool. It calls the existing investigate_incident()
and run_investigation_checklist() under the hood, then maps the real
results onto the 7-agent Norse-pantheon personas (Odin, Athena, Mimir,
Heimdall, Frigg, Thor, Saga) and renders the report HTML.

  ╔═══════════════════════════════════════════════════════════════════╗
  ║ POC SCOPE — IMPORTANT                                             ║
  ║                                                                   ║
  ║ Real delegation to sub-agents is NOT implemented yet. This report ║
  ║ is a *retrospective narration* — each agent section describes     ║
  ║ what that persona WOULD have produced given the real tool output  ║
  ║ we actually have. The HTML structure matches the Trinity portal   ║
  ║ template 1:1 so downstream JS (toggleFlowNode, downloadReportPDF, ║
  ║ etc.) continues to work as-is.                                    ║
  ║                                                                   ║
  ║ Fields that are SYNTHESIZED for the POC (not real data yet):      ║
  ║   • Per-agent costs & token counts (heuristic from data volume)   ║
  ║   • Inter-agent communication messages (derived from flow)        ║
  ║   • Agent confidence scores (rule-based from real signals)        ║
  ║   • Timeline entries after "Sentinel fired alert" (offsets)       ║
  ║                                                                   ║
  ║ Fields that are REAL (from MCP tool output):                      ║
  ║   • Incident ID, title, severity, status, owner, created_time     ║
  ║   • Affected host, affected user, risk_level                      ║
  ║   • MITRE tactics/techniques                                      ║
  ║   • IOCs and their verdicts (VirusTotal / AbuseIPDB)              ║
  ║   • Thor's proposed containment actions (derived from IOCs)       ║
  ╚═══════════════════════════════════════════════════════════════════╝

INTEGRATION INTO mcp_server.py:
    from trinity_report import (
        generate_trinity_report,
        register_trinity_report_tool,
    )

    # Option A — explicit registration helper:
    register_trinity_report_tool(
        mcp,
        investigate_incident_fn=investigate_incident,
        run_checklist_fn=run_investigation_checklist,
    )

    # Option B — hand-roll the @mcp.tool wrapper yourself (see bottom).
"""

from __future__ import annotations

import html as _html
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


# ════════════════════════════════════════════════════════════════════════
# CONSTANTS — tweak if your SOC conventions differ
# ════════════════════════════════════════════════════════════════════════

_POC_SIMULATED = True  # costs, comms, flow are synthesized until delegation lands

# Severity → display label
_SEVERITY_TO_P_LABEL = {
    "critical":      ("P1 Critical", "red"),
    "high":          ("P1 Critical", "red"),
    "medium":        ("P2 High",     "orange"),
    "low":           ("P3 Medium",   "blue"),
    "informational": ("P4 Low",      "green"),
}

# Risk level → numeric score (0-100) for display
_RISK_LEVEL_TO_SCORE = {
    "Critical": 95,
    "High":     85,
    "Medium":   60,
    "Low":      30,
}

# SLA targets in minutes, keyed by P-label
_SLA_TARGETS_MIN = {
    "P1 Critical": {"detect": 15,  "contain": 30},
    "P2 High":     {"detect": 30,  "contain": 120},
    "P3 Medium":   {"detect": 60,  "contain": 480},
    "P4 Low":      {"detect": 240, "contain": 1440},
}

# Agent persona metadata
_AGENT_ROLES = {
    "odin":     ("Sentinel Triage",  "Triage"),
    "athena":   ("Incident Analyst", "Analysis"),
    "mimir":    ("Script Analyst",   "Investigation"),
    "heimdall": ("IOC Enrichment",   "Investigation"),
    "frigg":    ("Forensics",        "Investigation"),
    "thor":     ("Containment",      "Action"),
    "saga":     ("Reporter",         "Reporting"),
}

_AGENT_TOOLS = {
    "odin":     ["Sentinel KQL", "Defender XDR", "Entra ID", "ServiceNow"],
    "athena":   ["Sentinel KQL", "Defender Hunting", "Entra Logs", "Correlation Engine"],
    "mimir":    ["PS AST Parser", "Deobfuscation", "AMSI Trace", "IOC Regex"],
    "heimdall": ["VirusTotal", "AbuseIPDB", "MISP", "MS Threat Intel"],
    "frigg":    ["Live Response", "KQL Endpoint", "Evidence Hash"],
    "thor":     ["Defender XDR", "Firewall API", "Entra ID", "Exchange"],
    "saga":     ["Templates", "ServiceNow", "SharePoint", "STIX 2.1"],
}

_AGENT_GATES = {
    "odin":     "Auto-pass for triage. Confidence: 85%",
    "athena":   "Confidence: 75%. Human: P1 only.",
    "mimir":    "Confidence: 80%. Never executes.",
    "heimdall": "Confidence: 80% (3+ sources).",
    "frigg":    "Human approval before acquisition.",
    "thor":     "Human: ALWAYS. Rollback mandatory.",
    "saga":     "Human: before external sharing.",
}

# MITRE technique prefixes that trigger Mimir (script analysis)
_MIMIR_TECHNIQUE_PREFIXES = (
    "T1059",   # Command and Scripting Interpreter
    "T1027",   # Obfuscated Files or Information
    "T1140",   # Deobfuscate/Decode
    "T1132",   # Data Encoding
    "T1218",   # Signed Binary Proxy Execution
)

# Cost heuristic (POC only; OpenAI-ish pricing)
_COST_PER_1K_TOKENS_USD = 0.013


# ════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════

def generate_trinity_report(
    incident_id: str,
    timespan: str = "P7D",
    *,
    investigate_incident_fn: Optional[Callable] = None,
    run_checklist_fn: Optional[Callable] = None,
    # Precomputed data can be passed instead of the function refs (useful for
    # testing, caching, and demos):
    investigate_data: Optional[dict] = None,
    checklist_data: Optional[dict] = None,
    classification: str = "CONFIDENTIAL",
    org_name: str = "Euronext Cybersecurity",
) -> dict:
    """
    Main entrypoint. Returns {"ok": bool, "data": {...}} consistent with the
    rest of the MCP server's contract.

    Either pass (investigate_incident_fn, run_checklist_fn) and this function
    will call them — or pass the already-fetched (investigate_data,
    checklist_data) dicts directly (e.g. for the standalone demo).
    """
    # ── 1. Fetch real data ────────────────────────────────────────────
    inv = investigate_data
    if inv is None:
        if investigate_incident_fn is None:
            return _fail("investigate_incident_fn or investigate_data is required")
        res = investigate_incident_fn(incident_id, timespan)
        if not res.get("ok"):
            return res  # propagate error
        inv = res.get("data") or {}

    chk = checklist_data
    if chk is None and run_checklist_fn is not None:
        res = run_checklist_fn(incident_id, "auto", timespan, False)
        # Checklist failure is not fatal — we can still render a partial report.
        if res.get("ok"):
            chk = res.get("data") or {}
        else:
            chk = {}
    chk = chk or {}

    # ── 2. Build the shaped report data ───────────────────────────────
    report = _build_report_context(
        inv, chk,
        classification=classification,
        org_name=org_name,
    )

    # ── 3. Render HTML (exact template structure) ─────────────────────
    report["html"] = _render_html(report)

    return _ok({
        "html":          report["html"],
        "meta":          report["meta"],
        "agents":        report["agents"],
        "poc_simulated": _POC_SIMULATED,
    })


def register_trinity_report_tool(
    mcp,
    *,
    investigate_incident_fn: Callable,
    run_checklist_fn: Callable,
    tool_def_registrar: Optional[Callable] = None,
) -> None:
    """
    Register `generate_trinity_report` as an MCP tool on the given server.

    If your mcp_server.py exposes a _register_tool_def() helper, pass it in
    so the tool shows up in get_tools(). Otherwise we just skip that step.
    """
    if tool_def_registrar is not None:
        tool_def_registrar(
            "generate_trinity_report",
            ("Generates the Trinity incident HTML report for a given Sentinel "
             "incident. Orchestrates investigate_incident + run_investigation_checklist "
             "internally and renders the multi-agent decision flow (Odin → Athena → "
             "Mimir/Heimdall/Frigg → Thor → Saga) onto the standard Trinity "
             "portal template. POC: agent delegation is retrospectively narrated; "
             "costs and inter-agent communications are synthesized."),
            {"incident_id": "Sentinel incident number",
             "timespan":    "ISO8601 duration, default P7D"},
        )

    @mcp.tool
    def generate_trinity_report_tool(incident_id: str,
                                     timespan: str = "P7D") -> dict:
        return generate_trinity_report(
            incident_id, timespan,
            investigate_incident_fn=investigate_incident_fn,
            run_checklist_fn=run_checklist_fn,
        )


# ════════════════════════════════════════════════════════════════════════
# REPORT CONTEXT BUILDER — maps real MCP data → structured report dict
# ════════════════════════════════════════════════════════════════════════

def _build_report_context(inv: dict, chk: dict,
                          classification: str,
                          org_name: str) -> dict:
    """Assemble the structured dict that the HTML renderer consumes."""
    incident = inv.get("incident") or {}
    alerts   = inv.get("alerts")   or {}
    ents     = inv.get("entities") or {}
    mitre    = inv.get("mitre")    or {}
    tl       = inv.get("timeline") or {}
    risk_level = inv.get("risk_level") or "Medium"

    # --- Basic incident fields ---
    inc_number_raw = incident.get("id") or incident.get("incident_number") or "?"
    inc_id = _format_incident_id(inc_number_raw)
    title  = str(incident.get("title") or "Untitled incident")
    severity_raw = str(incident.get("severity") or "Medium")
    status = str(incident.get("status") or "Investigating")
    owner  = incident.get("owner")
    created_time_iso = incident.get("created_time") or tl.get("first_alert")
    last_modified_iso = incident.get("last_modified_time") or incident.get("last_modified")

    p_label, _sev_color = _SEVERITY_TO_P_LABEL.get(severity_raw.lower(),
                                                    ("P3 Medium", "blue"))
    risk_score = _RISK_LEVEL_TO_SCORE.get(risk_level, 60)

    # --- Primary entities ---
    primary_host = _first_non_empty(
        (chk.get("entities_extracted") or {}).get("primary_host"),
        *(ents.get("hosts") or []),
    )
    primary_user = _first_non_empty(
        (chk.get("entities_extracted") or {}).get("primary_user"),
        *(ents.get("users") or []),
    )
    primary_ip = _first_non_empty(
        (chk.get("entities_extracted") or {}).get("primary_ip"),
        *(ents.get("ips") or []),
    )

    # --- MITRE techniques/tactics table rows ---
    techniques = list(mitre.get("techniques") or [])
    tactics    = list(mitre.get("tactics") or [])
    mitre_rows = _pair_techniques_with_tactics(techniques, tactics)
    primary_technique = techniques[0] if techniques else ""

    # --- IOCs table (from real VT/AbuseIPDB enrichment) ---
    ioc_enrichment = chk.get("ioc_enrichment") or {}
    iocs = _shape_iocs_for_table(ioc_enrichment)

    # --- SLA calc ---
    detect_minutes = _compute_detect_minutes(alerts, chk, created_time_iso)
    sla_targets = _SLA_TARGETS_MIN.get(p_label, _SLA_TARGETS_MIN["P3 Medium"])

    # --- Agent states ---
    agent_ctx = _derive_agent_states(
        inv=inv, chk=chk,
        techniques=techniques,
        iocs=iocs,
        primary_host=primary_host,
        primary_user=primary_user,
    )

    # --- Timeline (real base + synthetic agent offsets) ---
    timeline_rows = _build_timeline(
        first_alert_iso=created_time_iso,
        title=title,
        agent_ctx=agent_ctx,
        p_label=p_label,
    )

    # --- Analyst notes (auto-generated from real owner + risk) ---
    analyst_notes = _build_analyst_notes(
        owner=owner,
        primary_user=primary_user,
        risk_level=risk_level,
        first_alert_iso=created_time_iso,
    )

    # --- Meta ---
    generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    gen_date     = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    return {
        "meta": {
            "inc_id":         inc_id,
            "inc_dom_id":     _slug_id(inc_id),
            "title":          title,
            "generated_ts":   generated_ts,
            "gen_date":       gen_date,
            "classification": classification,
            "org_name":       org_name,
        },
        "incident_summary": {
            "inc_id":         inc_id,
            "p_label":        p_label,
            "status":         status,
            "detection_time": _fmt_iso_as_utc(created_time_iso),
            "source":         "Microsoft Sentinel",
            "risk_score":     risk_score,
            "host":           primary_host or "—",
            "user":           primary_user or "—",
            "mitre_primary":  primary_technique or "—",
        },
        "sla": {
            "detect_actual_min":  detect_minutes,
            "detect_target_min":  sla_targets["detect"],
            "contain_target_min": sla_targets["contain"],
            "jira":               "None",
        },
        "mitre_rows":    mitre_rows,
        "iocs":          iocs,
        "agents":        agent_ctx,
        "timeline_rows": timeline_rows,
        "analyst_notes": analyst_notes,
    }


# ════════════════════════════════════════════════════════════════════════
# AGENT STATE DERIVATION — the core "mock delegation" logic
# ════════════════════════════════════════════════════════════════════════

def _derive_agent_states(*, inv: dict, chk: dict,
                         techniques: List[str],
                         iocs: List[dict],
                         primary_host: str,
                         primary_user: str) -> Dict[str, dict]:
    """
    Build the per-agent state dicts that drive both the Agent Activity table
    and the Agent Decision Flow section.

    Each agent gets:
      status:       "complete" | "working" | "waiting"
      confidence:   int 0–100 (None for non-reasoning agents)
      action_text:  short summary (Action/Decision block)
      findings:     list of (label, value) tuples
      comms:        list of (time_str, direction, message) tuples
      actions:      list of (done_bool, text, tag) — for Thor's Actions Taken
      cost_usd:     float
      tokens:       int
    """
    alerts = inv.get("alerts") or {}
    ents   = inv.get("entities") or {}
    alerts_count = int(alerts.get("count") or 0)
    ioc_count    = len(iocs)
    has_alerts   = alerts_count > 0

    # Synthetic base time for inter-agent messages. Real first-alert time if
    # we have one, otherwise "now".
    base_dt = _parse_iso(inv.get("timeline", {}).get("first_alert")) \
           or _parse_iso((inv.get("incident") or {}).get("created_time")) \
           or datetime.now(timezone.utc)
    base_hms = base_dt.strftime("%H:%M:%S")

    def _offset(seconds: int) -> str:
        return (base_dt + timedelta(seconds=seconds)).strftime("%H:%M:%S")

    # Tokens heuristic (POC)
    def _cost(tokens: int) -> float:
        return round(tokens / 1000.0 * _COST_PER_1K_TOKENS_USD, 2)

    malicious_iocs = [i for i in iocs if i["verdict"] == "malicious"]
    mimir_needed = _any_technique_matches(techniques, _MIMIR_TECHNIQUE_PREFIXES)

    # ── ODIN ── Triage (always runs, always complete if we have anything)
    odin_tokens = 800 + alerts_count * 200
    odin = {
        "status":     "complete" if has_alerts else "waiting",
        "confidence": 95 if has_alerts else None,
        "action_text": (
            f"Triaged {inv.get('risk_level','Medium')}. "
            f"Correlated {alerts_count} related alert{'s' if alerts_count != 1 else ''}."
            if has_alerts else "Waiting for alerts."
        ),
        "findings": _truncate([
            ("Related", f"{alerts_count} alert{'s' if alerts_count != 1 else ''} on same host")
                if alerts_count else None,
            ("Flags", ", ".join(alerts.get("names", [])[:2]) or "—")
                if alerts.get("names") else None,
        ]),
        "comms": [
            (base_hms, "← Sentinel",
             (alerts.get("names") or ["SecurityAlert"])[0] +
             (f" on {primary_host}" if primary_host else "")),
            (_offset(7), "→ Athena",
             f"Triaged {inv.get('risk_level','Medium')}. {alerts_count} correlated alerts."),
        ],
        "cost_usd": _cost(odin_tokens),
        "tokens":   odin_tokens,
    }

    # ── ATHENA ── Analysis (complete if any real data)
    entity_count = sum(len(ents.get(k, [])) for k in
                       ("users", "ips", "hosts", "domains", "processes", "files"))
    athena_tokens = 4_000 + entity_count * 150 + len(techniques) * 400
    athena_confidence = 88 if techniques else (72 if has_alerts else None)
    athena = {
        "status":     "complete" if has_alerts else "waiting",
        "confidence": athena_confidence,
        "action_text": (
            f"Attack timeline built. "
            + ("Potential lateral movement." if "lateral" in " ".join(techniques).lower()
               or len(ents.get("hosts", [])) > 1
               else "Attack chain reconstructed.")
        ) if has_alerts else "Waiting for triage.",
        "findings": _truncate([
            ("Chain",
             " → ".join(_mitre_chain(techniques)) or "—")
                if techniques else None,
            ("Risk", _athena_risk_note(inv, iocs)),
        ]),
        "comms": [
            (_offset(7),  "← Odin",
             f"Triaged {inv.get('risk_level','Medium')}. {alerts_count} correlated alerts."),
            (_offset(55), "→ Mimir",
             "Analyze encoded PS payload" if mimir_needed else "Standby — no scripts detected"),
            (_offset(55), "→ Heimdall",
             f"Enrich {ioc_count} IOC{'s' if ioc_count != 1 else ''}"
                if ioc_count else "Standby — no IOCs"),
        ] + ([(_offset(98), "← Mimir", "Partial: deobfuscation complete")]
             if mimir_needed else []),
        "cost_usd": _cost(athena_tokens),
        "tokens":   athena_tokens,
    }

    # ── MIMIR ── Script Analyst (only relevant for script-related techniques)
    if mimir_needed:
        mimir_tokens = 6_000 + len(ents.get("processes", [])) * 300
        mimir = {
            "status":     "working",
            "confidence": 72,
            "action_text": "Deobfuscating script payload. Stage-2 extracted.",
            "findings": _truncate([
                ("Techniques", ", ".join([t for t in techniques
                                          if t.startswith(_MIMIR_TECHNIQUE_PREFIXES)][:3])),
                ("Processes", ", ".join((ents.get("processes") or [])[:2]) or "—"),
            ]),
            "comms": [
                (_offset(55),  "← Athena", "Analyze encoded PS payload"),
                (_offset(98), "→ Athena", "Partial: deobfuscation complete"),
            ],
            "cost_usd": _cost(mimir_tokens),
            "tokens":   mimir_tokens,
        }
    else:
        mimir = {
            "status":      "waiting",
            "confidence":  None,
            "action_text": "Not triggered — no script execution detected.",
            "findings":    [],
            "comms":       [],
            "cost_usd":    0.0,
            "tokens":      0,
        }

    # ── HEIMDALL ── IOC Enrichment (real VT + AbuseIPDB data)
    if ioc_count:
        heimdall_tokens = 2_000 + ioc_count * 400
        # Pull the 2 most interesting IOCs for findings
        heimdall_findings = []
        for ioc in sorted(iocs,
                          key=lambda x: (x["verdict"] != "malicious",
                                         x["verdict"] != "suspicious"))[:3]:
            heimdall_findings.append((ioc["value"], ioc["evidence"]))

        any_malicious   = any(i["verdict"] == "malicious" for i in iocs)
        n_verdicted     = sum(1 for i in iocs if i["verdict"] in ("malicious", "suspicious", "clean"))
        heimdall_status = "complete" if n_verdicted == ioc_count else "working"

        heimdall = {
            "status":     heimdall_status,
            "confidence": 85 if any_malicious else 65,
            "action_text": (
                f"{ioc_count} IOC{'s' if ioc_count != 1 else ''} enriched "
                f"against VT/AbuseIPDB. "
                + (f"{len(malicious_iocs)} malicious." if malicious_iocs else "No malicious hits.")
            ),
            "findings": heimdall_findings or [],
            "comms": [
                (_offset(55), "← Athena",
                 f"Enrich {ioc_count} IOC{'s' if ioc_count != 1 else ''}"),
            ] + ([(_offset(130), "→ Athena",
                   f"{len(malicious_iocs)} malicious verdicts")] if malicious_iocs else []),
            "cost_usd": _cost(heimdall_tokens),
            "tokens":   heimdall_tokens,
        }
    else:
        heimdall = {
            "status":      "waiting",
            "confidence":  None,
            "action_text": "Waiting for IOCs to enrich.",
            "findings":    [],
            "comms":       [],
            "cost_usd":    0.0,
            "tokens":      0,
        }

    # ── FRIGG ── Forensics (always human-gated in POC)
    asset_context = inv.get("asset_context") or []
    frigg_findings = []
    if asset_context:
        for ac in asset_context[:2]:
            ent = ac.get("entity") or "host"
            frigg_findings.append(("Asset", f"{ent} — CMDB context available"))
    frigg = {
        "status":      "waiting",
        "confidence":  None,
        "action_text": "Queued — waiting for human approval before acquisition.",
        "findings":    frigg_findings,
        "comms":       [],
        "cost_usd":    0.0,
        "tokens":      0,
    }

    # ── THOR ── Containment (human-gated; actions derived from real IOCs)
    thor_actions = _derive_thor_actions(
        primary_host=primary_host,
        primary_user=primary_user,
        malicious_iocs=malicious_iocs,
    )
    thor = {
        "status":      "waiting",
        "confidence":  None,
        "action_text": "Standing by for containment. Awaiting human gate.",
        "findings":    [],
        "comms":       [],
        "actions":     thor_actions,
        "cost_usd":    0.0,
        "tokens":      0,
    }

    # ── SAGA ── Reporter (that's us, generating right now)
    saga_tokens = 600 + alerts_count * 50 + ioc_count * 30
    saga = {
        "status":      "working",
        "confidence":  None,
        "action_text": "Assembling report. Awaiting human review before sharing.",
        "findings":    [],
        "comms":       [],
        "cost_usd":    _cost(saga_tokens),
        "tokens":      saga_tokens,
    }

    return {
        "odin":     odin,
        "athena":   athena,
        "mimir":    mimir,
        "heimdall": heimdall,
        "frigg":    frigg,
        "thor":     thor,
        "saga":     saga,
    }


# ════════════════════════════════════════════════════════════════════════
# HTML RENDERER — preserves the exact Trinity portal template structure
# ════════════════════════════════════════════════════════════════════════

# We include the --red / --text-3 / --accent CSS variables as :root defaults
# so the report renders standalone. When embedded in the Trinity portal,
# the outer page's variables will win.
_CSS = """*{margin:0;padding:0;box-sizing:border-box}
:root{--red:#ef4444;--text-3:#888;--accent:#6C63FF}
body{font-family:'DM Sans','Inter',system-ui,sans-serif;background:#fff;color:#1a1a1a;padding:40px;max-width:800px;margin:0 auto;font-size:13px;line-height:1.5}
.report-header{text-align:center;margin-bottom:32px;padding-bottom:24px;border-bottom:2px solid #e0e0e0}
.report-logo{font-size:12px;font-weight:700;color:#6C63FF;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px}
.report-title{font-size:24px;font-weight:700;margin-bottom:4px}
.report-subtitle{font-size:12px;color:#888}
.report-section{margin-bottom:24px}
.report-section-title{font-size:11px;font-weight:700;color:#6C63FF;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #e0e0e0}
.report-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:12px}
.report-kv{padding:10px 12px;background:#f7f7f8;border-radius:8px}
.report-kv-label{font-size:9px;color:#888;text-transform:uppercase;letter-spacing:0.3px;margin-bottom:2px}
.report-kv-val{font-size:13px;font-weight:600}
.report-table{width:100%;border-collapse:collapse;font-size:12px}
.report-table th{text-align:left;font-size:10px;font-weight:600;color:#888;text-transform:uppercase;padding:8px 12px;border-bottom:2px solid #e0e0e0}
.report-table td{padding:8px 12px;border-bottom:1px solid #f0f0f0;color:#333}
.report-table tr:last-child td{border-bottom:none}
.report-footer{text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid #e0e0e0;font-size:10px;color:#999}
.report-close,.report-actions{display:none}
.rf-flow{display:flex;flex-direction:column;align-items:center;gap:0;padding:8px 0}
.rf-connector{width:2px;height:20px;background:#ccc;margin:0 auto}
.rf-par-wrap{width:100%;display:flex;flex-direction:column;align-items:center}
.rf-par-label{font-size:9px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px;padding:2px 10px;border-radius:4px;border:1px dashed #ccc}
.rf-par-row{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;width:100%}
.rf-node{width:100%;max-width:560px;border:1px solid #ddd;border-radius:10px;overflow:hidden}
.rf-par-row .rf-node{max-width:240px;min-width:140px;flex:1}
.rf-head{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer}
.rf-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.rf-dot.done{background:#22c55e}
.rf-dot.active{background:#6C63FF}
.rf-dot.pending{background:#ccc}
.rf-agent{font-weight:700;font-size:12px;flex:1;display:flex;align-items:center;gap:6px}
.rf-role{font-weight:400;color:#888;font-size:10px}
.rf-conf{font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;background:#f0f0f0}
.rf-conf.high{color:#22c55e}
.rf-conf.mid{color:#f59e0b}
.rf-conf.low{color:#ef4444}
.rf-chevron{display:none}
.rf-body{max-height:none;overflow:visible}
.rf-inner{padding:0 14px 14px;display:flex;flex-direction:column;gap:10px}
.rf-block{background:#f7f7f8;border-radius:8px;padding:10px 12px}
.rf-block-label{font-size:9px;font-weight:700;color:#6C63FF;text-transform:uppercase;letter-spacing:0.3px;margin-bottom:4px}
.rf-block-text{font-size:12px;line-height:1.5}
.rf-finding{display:flex;gap:8px;font-size:11px;padding:3px 0;border-bottom:1px solid #eee}
.rf-finding:last-child{border-bottom:none}
.rf-finding-label{font-weight:600;color:#888;min-width:80px;flex-shrink:0}
.rf-finding-val{color:#333}
.rf-tools{display:flex;flex-wrap:wrap;gap:4px}
.rf-tool{font-size:9px;padding:2px 6px;border-radius:4px;background:rgba(108,99,255,0.1);color:#6C63FF;font-weight:600}
.rf-comms{display:flex;flex-direction:column;gap:4px}
.rf-comm{font-size:11px;color:#555;display:flex;gap:6px;align-items:baseline}
.rf-comm-arrow{color:#6C63FF;font-weight:700;flex-shrink:0}
.rf-comm-time{color:#888;font-size:10px;flex-shrink:0;min-width:50px}
.rf-gate{font-size:10px;color:#f59e0b;font-style:italic}
.rf-cost{font-size:10px;color:#888;text-align:right;margin-top:2px}
.rf-cost span{color:#6C63FF;font-weight:600}"""


def _render_html(ctx: dict) -> str:
    """Build the full HTML string. Preserves the template's exact structure."""
    meta = ctx["meta"]
    summ = ctx["incident_summary"]
    sla  = ctx["sla"]
    agents = ctx["agents"]

    parts: List[str] = []

    # ── HEAD ──────────────────────────────────────────────────────────
    parts.append(
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>Trinity Incident Report — {_h(meta["inc_id"])}</title>'
        f'<style>{_CSS}</style></head><body>'
    )

    # ── ACTION BUTTONS (hidden in standalone, visible in portal) ──────
    parts.append(
        '<div class="report-actions">'
        '<button class="report-dl" onclick="downloadReportPDF()" title="Download as PDF">⇩</button>'
        f'<button class="report-dl" onclick="downloadReportHTML(\'{_h(meta["inc_id"])}\')" title="Download as HTML">⎘</button>'
        '</div>'
        '<button class="report-close" onclick="closeReport()">×</button>'
    )

    # ── HEADER ────────────────────────────────────────────────────────
    parts.append(f"""
    <div class="report-header">
      <div class="report-logo">△ Trinity — Incident Report</div>
      <div class="report-title">{_h(meta["title"])}</div>
      <div class="report-subtitle">{_h(meta["inc_id"])} • Generated {_h(meta["generated_ts"])} • Classification: {_h(meta["classification"])}</div>
    </div>""")

    # ── INCIDENT SUMMARY ──────────────────────────────────────────────
    parts.append('<div class="report-section"><div class="report-section-title">Incident Summary</div>')
    parts.append('<div class="report-grid">')
    for label, val, extra_style in [
        ("Incident ID",    summ["inc_id"],        ""),
        ("Severity",       summ["p_label"],       'style="color:var(--red)"' if summ["p_label"].startswith("P1") else ""),
        ("Status",         summ["status"],        ""),
        ("Detection Time", summ["detection_time"], ""),
        ("Source",         summ["source"],        ""),
        ("Risk Score",     f"{summ['risk_score']}/100",
                           'style="color:var(--red)"' if summ["risk_score"] >= 80 else ""),
        ("Affected Host",  summ["host"],          ""),
        ("Affected User",  summ["user"],          ""),
        ("MITRE ATT&CK",   summ["mitre_primary"], ""),
    ]:
        parts.append(
            f'<div class="report-kv"><div class="report-kv-label">{_h(label)}</div>'
            f'<div class="report-kv-val" {extra_style}>{_h(val)}</div></div>'
        )
    parts.append('</div></div>')

    # ── SLA PERFORMANCE ───────────────────────────────────────────────
    detect_actual = f"{sla['detect_actual_min']}min" if sla["detect_actual_min"] is not None else "Unknown"
    parts.append(f"""
    <div class="report-section"><div class="report-section-title">SLA Performance</div>
      <div class="report-grid">
        <div class="report-kv"><div class="report-kv-label">Time to Detect</div><div class="report-kv-val">{_h(detect_actual)} <span style="font-size:10px;color:var(--text-3)">/ {sla['detect_target_min']}min SLA</span></div></div>
        <div class="report-kv"><div class="report-kv-label">Time to Contain</div><div class="report-kv-val">Pending <span style="font-size:10px;color:var(--text-3)">/ {sla['contain_target_min']}min SLA</span></div></div>
        <div class="report-kv"><div class="report-kv-label">Jira</div><div class="report-kv-val">{_h(sla['jira'])}</div></div>
      </div>
    </div>""")

    # ── MITRE TABLE ───────────────────────────────────────────────────
    parts.append(
        '<div class="report-section"><div class="report-section-title">MITRE ATT&amp;CK Techniques</div>'
        '<table class="report-table"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>'
    )
    if ctx["mitre_rows"]:
        for tid, tname, tac in ctx["mitre_rows"]:
            parts.append(
                f'<tr><td style="font-weight:600">{_h(tid)}</td>'
                f'<td>{_h(tname)}</td><td>{_h(tac)}</td></tr>'
            )
    else:
        parts.append('<tr><td colspan="3" style="color:#999;font-style:italic">No MITRE techniques mapped.</td></tr>')
    parts.append('</tbody></table></div>')

    # ── IOCs TABLE ────────────────────────────────────────────────────
    parts.append(
        '<div class="report-section"><div class="report-section-title">Indicators of Compromise</div>'
        '<table class="report-table"><thead><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Source</th></tr></thead><tbody>'
    )
    if ctx["iocs"]:
        for ioc in ctx["iocs"]:
            v_color = _verdict_color(ioc["verdict"])
            parts.append(
                f'<tr><td>{_h(ioc["type_label"])}</td>'
                f'<td style="font-family:monospace;font-size:11px">{_h(ioc["display_value"])}</td>'
                f'<td><span style="color:{v_color}; font-weight:600">{_h(ioc["verdict"])}</span></td>'
                f'<td>{_h(ioc["source"])}</td></tr>'
            )
    else:
        parts.append('<tr><td colspan="4" style="color:#999;font-style:italic">No IOCs enriched.</td></tr>')
    parts.append('</tbody></table></div>')

    # ── AGENT ACTIVITY TABLE ──────────────────────────────────────────
    parts.append(
        '<div class="report-section"><div class="report-section-title">Agent Activity &amp; Findings</div>'
        '<table class="report-table"><thead><tr><th>Agent</th><th>Role</th><th>Status</th><th>Findings</th><th>Cost</th></tr></thead><tbody>'
    )
    total_cost = 0.0
    total_tokens = 0
    for agent_key in ["odin", "athena", "mimir", "heimdall", "frigg", "thor", "saga"]:
        a = agents[agent_key]
        role_label, _phase = _AGENT_ROLES[agent_key]
        findings_text = a["action_text"]
        parts.append(
            f'<tr><td style="font-weight:600">{_h(agent_key.capitalize())}</td>'
            f'<td>{_h(role_label)}</td>'
            f'<td>{_h(a["status"])}</td>'
            f'<td>{_h(findings_text)}</td>'
            f'<td style="color:var(--accent)">${a["cost_usd"]:.2f}</td></tr>'
        )
        total_cost   += a["cost_usd"]
        total_tokens += a["tokens"]
    parts.append('</tbody></table>')
    parts.append(
        f'<div style="margin-top:10px;display:flex;justify-content:flex-end;gap:16px;font-size:12px;font-weight:600">'
        f'<span style="color:var(--text-3)">Total AI Cost:</span>'
        f'<span style="color:var(--accent)">${total_cost:.2f} ({total_tokens:,} tokens)</span>'
        f'</div></div>'
    )

    # ── AGENT DECISION FLOW ───────────────────────────────────────────
    parts.append(
        '<div class="report-section"><div class="report-section-title">Agent Decision Flow '
        '<span style="font-size:9px;font-weight:400;color:var(--text-3);text-transform:none;letter-spacing:0">— click to expand</span></div>'
        '<div class="rf-flow">'
    )

    # Sequential: Odin → Athena → [parallel: Mimir, Heimdall, Frigg] → Thor → Saga
    parts.append(_render_agent_node("odin", agents["odin"], meta["inc_dom_id"]))
    parts.append('<div class="rf-connector active"></div>')
    parts.append(_render_agent_node("athena", agents["athena"], meta["inc_dom_id"]))
    parts.append('<div class="rf-connector"></div>')

    # Parallel row
    parts.append('<div class="rf-par-wrap"><div class="rf-par-label">Parallel Investigation</div><div class="rf-par-row">')
    parts.append(_render_agent_node("mimir", agents["mimir"], meta["inc_dom_id"]))
    parts.append(_render_agent_node("heimdall", agents["heimdall"], meta["inc_dom_id"]))
    parts.append(_render_agent_node("frigg", agents["frigg"], meta["inc_dom_id"]))
    parts.append('</div></div>')

    parts.append('<div class="rf-connector"></div>')
    parts.append(_render_agent_node("thor", agents["thor"], meta["inc_dom_id"]))
    parts.append('<div class="rf-connector"></div>')
    parts.append(_render_agent_node("saga", agents["saga"], meta["inc_dom_id"]))

    parts.append('</div></div>')

    # ── TIMELINE ──────────────────────────────────────────────────────
    parts.append(
        '<div class="report-section"><div class="report-section-title">Timeline</div>'
        '<table class="report-table"><thead><tr><th>Time</th><th>Event</th></tr></thead><tbody>'
    )
    for t, evt in ctx["timeline_rows"]:
        parts.append(
            f'<tr><td style="white-space:nowrap;font-variant-numeric:tabular-nums">{_h(t)}</td>'
            f'<td>{evt}</td></tr>'   # evt contains <strong> tags already
        )
    parts.append('</tbody></table></div>')

    # ── ANALYST NOTES ─────────────────────────────────────────────────
    parts.append(
        '<div class="report-section"><div class="report-section-title">Analyst Notes</div>'
        '<table class="report-table"><thead><tr><th>Analyst</th><th>Time</th><th>Note</th></tr></thead><tbody>'
    )
    if ctx["analyst_notes"]:
        for name, t, note in ctx["analyst_notes"]:
            parts.append(
                f'<tr><td style="font-weight:600">{_h(name)}</td>'
                f'<td>{_h(t)}</td><td>{_h(note)}</td></tr>'
            )
    else:
        parts.append('<tr><td colspan="3" style="color:#999;font-style:italic">No notes yet.</td></tr>')
    parts.append('</tbody></table></div>')

    # ── FOOTER ────────────────────────────────────────────────────────
    parts.append(
        f'<div class="report-footer">Trinity CyAgent Operations Portal • {_h(meta["org_name"])} • {_h(meta["gen_date"])} • {_h(meta["classification"])}</div>'
        '</body></html>'
    )

    return "".join(parts)


def _render_agent_node(agent_key: str, state: dict, inc_dom_id: str) -> str:
    """Render one rf-node. Matches the template's nested structure exactly."""
    role_label, phase = _AGENT_ROLES[agent_key]
    node_id = f"rf-{inc_dom_id}-{agent_key}"

    # Status → dot class
    dot_cls = {"complete": "done", "working": "active", "waiting": "pending"} \
              .get(state["status"], "pending")

    # Confidence → badge
    conf_html = ""
    if state.get("confidence") is not None:
        c = state["confidence"]
        tier = "high" if c >= 80 else ("mid" if c >= 65 else "low")
        conf_html = f'<span class="rf-conf {tier}">{c}%</span>'

    html_parts = [
        f'<div class="rf-node" id="{_h(node_id)}" onclick="toggleFlowNode(\'{_h(node_id)}\',event)">',
        '<div class="rf-head">',
        f'<span class="rf-dot {dot_cls}"></span>',
        f'<span class="rf-agent">{_h(agent_key.capitalize())} <span class="rf-role">{_h(role_label)} ({_h(phase)})</span></span>',
        conf_html,
        '<span class="rf-chevron">▶</span>',
        '</div>',
        '<div class="rf-body"><div class="rf-inner">',
    ]

    # Action / Decision block
    html_parts.append(
        '<div class="rf-block">'
        '<div class="rf-block-label">Action / Decision</div>'
        f'<div class="rf-block-text">{_h(state["action_text"])}</div>'
        '</div>'
    )

    # Gate
    html_parts.append(
        f'<div class="rf-gate">Gate: {_h(_AGENT_GATES[agent_key])}</div>'
    )

    # Reasoning & Findings
    if state.get("findings"):
        html_parts.append(
            '<div class="rf-block">'
            '<div class="rf-block-label">Reasoning &amp; Findings</div>'
        )
        for label, val in state["findings"]:
            html_parts.append(
                f'<div class="rf-finding">'
                f'<span class="rf-finding-label">{_h(label)}</span>'
                f'<span class="rf-finding-val">{_h(val)}</span>'
                f'</div>'
            )
        html_parts.append('</div>')

    # Actions Taken (Thor-specific)
    if state.get("actions"):
        html_parts.append(
            '<div class="rf-block">'
            '<div class="rf-block-label">Actions Taken</div>'
        )
        for done, text, tag in state["actions"]:
            check = "☑" if done else "☐"
            tag_html = (f' <span style="color:var(--red);font-size:9px;font-weight:700">{_h(tag)}</span>'
                        if tag else '')
            html_parts.append(
                f'<div class="rf-finding">'
                f'<span class="rf-finding-label">{check}</span>'
                f'<span class="rf-finding-val">{_h(text)}{tag_html}</span>'
                f'</div>'
            )
        html_parts.append('</div>')

    # Communications
    if state.get("comms"):
        html_parts.append(
            '<div class="rf-block">'
            '<div class="rf-block-label">Communications</div>'
            '<div class="rf-comms">'
        )
        for t, arrow, msg in state["comms"]:
            html_parts.append(
                f'<div class="rf-comm">'
                f'<span class="rf-comm-time">{_h(t)}</span>'
                f'<span class="rf-comm-arrow">{_h(arrow)}</span>'
                f'<span>{_h(msg)}</span>'
                f'</div>'
            )
        html_parts.append('</div></div>')

    # Tools
    html_parts.append(
        '<div class="rf-block"><div class="rf-block-label">Tools</div>'
        '<div class="rf-tools">'
    )
    for tool in _AGENT_TOOLS[agent_key]:
        html_parts.append(f'<span class="rf-tool">{_h(tool)}</span>')
    html_parts.append('</div></div>')

    # Cost
    html_parts.append(
        f'<div class="rf-cost">${state["cost_usd"]:.2f} • {state["tokens"]:,} tokens</div>'
    )

    html_parts.append('</div></div></div>')
    return "".join(html_parts)


# ════════════════════════════════════════════════════════════════════════
# UTILITIES
# ════════════════════════════════════════════════════════════════════════

def _ok(data: Any) -> dict:
    return {"ok": True, "data": data}


def _fail(msg: str, code: str = "VALIDATION_ERROR") -> dict:
    return {"ok": False, "error": msg, "code": code}


def _h(val: Any) -> str:
    """HTML-escape. Handles None and non-strings."""
    if val is None:
        return ""
    return _html.escape(str(val), quote=True)


def _first_non_empty(*candidates) -> str:
    for c in candidates:
        if c and str(c).strip():
            return str(c).strip()
    return ""


def _slug_id(inc_id: str) -> str:
    """INC-2026-0847 → INC20260847 (for DOM ids that JS toggle relies on)."""
    return re.sub(r"[^A-Za-z0-9]", "", inc_id or "unknown")


def _format_incident_id(raw) -> str:
    """Normalise to INC-YYYY-NNNN style if we can; otherwise passthrough."""
    if raw is None:
        return "INC-UNKNOWN"
    s = str(raw)
    if s.upper().startswith("INC-"):
        return s
    # pure number? year-prefix it with current year for display.
    if s.isdigit():
        yr = datetime.now(timezone.utc).year
        return f"INC-{yr}-{int(s):04d}"
    return s


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        # Handle trailing Z
        if isinstance(s, str) and s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(str(s))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _fmt_iso_as_utc(s: Optional[str]) -> str:
    dt = _parse_iso(s)
    if not dt:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _truncate(items: List[Optional[Tuple]]) -> List[Tuple]:
    return [it for it in items if it is not None]


def _any_technique_matches(techniques: List[str], prefixes: Tuple[str, ...]) -> bool:
    for t in techniques or []:
        ts = str(t).strip()
        for p in prefixes:
            if ts.startswith(p):
                return True
    return False


def _mitre_chain(techniques: List[str]) -> List[str]:
    """Label-ify for the Athena 'Chain' finding."""
    mapping = {
        "T1059": "Script", "T1027": "Obfuscation", "T1140": "Decode",
        "T1132": "Encoding", "T1071": "C2", "T1105": "Ingress",
        "T1003": "Cred Dump", "T1110": "Brute Force", "T1078": "Valid Accounts",
        "T1021": "Lateral", "T1486": "Encrypt", "T1566": "Phishing",
    }
    out = []
    seen = set()
    for t in techniques or []:
        key = str(t).split(".")[0]
        label = mapping.get(key, key)
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out[:5]


def _athena_risk_note(inv: dict, iocs: List[dict]) -> str:
    malicious = any(i["verdict"] == "malicious" for i in iocs)
    if malicious:
        return "Malicious IOCs — C2 channel likely established"
    risk = inv.get("risk_level") or "Medium"
    return f"Overall risk: {risk}"


_MITRE_TECHNIQUE_NAMES = {
    # Minimal name map — extend as needed. Missing entries fall back to id.
    "T1059":       "Command and Scripting Interpreter",
    "T1059.001":   "PowerShell",
    "T1059.003":   "Windows Command Shell",
    "T1027":       "Obfuscated Files or Information",
    "T1140":       "Deobfuscate/Decode Files",
    "T1132":       "Data Encoding",
    "T1132.001":   "Standard Encoding",
    "T1071":       "Application Layer Protocol",
    "T1071.001":   "Web Protocols",
    "T1105":       "Ingress Tool Transfer",
    "T1003":       "OS Credential Dumping",
    "T1110":       "Brute Force",
    "T1110.001":   "Password Guessing",
    "T1078":       "Valid Accounts",
    "T1021":       "Remote Services",
    "T1021.001":   "Remote Desktop Protocol",
    "T1486":       "Data Encrypted for Impact",
    "T1566":       "Phishing",
    "T1566.001":   "Spearphishing Attachment",
    "T1218":       "Signed Binary Proxy Execution",
}

_TACTIC_FOR_TECHNIQUE_PREFIX = {
    "T1059": "Execution",
    "T1027": "Defense Evasion",
    "T1140": "Defense Evasion",
    "T1132": "Command and Control",
    "T1071": "Command and Control",
    "T1105": "Command and Control",
    "T1003": "Credential Access",
    "T1110": "Credential Access",
    "T1078": "Defense Evasion",
    "T1021": "Lateral Movement",
    "T1486": "Impact",
    "T1566": "Initial Access",
    "T1218": "Defense Evasion",
}


def _pair_techniques_with_tactics(techniques: List[str], tactics: List[str]) -> List[Tuple[str, str, str]]:
    """Return rows of (id, name, tactic) for the MITRE table."""
    # If we have a roughly-matched tactics list (same length), zip them.
    rows: List[Tuple[str, str, str]] = []
    tactic_for = {}
    if tactics and len(tactics) == len(techniques):
        for tid, tac in zip(techniques, tactics):
            tactic_for[tid] = tac
    for tid in techniques or []:
        tid_s = str(tid)
        name  = _MITRE_TECHNIQUE_NAMES.get(tid_s) or _MITRE_TECHNIQUE_NAMES.get(tid_s.split(".")[0]) or tid_s
        tac = tactic_for.get(tid_s) \
              or _TACTIC_FOR_TECHNIQUE_PREFIX.get(tid_s.split(".")[0]) \
              or (tactics[0] if tactics else "—")
        rows.append((tid_s, name, tac))
    return rows


def _shape_iocs_for_table(ioc_enrichment: Dict[str, dict]) -> List[dict]:
    """Flatten ioc_enrichment into rows for both the IOC table and Heimdall's
    findings. `source` is the Heimdall/Mimir agent credited for surfacing it."""
    out = []
    for key, d in (ioc_enrichment or {}).items():
        if not isinstance(d, dict):
            continue
        ioc_type = (d.get("ioc_type") or "").lower()
        verdict  = (d.get("verdict")  or "unknown").lower()

        type_label = {
            "ip":     "IP",
            "domain": "Domain",
            "url":    "URL",
            "sha256": "Hash (SHA256)",
            "sha1":   "Hash (SHA1)",
            "md5":    "Hash (MD5)",
        }.get(ioc_type, ioc_type.upper() or "IOC")

        # Defanged display for domains/URLs (like the template: cdn-update[.]cloud)
        display_value = key
        if ioc_type in ("domain", "url") and key:
            display_value = _defang(str(key))

        # Evidence string used in Heimdall findings
        evidence_parts = []
        vt = d.get("virustotal") if isinstance(d.get("virustotal"), dict) else None
        ab = d.get("abuseipdb")  if isinstance(d.get("abuseipdb"),  dict) else None
        if vt and (vt.get("malicious_engines") is not None):
            tot = (vt.get("malicious_engines") or 0) + (vt.get("suspicious_engines") or 0)
            evidence_parts.append(f"VT {vt.get('malicious_engines') or 0}/{tot or '—'}")
        if ab and (ab.get("abuse_confidence_score") is not None):
            evidence_parts.append(f"AbuseIPDB {ab.get('abuse_confidence_score')}%")
        evidence = ", ".join(evidence_parts) or verdict

        # Source: Heimdall for IPs/domains/hashes, Mimir if first seen from
        # script analysis (URLs often surfaced from payload deobfuscation)
        source = "Mimir" if ioc_type == "url" else "Heimdall"

        out.append({
            "value":         key,
            "display_value": display_value,
            "type":          ioc_type,
            "type_label":    type_label,
            "verdict":       verdict,
            "source":        source,
            "evidence":      evidence,
        })

    # Sort: malicious first, then suspicious, then everything else
    rank = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3}
    out.sort(key=lambda x: (rank.get(x["verdict"], 4), x["type"], x["value"]))
    return out


def _defang(s: str) -> str:
    """cdn-update.cloud → cdn-update[.]cloud; https:// → hxxps://"""
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Defang only the last '.' before a TLD-ish suffix? Simpler: defang all dots.
    # The template example defangs only the final dot ("cdn-update[.]cloud").
    # We approximate: if it looks like a domain (no path), defang the last dot.
    if "/" not in s and s.count(".") >= 1:
        idx = s.rfind(".")
        s = s[:idx] + "[.]" + s[idx+1:]
    else:
        s = s.replace(".", "[.]", 1)  # defang first dot to neutralize
    return s


def _verdict_color(verdict: str) -> str:
    return {
        "malicious":  "var(--red)",
        "suspicious": "#f59e0b",
        "clean":      "#22c55e",
        "unknown":    "#888",
    }.get(verdict, "#888")


def _compute_detect_minutes(alerts: dict, chk: dict, created_iso: Optional[str]) -> Optional[int]:
    """POC heuristic: Sentinel's detect-time is ~2min for most rules. If we
    have alert_start and incident_created, compute the gap."""
    # For POC, hardcode to 2 minutes (matches the template). If you want real
    # numbers, plug in the difference between alert TimeGenerated and
    # incident CreatedTime.
    return 2


def _build_timeline(*, first_alert_iso: Optional[str],
                    title: str, agent_ctx: Dict[str, dict],
                    p_label: str) -> List[Tuple[str, str]]:
    """Timeline rows: (time, HTML-safe event-with-<strong>). Base time is
    first_alert; agent steps are offsets."""
    base = _parse_iso(first_alert_iso) or datetime.now(timezone.utc)
    def _off(s):
        return (base + timedelta(seconds=s)).strftime("%H:%M:%S")

    rows = [
        (_off(0),   f'<strong>Sentinel</strong> fired alert'),
        (_off(7),   f'<strong>Odin</strong> classified {_h(p_label)}. Escalated to Athena.'),
        (_off(55),  f'<strong>Athena</strong> triggered parallel investigation.'),
    ]
    working_or_done = [k for k in ("mimir", "heimdall", "frigg")
                        if agent_ctx[k]["status"] in ("working", "complete")]
    if working_or_done:
        names = " + ".join(f'<strong>{k.capitalize()}</strong>' for k in working_or_done)
        rows.append((_off(58), f'{names} working...'))
    return rows


def _build_analyst_notes(*, owner, primary_user: str, risk_level: str,
                         first_alert_iso: Optional[str]) -> List[Tuple[str, str, str]]:
    """Synthesize a note from the real owner field."""
    if not owner:
        return []

    # owner may be a dict {assignedTo: "..."} or a raw string
    name = ""
    if isinstance(owner, dict):
        name = owner.get("assignedTo") or owner.get("email") or owner.get("userPrincipalName") or ""
    else:
        name = str(owner)

    if not name:
        return []

    # Nicely abbreviate: "Ana Rocha" → "A. Rocha"
    parts = name.split("@")[0].replace(".", " ").split()
    if len(parts) >= 2:
        initials_name = f"{parts[0][0].upper()}. {parts[-1].capitalize()}"
    else:
        initials_name = name

    base = _parse_iso(first_alert_iso) or datetime.now(timezone.utc)
    t = (base + timedelta(seconds=55)).strftime("%H:%M")

    note_bits = []
    if primary_user:
        note_bits.append(f"Watching — {primary_user} involved")
    note_bits.append(f"{risk_level} risk")

    return [(initials_name, t, ". ".join(note_bits) + ".")]


def _derive_thor_actions(*, primary_host: str, primary_user: str,
                         malicious_iocs: List[dict]) -> List[Tuple[bool, str, str]]:
    """Build Thor's recommended actions from the malicious IOCs + primaries."""
    out = []
    if primary_host:
        out.append((False, f"Isolate {primary_host}", "CRITICAL"))
    for ioc in malicious_iocs[:3]:
        out.append((False, f"Block {ioc['display_value']}", "CRITICAL"))
    if primary_user:
        out.append((False, f"Disable {primary_user}", ""))
    if not out:
        out.append((False, "No containment actions required.", ""))
    return out


# ════════════════════════════════════════════════════════════════════════
# __main__ — standalone demo with mock (realistic) data
# ════════════════════════════════════════════════════════════════════════

def _demo_investigate_data() -> dict:
    """Shaped like a real investigate_incident() return."""
    return {
        "incident": {
            "id":                  847,
            "title":               "Suspicious PowerShell Execution on WKST-FIN-042",
            "severity":            "High",
            "status":              "Investigating",
            "owner":               {"assignedTo": "ana.rocha@euronext.com"},
            "created_time":        "2026-04-20 14:32:07Z",
            "last_modified_time":  "2026-04-20 14:35:12Z",
        },
        "alerts": {
            "count":         3,
            "names":         ["SuspiciousPowerShellExecution",
                              "EncodedCommandLine",
                              "AnomalousNetworkConnection"],
            "product_names": ["Microsoft Defender for Endpoint"],
            "components":    ["MDE"],
        },
        "entities": {
            "users":          ["j.martin@euronext.com"],
            "ips":            ["185.220.101.34"],
            "hosts":          ["WKST-FIN-042"],
            "domains":        ["cdn-update.cloud"],
            "processes":      ["powershell.exe -enc JABzAD0ATgBlAHcA..."],
            "files":          [],
            "hashes":         [],
            "local_accounts": [],
        },
        "timeline": {
            "first_alert": "2026-04-20 14:32:07Z",
            "last_alert":  "2026-04-20 14:33:45Z",
        },
        "mitre": {
            "tactics":    ["Execution", "Command and Control", "Command and Control"],
            "techniques": ["T1059.001", "T1132.001", "T1071.001"],
        },
        "asset_context": [
            {"entity": "WKST-FIN-042",
             "result": {"BusinessEntity": "Finance", "logsource": "MDE"}},
        ],
        "risk_level": "High",
    }


def _demo_checklist_data() -> dict:
    """Shaped like a real run_investigation_checklist() return."""
    return {
        "incident_id": 847,
        "incident_title": "Suspicious PowerShell Execution on WKST-FIN-042",
        "checklist_used": "execution",
        "checklist_auto": True,
        "compact": False,
        "entities_extracted": {
            "hosts":        ["wkst-fin-042"],
            "users":        ["j.martin@euronext.com"],
            "ips":          ["185.220.101.34"],
            "domains":      ["cdn-update.cloud"],
            "primary_host": "wkst-fin-042",
            "primary_user": "j.martin@euronext.com",
            "primary_ip":   "185.220.101.34",
        },
        "mitre": {
            "tactics":    ["Execution", "Command and Control"],
            "techniques": ["T1059.001", "T1132.001", "T1071.001"],
        },
        "ioc_enrichment": {
            "cdn-update.cloud": {
                "ioc":       "cdn-update.cloud",
                "ioc_type":  "domain",
                "verdict":   "malicious",
                "escalate":  True,
                "virustotal": {
                    "provider": "virustotal", "status": "found",
                    "malicious_engines": 8, "suspicious_engines": 2,
                    "country": "RU", "gui_link": "https://vt/...",
                },
            },
            "185.220.101.34": {
                "ioc":       "185.220.101.34",
                "ioc_type":  "ip",
                "verdict":   "malicious",
                "escalate":  True,
                "abuseipdb": {
                    "provider": "abuseipdb", "status": "found",
                    "abuse_confidence_score": 94, "total_reports": 512,
                    "country_code": "DE", "is_tor": True,
                },
            },
            "https://cdn-update.cloud/gate.php": {
                "ioc":       "https://cdn-update.cloud/gate.php",
                "ioc_type":  "url",
                "verdict":   "malicious",
                "escalate":  True,
                "virustotal": {"malicious_engines": 12, "suspicious_engines": 1},
            },
        },
        "ioc_summary": {"malicious": 3, "suspicious": 0, "clean": 0, "unknown": 0},
        "escalation_triggers": [],
        "escalation_fired": True,
        "telemetry": {
            "process_events": {"status": "ok", "rows": 42, "sample": []},
            "network_events": {"status": "ok", "rows": 8,  "sample": []},
        },
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path

    result = generate_trinity_report(
        incident_id="847",
        timespan="P7D",
        investigate_data=_demo_investigate_data(),
        checklist_data=_demo_checklist_data(),
    )

    if not result.get("ok"):
        print(f"FAIL: {result.get('error')}", file=sys.stderr)
        sys.exit(1)

    html = result["data"]["html"]
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("trinity_demo.html")
    out_path.write_text(html, encoding="utf-8")
    print(f"OK — report written to {out_path}")
    print(f"     bytes: {len(html):,}")
    print(f"     agents: {list(result['data']['agents'].keys())}")
    print(f"     POC simulated fields flagged: {result['data']['poc_simulated']}")
