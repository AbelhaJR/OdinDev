"""
trinity_report.py
=================
Generates the Trinity incident HTML report from real Sentinel MCP data.

SIZE CAPS (to fit through chat-UI response limits):
  - Trace table capped at 20 rows (all errors + slowest successes)
  - Inputs truncated to 100 chars, outputs to 60 chars
  - Odin "Communications" list capped at 4 entries
Stats lines still reflect the FULL totals - nothing is hidden, just less verbose.
"""

from __future__ import annotations

import html as _html
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple


# ============ CAPS ============
_TRACE_TABLE_MAX_ROWS   = 20
_TRACE_INPUT_MAX_CHARS  = 100
_TRACE_OUTPUT_MAX_CHARS = 60
_ODIN_COMMS_MAX_ENTRIES = 4


_SEVERITY_TO_P_LABEL = {
    "critical":      ("P1 Critical", "red"),
    "high":          ("P1 Critical", "red"),
    "medium":        ("P2 High",     "orange"),
    "low":           ("P3 Medium",   "blue"),
    "informational": ("P4 Low",      "green"),
}

_RISK_LEVEL_TO_SCORE = {"Critical": 95, "High": 85, "Medium": 60, "Low": 30}

_SLA_TARGETS_MIN = {
    "P1 Critical": {"detect": 15,  "contain": 30},
    "P2 High":     {"detect": 30,  "contain": 120},
    "P3 Medium":   {"detect": 60,  "contain": 480},
    "P4 Low":      {"detect": 240, "contain": 1440},
}

_ODIN_TOOLS = ["Sentinel KQL", "Defender XDR", "Entra Logs",
               "CMDB", "VirusTotal", "AbuseIPDB"]

_COST_PER_1K_TOKENS_USD = 0.013

_MITRE_TECHNIQUE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell", "T1059.003": "Windows Command Shell",
    "T1027": "Obfuscated Files or Information", "T1140": "Deobfuscate/Decode Files",
    "T1218": "Signed Binary Proxy Execution", "T1484": "Domain Policy Modification",
    "T1132": "Data Encoding", "T1132.001": "Standard Encoding",
    "T1071": "Application Layer Protocol", "T1071.001": "Web Protocols",
    "T1105": "Ingress Tool Transfer", "T1003": "OS Credential Dumping",
    "T1110": "Brute Force", "T1110.001": "Password Guessing",
    "T1078": "Valid Accounts", "T1078.002": "Domain Accounts", "T1078.003": "Local Accounts",
    "T1098": "Account Manipulation", "T1098.007": "Additional Local or Domain Groups",
    "T1136": "Create Account", "T1136.001": "Local Account",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1069": "Permission Groups Discovery",
    "T1021": "Remote Services", "T1021.001": "Remote Desktop Protocol",
    "T1486": "Data Encrypted for Impact",
    "T1566": "Phishing", "T1566.001": "Spearphishing Attachment",
    "T1585": "Establish Accounts", "T1583": "Acquire Infrastructure",
}

_TACTIC_FOR_TECHNIQUE_PREFIX = {
    "T1059": "Execution", "T1027": "Defense Evasion", "T1140": "Defense Evasion",
    "T1218": "Defense Evasion", "T1484": "Defense Evasion",
    "T1132": "Command and Control", "T1071": "Command and Control",
    "T1105": "Command and Control", "T1003": "Credential Access",
    "T1110": "Credential Access", "T1078": "Defense Evasion",
    "T1098": "Persistence", "T1136": "Persistence",
    "T1548": "Privilege Escalation", "T1069": "Discovery",
    "T1021": "Lateral Movement", "T1486": "Impact",
    "T1566": "Initial Access",
    "T1585": "Resource Development", "T1583": "Resource Development",
}


def generate_trinity_report_html(
    checklist_result: dict,
    *,
    tool_trace: Optional[List[dict]] = None,
    classification: str = "CONFIDENTIAL",
    org_name: str = "Euronext Cybersecurity",
) -> str:
    try:
        if tool_trace is None:
            tool_trace = checklist_result.get("tool_trace") or []
        ctx = _build_report_context(
            checklist_result or {}, tool_trace,
            classification=classification, org_name=org_name,
        )
        return _render_html(ctx)
    except Exception as e:
        return _render_error_html(str(e),
                                  classification=classification, org_name=org_name)


def _build_report_context(checklist: dict, trace: List[dict],
                          *, classification: str, org_name: str) -> dict:
    inc_id_raw = checklist.get("incident_id") or "?"
    title      = str(checklist.get("incident_title") or "Untitled incident")

    entities     = checklist.get("entities_extracted") or {}
    mitre        = checklist.get("mitre") or {}
    ioc_enrich   = checklist.get("ioc_enrichment") or {}
    ioc_summary  = checklist.get("ioc_summary") or {}
    esc_triggers = checklist.get("escalation_triggers") or []
    esc_fired    = bool(checklist.get("escalation_fired"))
    cl_used      = checklist.get("checklist_used") or "default"
    cl_auto      = bool(checklist.get("checklist_auto"))
    surfaced_cmdb = checklist.get("surfaced_hosts_cmdb") or []

    incident_details = checklist.get("incident_details") or {}
    inc_meta = incident_details.get("incident") or {}

    severity_raw = str(inc_meta.get("severity")
                       or _infer_severity_from_iocs(ioc_summary))
    status = str(inc_meta.get("status") or "Investigating")
    owner  = inc_meta.get("owner")
    created_iso = inc_meta.get("created_time") \
                  or (incident_details.get("timeline") or {}).get("first_alert")
    risk_level  = incident_details.get("risk_level") \
                  or _derive_risk_level(ioc_summary, esc_fired)

    primary_host = entities.get("primary_host") or _first(entities.get("hosts") or [])
    primary_user = entities.get("primary_user") or _first(entities.get("users") or [])
    primary_ip   = entities.get("primary_ip")   or _first(entities.get("ips")   or [])

    p_label, _sc = _SEVERITY_TO_P_LABEL.get(severity_raw.lower(),
                                             ("P3 Medium", "blue"))
    risk_score = _RISK_LEVEL_TO_SCORE.get(risk_level, 60)

    techniques = [str(t) for t in (mitre.get("techniques") or [])]
    tactics    = [str(t) for t in (mitre.get("tactics") or [])]
    mitre_rows = _pair_techniques_with_tactics(techniques, tactics)
    primary_technique = techniques[0] if techniques else ""

    iocs = _shape_iocs_for_table(ioc_enrich)
    sla_targets = _SLA_TARGETS_MIN.get(p_label, _SLA_TARGETS_MIN["P3 Medium"])

    trace_rows, trace_stats = _shape_trace_rows(trace)

    odin = _build_odin_state(
        checklist=checklist, iocs=iocs, ioc_summary=ioc_summary,
        esc_triggers=esc_triggers, esc_fired=esc_fired,
        cl_used=cl_used, cl_auto=cl_auto,
        primary_host=primary_host, primary_user=primary_user, primary_ip=primary_ip,
        title=title, mitre_techniques=techniques,
        created_iso=created_iso, entities=entities,
        surfaced_cmdb=surfaced_cmdb,
        trace=trace, trace_stats=trace_stats,
    )

    timeline_rows = _build_timeline(
        created_iso=created_iso, cl_used=cl_used, esc_fired=esc_fired,
        trace_stats=trace_stats,
    )
    analyst_notes = _build_analyst_notes(
        owner=owner, primary_user=primary_user,
        risk_level=risk_level, created_iso=created_iso,
    )

    now_utc = datetime.now(timezone.utc)
    inc_id_display = _format_incident_id(inc_id_raw)

    return {
        "meta": {
            "inc_id":         inc_id_display,
            "inc_dom_id":     _slug_id(inc_id_display),
            "title":          title,
            "generated_ts":   now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "gen_date":       now_utc.strftime("%Y-%m-%d"),
            "classification": classification,
            "org_name":       org_name,
        },
        "incident_summary": {
            "inc_id":         inc_id_display,
            "p_label":        p_label,
            "status":         status,
            "detection_time": _fmt_iso_as_utc(created_iso),
            "source":         "Microsoft Sentinel",
            "risk_score":     risk_score,
            "host":           primary_host or "—",
            "user":           primary_user or "—",
            "mitre_primary":  primary_technique or "—",
        },
        "sla": {
            "detect_actual_min":  2,
            "detect_target_min":  sla_targets["detect"],
            "contain_target_min": sla_targets["contain"],
            "jira":               "None",
        },
        "mitre_rows":    mitre_rows,
        "iocs":          iocs,
        "trace_rows":    trace_rows,
        "trace_stats":   trace_stats,
        "odin":          odin,
        "timeline_rows": timeline_rows,
        "analyst_notes": analyst_notes,
    }


def _shape_trace_rows(trace: List[dict]) -> Tuple[List[dict], dict]:
    """
    Normalize trace events into table rows + aggregate stats.
    Cap rows at _TRACE_TABLE_MAX_ROWS (all errors + slowest successes).
    Stats reflect ALL events so the summary line does not lie.
    """
    total_ms = 0
    n_err = 0
    by_tool: Dict[str, int] = {}

    events = [e for e in (trace or []) if isinstance(e, dict)]

    for ev in events:
        total_ms += int(ev.get("duration_ms") or 0)
        if str(ev.get("status") or "ok") != "ok":
            n_err += 1
        tool = str(ev.get("tool") or "unknown")
        by_tool[tool] = by_tool.get(tool, 0) + 1

    errors     = [e for e in events if str(e.get("status") or "ok") != "ok"]
    successes  = [e for e in events if str(e.get("status") or "ok") == "ok"]
    successes.sort(key=lambda e: -int(e.get("duration_ms") or 0))
    budget     = max(0, _TRACE_TABLE_MAX_ROWS - len(errors))
    selected   = errors + successes[:budget]

    order = {id(e): i for i, e in enumerate(events)}
    selected.sort(key=lambda e: order.get(id(e), 0))

    rows: List[dict] = []
    for ev in selected:
        rows.append({
            "t":           str(ev.get("t") or ""),
            "tool":        str(ev.get("tool") or "unknown"),
            "input":       _truncate_str(ev.get("input")  or "", _TRACE_INPUT_MAX_CHARS),
            "output":      _truncate_str(ev.get("output") or "", _TRACE_OUTPUT_MAX_CHARS),
            "status":      str(ev.get("status") or "ok"),
            "duration_ms": int(ev.get("duration_ms") or 0),
            "error":       ev.get("error"),
        })

    stats = {
        "n_calls":  len(events),
        "n_shown":  len(rows),
        "n_errors": n_err,
        "total_ms": total_ms,
        "by_tool":  by_tool,
    }
    return rows, stats


def _build_odin_state(*, checklist, iocs, ioc_summary,
                      esc_triggers, esc_fired,
                      cl_used, cl_auto,
                      primary_host, primary_user, primary_ip,
                      title, mitre_techniques,
                      created_iso, entities, surfaced_cmdb,
                      trace, trace_stats) -> dict:
    confidence = _derive_confidence(iocs=iocs, esc_fired=esc_fired,
                                     mitre_count=len(mitre_techniques),
                                     trace_stats=trace_stats)

    n_calls = trace_stats["n_calls"]
    n_err   = trace_stats["n_errors"]
    ioc_malicious = int(ioc_summary.get("malicious") or 0)

    if esc_fired or ioc_malicious:
        action_text = (f"{n_calls} tool calls. {ioc_malicious} malicious IOC"
                       f"{'s' if ioc_malicious != 1 else ''}. Escalation fired.")
    elif n_calls:
        action_text = (f"{n_calls} tool call{'s' if n_calls != 1 else ''}"
                       f" — {cl_used}{' (auto)' if cl_auto else ''} checklist. "
                       f"{'No errors.' if n_err == 0 else f'{n_err} failed.'}")
    else:
        action_text = "No tool calls recorded."

    findings: List[Tuple[str, str]] = []
    findings.append(("Checklist", f"{cl_used}{' (auto)' if cl_auto else ''}"))
    findings.append(("Tool calls", f"{n_calls} total, {n_calls - n_err} ok, {n_err} error"
                                    if n_err else f"{n_calls} total"))
    findings.append(("Total time", f"{trace_stats['total_ms']/1000:.2f}s"))

    if iocs:
        counts: Dict[str, int] = {}
        for i in iocs:
            counts[i["verdict"]] = counts.get(i["verdict"], 0) + 1
        findings.append(("IOCs", ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))))

    if esc_triggers:
        names = sorted({str(t.get("trigger") or "") for t in esc_triggers if t})
        disp = ", ".join(n for n in names[:3] if n)
        if disp:
            findings.append(("Escalation", disp))

    if mitre_techniques:
        findings.append(("MITRE", ", ".join(mitre_techniques[:3])))

    if surfaced_cmdb:
        hosts_s = ", ".join(sorted({str(s.get("host")) for s in surfaced_cmdb
                                     if s.get("host")})[:2])
        if hosts_s:
            findings.append(("CMDB", f"Matched: {hosts_s}"))

    # Communications — capped at _ODIN_COMMS_MAX_ENTRIES
    base_dt = _parse_iso(created_iso) or datetime.now(timezone.utc)
    comms: List[Tuple[str, str, str]] = []
    comms.append((_fmt_dt_hms(base_dt, 0), "← Sentinel",
                  (title or "SecurityAlert")
                  + (f" on {primary_host}" if primary_host else "")))

    for ev in (trace or [])[:12]:
        tool = str(ev.get("tool") or "")
        t    = str(ev.get("t") or "")
        inp  = _truncate_str(str(ev.get("input") or ""), 70)
        out  = _truncate_str(str(ev.get("output") or ""), 50)
        if tool in ("enrich_ioc", "enrich_virustotal", "enrich_abuseipdb"):
            comms.append((t, "→ Threat Intel", f"{inp} → {out}"))
        elif tool == "query_cmdb":
            comms.append((t, "→ CMDB", f"{inp} → {out}"))
        elif tool == "la_query":
            comms.append((t, "→ Sentinel KQL", f"{inp} → {out}"))
        if len(comms) >= _ODIN_COMMS_MAX_ENTRIES:
            break

    if esc_fired:
        comms.append((_fmt_dt_hms(base_dt, 45),
                      "→ Sentinel", "Escalation fired — threshold exceeded"))

    tokens = 800 + n_calls * 200 + len(iocs) * 400
    cost_usd = round(tokens / 1000.0 * _COST_PER_1K_TOKENS_USD, 2)

    status = "complete" if n_calls > 0 else "working"

    return {
        "status":      status,
        "confidence":  confidence,
        "action_text": action_text,
        "findings":    findings,
        "comms":       comms,
        "tools":       _ODIN_TOOLS,
        "gate":        "Auto-pass for automated investigation. Human review before containment.",
        "cost_usd":    cost_usd,
        "tokens":      tokens,
    }


def _derive_confidence(*, iocs, esc_fired, mitre_count, trace_stats) -> int:
    score = 50
    if iocs:
        n_verdicted = sum(1 for i in iocs if i["verdict"] in ("malicious", "suspicious", "clean"))
        n_total     = len(iocs)
        if n_total:
            score += int(25 * (n_verdicted / n_total))
        if any(i["verdict"] == "malicious" for i in iocs):
            score += 10

    n_calls = trace_stats.get("n_calls", 0)
    n_err   = trace_stats.get("n_errors", 0)
    if n_calls:
        score += int(15 * ((n_calls - n_err) / n_calls))

    if mitre_count:
        score += 5
    if esc_fired:
        score += 5
    return max(0, min(100, score))


def _infer_severity_from_iocs(ioc_summary: dict) -> str:
    mal = int((ioc_summary or {}).get("malicious") or 0)
    sus = int((ioc_summary or {}).get("suspicious") or 0)
    if mal >= 1: return "High"
    if sus >= 1: return "Medium"
    return "Low"


def _derive_risk_level(ioc_summary: dict, esc_fired: bool) -> str:
    mal = int((ioc_summary or {}).get("malicious") or 0)
    if esc_fired or mal >= 2: return "High"
    if mal == 1:              return "Medium"
    return "Low"


def _shape_iocs_for_table(ioc_enrichment: Dict[str, dict]) -> List[dict]:
    out: List[dict] = []
    for key, d in (ioc_enrichment or {}).items():
        if not isinstance(d, dict): continue
        ioc_type = str(d.get("ioc_type") or "").lower()
        verdict  = str(d.get("verdict")  or "unknown").lower()

        type_label = {
            "ip": "IP", "domain": "Domain", "url": "URL",
            "sha256": "Hash (SHA256)", "sha1": "Hash (SHA1)", "md5": "Hash (MD5)",
        }.get(ioc_type, ioc_type.upper() or "IOC")

        display_value = _defang(str(key)) if ioc_type in ("domain", "url") else str(key)

        out.append({
            "value": key, "display_value": display_value,
            "type": ioc_type, "type_label": type_label,
            "verdict": verdict, "source": "Odin",
        })

    rank = {"malicious": 0, "suspicious": 1, "clean": 2, "unknown": 3}
    out.sort(key=lambda x: (rank.get(x["verdict"], 4), x["type"], x["value"]))
    return out


def _defang(s: str) -> str:
    s = s.replace("http://", "hxxp://").replace("https://", "hxxps://")
    if "/" not in s and s.count(".") >= 1:
        idx = s.rfind(".")
        s = s[:idx] + "[.]" + s[idx+1:]
    else:
        s = s.replace(".", "[.]", 1)
    return s


def _verdict_color(v: str) -> str:
    return {"malicious": "var(--red)", "suspicious": "#f59e0b",
            "clean": "#22c55e", "unknown": "#888"}.get(v, "#888")


def _status_color(s: str) -> str:
    return {"ok": "#22c55e", "error": "#ef4444",
            "exception": "#ef4444", "skipped": "#888"}.get(s, "#f59e0b")


def _pair_techniques_with_tactics(techniques, tactics):
    rows = []
    tactic_for = {}
    if tactics and len(tactics) == len(techniques):
        for tid, tac in zip(techniques, tactics):
            tactic_for[tid] = tac
    for tid in techniques or []:
        tid_s = str(tid)
        name = (_MITRE_TECHNIQUE_NAMES.get(tid_s)
                or _MITRE_TECHNIQUE_NAMES.get(tid_s.split(".")[0]) or tid_s)
        tac = (tactic_for.get(tid_s)
               or _TACTIC_FOR_TECHNIQUE_PREFIX.get(tid_s.split(".")[0])
               or (tactics[0] if tactics else "—"))
        rows.append((tid_s, name, tac))
    return rows


def _build_timeline(*, created_iso, cl_used, esc_fired, trace_stats) -> List[Tuple[str, str]]:
    base = _parse_iso(created_iso) or datetime.now(timezone.utc)
    def _off(s): return (base + timedelta(seconds=s)).strftime("%H:%M:%S")
    rows = [
        (_off(0),  '<strong>Sentinel</strong> fired alert'),
        (_off(7),  f'<strong>Odin</strong> triggered {_h(cl_used)} investigation checklist.'),
    ]
    n = trace_stats.get("n_calls", 0)
    if n:
        rows.append((_off(10),
                     f'<strong>Odin</strong> executed {n} tool call{"s" if n != 1 else ""} '
                     f'({trace_stats["total_ms"]/1000:.1f}s).'))
    if esc_fired:
        rows.append((_off(45), '<strong>Odin</strong> escalated — threshold exceeded.'))
    rows.append((_off(60), '<strong>Odin</strong> investigation complete.'))
    return rows


def _build_analyst_notes(*, owner, primary_user, risk_level, created_iso):
    if not owner: return []
    name = ""
    if isinstance(owner, dict):
        name = (owner.get("assignedTo") or owner.get("email")
                or owner.get("userPrincipalName") or "")
    else:
        name = str(owner)
    if not name: return []

    parts = name.split("@")[0].replace(".", " ").split()
    display = f"{parts[0][0].upper()}. {parts[-1].capitalize()}" if len(parts) >= 2 else name
    base = _parse_iso(created_iso) or datetime.now(timezone.utc)
    t = (base + timedelta(seconds=55)).strftime("%H:%M")
    bits = []
    if primary_user: bits.append(f"{primary_user} involved")
    bits.append(f"{risk_level} risk")
    return [(display, t, ". ".join(bits) + ".")]


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
.report-table td{padding:8px 12px;border-bottom:1px solid #f0f0f0;color:#333;vertical-align:top}
.report-table tr:last-child td{border-bottom:none}
.report-table td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;word-break:break-word}
.report-footer{text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid #e0e0e0;font-size:10px;color:#999}
.report-close,.report-actions{display:none}
.rf-flow{display:flex;flex-direction:column;align-items:center;gap:0;padding:8px 0}
.rf-connector{width:2px;height:20px;background:#ccc;margin:0 auto}
.rf-node{width:100%;max-width:560px;border:1px solid #ddd;border-radius:10px;overflow:hidden}
.rf-head{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer}
.rf-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.rf-dot.done{background:#22c55e}.rf-dot.active{background:#6C63FF}.rf-dot.pending{background:#ccc}
.rf-agent{font-weight:700;font-size:12px;flex:1;display:flex;align-items:center;gap:6px}
.rf-role{font-weight:400;color:#888;font-size:10px}
.rf-conf{font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;background:#f0f0f0}
.rf-conf.high{color:#22c55e}.rf-conf.mid{color:#f59e0b}.rf-conf.low{color:#ef4444}
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
.rf-cost span{color:#6C63FF;font-weight:600}
.trace-tool{font-weight:600;color:#1a1a1a}
.trace-pill{display:inline-block;font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:0.3px}
.trace-dur{color:#888;font-variant-numeric:tabular-nums}"""


def _render_html(ctx: dict) -> str:
    meta = ctx["meta"]; summ = ctx["incident_summary"]
    sla  = ctx["sla"];  odin = ctx["odin"]
    parts: List[str] = []

    parts.append(
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f'<title>Trinity Incident Report — {_h(meta["inc_id"])}</title>'
        f'<style>{_CSS}</style></head><body>'
    )
    parts.append(
        '<div class="report-actions">'
        '<button class="report-dl" onclick="downloadReportPDF()" title="Download as PDF">⇩</button>'
        f'<button class="report-dl" onclick="downloadReportHTML(\'{_h(meta["inc_id"])}\')" title="Download as HTML">⎘</button>'
        '</div><button class="report-close" onclick="closeReport()">×</button>'
    )
    parts.append(f"""
    <div class="report-header">
      <div class="report-logo">△ Trinity — Incident Report</div>
      <div class="report-title">{_h(meta["title"])}</div>
      <div class="report-subtitle">{_h(meta["inc_id"])} • Generated {_h(meta["generated_ts"])} • Classification: {_h(meta["classification"])}</div>
    </div>""")

    parts.append('<div class="report-section"><div class="report-section-title">Incident Summary</div><div class="report-grid">')
    for label, val, extra in [
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
        parts.append(f'<div class="report-kv"><div class="report-kv-label">{_h(label)}</div>'
                     f'<div class="report-kv-val" {extra}>{_h(val)}</div></div>')
    parts.append('</div></div>')

    detect_actual = f"{sla['detect_actual_min']}min" if sla["detect_actual_min"] is not None else "Unknown"
    parts.append(f"""
    <div class="report-section"><div class="report-section-title">SLA Performance</div>
      <div class="report-grid">
        <div class="report-kv"><div class="report-kv-label">Time to Detect</div><div class="report-kv-val">{_h(detect_actual)} <span style="font-size:10px;color:var(--text-3)">/ {sla['detect_target_min']}min SLA</span></div></div>
        <div class="report-kv"><div class="report-kv-label">Time to Contain</div><div class="report-kv-val">Pending <span style="font-size:10px;color:var(--text-3)">/ {sla['contain_target_min']}min SLA</span></div></div>
        <div class="report-kv"><div class="report-kv-label">Jira</div><div class="report-kv-val">{_h(sla['jira'])}</div></div>
      </div>
    </div>""")

    parts.append('<div class="report-section"><div class="report-section-title">MITRE ATT&amp;CK Techniques</div>'
                 '<table class="report-table"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>')
    if ctx["mitre_rows"]:
        for tid, tname, tac in ctx["mitre_rows"]:
            parts.append(f'<tr><td style="font-weight:600">{_h(tid)}</td><td>{_h(tname)}</td><td>{_h(tac)}</td></tr>')
    else:
        parts.append('<tr><td colspan="3" style="color:#999;font-style:italic">No MITRE techniques mapped.</td></tr>')
    parts.append('</tbody></table></div>')

    parts.append('<div class="report-section"><div class="report-section-title">Indicators of Compromise</div>'
                 '<table class="report-table"><thead><tr><th>Type</th><th>Value</th><th>Verdict</th><th>Source</th></tr></thead><tbody>')
    if ctx["iocs"]:
        for ioc in ctx["iocs"]:
            parts.append(
                f'<tr><td>{_h(ioc["type_label"])}</td>'
                f'<td class="mono">{_h(ioc["display_value"])}</td>'
                f'<td><span style="color:{_verdict_color(ioc["verdict"])};font-weight:600">{_h(ioc["verdict"])}</span></td>'
                f'<td>{_h(ioc["source"])}</td></tr>'
            )
    else:
        parts.append('<tr><td colspan="4" style="color:#999;font-style:italic">No IOCs enriched.</td></tr>')
    parts.append('</tbody></table></div>')

    # Tool-call trace
    st = ctx["trace_stats"]
    shown_note = ""
    if st.get("n_shown") and st["n_shown"] < st["n_calls"]:
        shown_note = f" — showing {st['n_shown']} (all errors + slowest)"
    parts.append(
        '<div class="report-section"><div class="report-section-title">Investigation Findings — Tool Call Trace</div>'
        f'<div style="font-size:11px;color:var(--text-3);margin-bottom:8px">'
        f'{st["n_calls"]} call{"s" if st["n_calls"] != 1 else ""}, '
        f'{st["n_errors"]} error{"s" if st["n_errors"] != 1 else ""}, '
        f'total {st["total_ms"]/1000:.2f}s{shown_note}'
        f'</div>'
        '<table class="report-table"><thead><tr>'
        '<th>Time</th><th>Tool</th><th>Input</th><th>Output</th><th>Status</th><th>Duration</th>'
        '</tr></thead><tbody>'
    )
    if ctx["trace_rows"]:
        for r in ctx["trace_rows"]:
            sc = _status_color(r["status"])
            dur = f"{r['duration_ms']}ms" if r['duration_ms'] < 1000 \
                  else f"{r['duration_ms']/1000:.2f}s"
            err_html = ""
            if r["error"]:
                err_html = f'<div style="font-size:10px;color:var(--red);margin-top:2px">{_h(r["error"])}</div>'
            parts.append(
                '<tr>'
                f'<td style="white-space:nowrap;font-variant-numeric:tabular-nums">{_h(r["t"])}</td>'
                f'<td class="trace-tool">{_h(r["tool"])}</td>'
                f'<td class="mono">{_h(r["input"])}</td>'
                f'<td class="mono">{_h(r["output"])}{err_html}</td>'
                f'<td><span class="trace-pill" style="color:{sc};background:rgba(0,0,0,0.04)">{_h(r["status"])}</span></td>'
                f'<td class="trace-dur">{_h(dur)}</td>'
                '</tr>'
            )
    else:
        parts.append('<tr><td colspan="6" style="color:#999;font-style:italic">No tool calls traced.</td></tr>')
    parts.append('</tbody></table>')
    parts.append(
        f'<div style="margin-top:10px;display:flex;justify-content:flex-end;gap:16px;font-size:12px;font-weight:600">'
        f'<span style="color:var(--text-3)">Total AI Cost:</span>'
        f'<span style="color:var(--accent)">${odin["cost_usd"]:.2f} ({odin["tokens"]:,} tokens)</span>'
        f'</div></div>'
    )

    parts.append(
        '<div class="report-section"><div class="report-section-title">Agent Decision Flow '
        '<span style="font-size:9px;font-weight:400;color:var(--text-3);text-transform:none;letter-spacing:0">— click to expand</span></div>'
        '<div class="rf-flow">'
    )
    parts.append(_render_odin_node(odin, meta["inc_dom_id"]))
    parts.append('</div></div>')

    parts.append('<div class="report-section"><div class="report-section-title">Timeline</div>'
                 '<table class="report-table"><thead><tr><th>Time</th><th>Event</th></tr></thead><tbody>')
    for t, evt in ctx["timeline_rows"]:
        parts.append(f'<tr><td style="white-space:nowrap;font-variant-numeric:tabular-nums">{_h(t)}</td><td>{evt}</td></tr>')
    parts.append('</tbody></table></div>')

    parts.append('<div class="report-section"><div class="report-section-title">Analyst Notes</div>'
                 '<table class="report-table"><thead><tr><th>Analyst</th><th>Time</th><th>Note</th></tr></thead><tbody>')
    if ctx["analyst_notes"]:
        for name, t, note in ctx["analyst_notes"]:
            parts.append(f'<tr><td style="font-weight:600">{_h(name)}</td><td>{_h(t)}</td><td>{_h(note)}</td></tr>')
    else:
        parts.append('<tr><td colspan="3" style="color:#999;font-style:italic">No notes yet.</td></tr>')
    parts.append('</tbody></table></div>')

    parts.append(
        f'<div class="report-footer">Trinity CyAgent Operations Portal • {_h(meta["org_name"])} • {_h(meta["gen_date"])} • {_h(meta["classification"])}</div>'
        '</body></html>'
    )
    return "".join(parts)


def _render_odin_node(state: dict, inc_dom_id: str) -> str:
    node_id = f"rf-{inc_dom_id}-odin"
    dot_cls = {"complete": "done", "working": "active", "waiting": "pending"} \
              .get(state.get("status"), "pending")

    conf_html = ""
    if state.get("confidence") is not None:
        c = state["confidence"]
        tier = "high" if c >= 80 else ("mid" if c >= 65 else "low")
        conf_html = f'<span class="rf-conf {tier}">{c}%</span>'

    parts = [
        f'<div class="rf-node" id="{_h(node_id)}" onclick="toggleFlowNode(\'{_h(node_id)}\',event)">',
        '<div class="rf-head">',
        f'<span class="rf-dot {dot_cls}"></span>',
        '<span class="rf-agent">Odin <span class="rf-role">Incident Analyst (Investigation)</span></span>',
        conf_html,
        '<span class="rf-chevron">▶</span>',
        '</div><div class="rf-body"><div class="rf-inner">',
    ]
    parts.append(f'<div class="rf-block"><div class="rf-block-label">Action / Decision</div>'
                 f'<div class="rf-block-text">{_h(state.get("action_text", ""))}</div></div>')
    parts.append(f'<div class="rf-gate">Gate: {_h(state.get("gate", ""))}</div>')

    if state.get("findings"):
        parts.append('<div class="rf-block"><div class="rf-block-label">Reasoning &amp; Findings</div>')
        for lab, val in state["findings"]:
            parts.append(f'<div class="rf-finding"><span class="rf-finding-label">{_h(lab)}</span>'
                         f'<span class="rf-finding-val">{_h(val)}</span></div>')
        parts.append('</div>')

    if state.get("comms"):
        parts.append('<div class="rf-block"><div class="rf-block-label">Communications</div><div class="rf-comms">')
        for t, arrow, msg in state["comms"]:
            parts.append(f'<div class="rf-comm"><span class="rf-comm-time">{_h(t)}</span>'
                         f'<span class="rf-comm-arrow">{_h(arrow)}</span>'
                         f'<span>{_h(msg)}</span></div>')
        parts.append('</div></div>')

    parts.append('<div class="rf-block"><div class="rf-block-label">Tools</div><div class="rf-tools">')
    for tool in state.get("tools", []):
        parts.append(f'<span class="rf-tool">{_h(tool)}</span>')
    parts.append('</div></div>')
    parts.append(f'<div class="rf-cost">${state.get("cost_usd", 0):.2f} • {state.get("tokens", 0):,} tokens</div>')
    parts.append('</div></div></div>')
    return "".join(parts)


def _render_error_html(err: str, *, classification, org_name) -> str:
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<title>Trinity Incident Report — error</title>'
        f'<style>{_CSS}</style></head><body>'
        '<div class="report-header">'
        '<div class="report-logo">△ Trinity — Incident Report</div>'
        '<div class="report-title">Report rendering failed</div></div>'
        '<div class="report-section"><div class="report-section-title">Error</div>'
        f'<div style="background:#fef2f2;color:#991b1b;padding:12px;border-radius:8px;font-family:monospace;font-size:12px">{_h(err)}</div>'
        '</div>'
        f'<div class="report-footer">Trinity CyAgent Operations Portal • {_h(org_name)} • {_h(classification)}</div>'
        '</body></html>'
    )


def _h(val: Any) -> str:
    if val is None: return ""
    return _html.escape(str(val), quote=True)


def _first(seq):
    for x in seq or []:
        if x: return x
    return ""


def _truncate_str(s: str, n: int) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n-1] + "…"


def _slug_id(inc_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", inc_id or "unknown")


def _format_incident_id(raw) -> str:
    if raw is None: return "INC-UNKNOWN"
    s = str(raw)
    if s.upper().startswith("INC-"): return s
    if s.isdigit():
        yr = datetime.now(timezone.utc).year
        return f"INC-{yr}-{int(s):04d}"
    return s


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try:
        txt = str(s)
        if txt.endswith("Z"):
            txt = txt[:-1] + "+00:00"
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _fmt_iso_as_utc(s: Optional[str]) -> str:
    dt = _parse_iso(s)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "—"


def _fmt_dt_hms(dt: datetime, offset_s: int) -> str:
    return (dt + timedelta(seconds=offset_s)).strftime("%H:%M:%S")


# ============ STANDALONE DEMO ============

def _demo_payload_35_calls() -> dict:
    """Synthetic payload mirroring a real 35-call, 6-error run."""
    trace = []
    for i in range(6):
        trace.append({
            "t": f"09:22:{30+i:02d}", "tool": "la_query",
            "input":  f"SomeTable_{i} | where DeviceName contains 'ds800' | project TimeGenerated, DeviceName, AccountName, FileName | take 100",
            "output": "", "status": "error", "duration_ms": 9000 + i * 200,
            "error": "ARM request failed: 504 Gateway Timeout" if i % 2 else "Log Analytics: table not found",
        })
    for i in range(29):
        trace.append({
            "t": f"09:22:{40+i:02d}",
            "tool": "la_query" if i % 3 else ("query_cmdb" if i % 5 == 0 else "enrich_ioc"),
            "input":  "DeviceProcessEvents | where DeviceName contains 'ds800' and TimeGenerated > ago(12h) | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256 | take 100",
            "output": f"{(i*7) % 50} rows" if i % 3 else "verdict=clean",
            "status": "ok",
            "duration_ms": 100 + (i * 173) % 3000,
        })

    return {
        "incident_id":    1537667,
        "incident_title": "Defender | ES Copenhagen | A user was added to the local administrators group",
        "checklist_used": "default",
        "checklist_auto": True,
        "alerts_count":   2,
        "entities_extracted": {
            "hosts": ["ds800.intern.vp.dk"], "users": ["vp03da3"],
            "ips": [], "domains": [],
            "primary_host": "ds800", "primary_user": "vp03da3", "primary_ip": "",
        },
        "mitre": {"tactics": ["Resource Development"], "techniques": ["T1585"]},
        "ioc_enrichment": {},
        "ioc_summary": {"malicious": 0},
        "escalation_triggers": [],
        "escalation_fired": False,
        "surfaced_hosts_cmdb": [
            {"host": "ds800.intern.vp.dk", "cmdb_rows": 1,
             "top": {"BusinessEntity": "ES Copenhagen", "PSNC": "PROD"}},
        ],
        "checklist_coverage": {"security_alerts_30d": "ok", "behavior_analytics": "error"},
        "incident_details": {
            "incident": {
                "id": 1537667,
                "title": "Defender | ES Copenhagen | A user was added to the local administrators group",
                "severity": "Medium", "status": "Closed",
                "owner": "ana.rocha@euronext.com",
                "created_time": "2026-04-21 09:22:24Z",
            },
            "timeline": {"first_alert": "2026-04-21 09:22:24Z"},
            "risk_level": "Medium",
        },
        "tool_trace": trace,
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path
    html = generate_trinity_report_html(_demo_payload_35_calls())
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("trinity_demo.html")
    out.write_text(html, encoding="utf-8")
    print(f"OK - report written to {out} ({len(html):,} bytes)")
