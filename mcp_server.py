from fastmcp import FastMCP
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os
import re
import json
import urllib.request
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Any, Dict, List, Optional, Tuple

# ============================================================
# MCP SETUP
# ============================================================

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger("SentinelMCP")

# ── HTTP session with automatic retry on transient errors ──────────────────
# Retries on 429 (throttle), 500, 502, 503, 504 with exponential backoff.
# backoff_factor=1 → waits 1s, 2s, 4s between attempts.
# Respects Retry-After headers automatically when status_forcelist includes 429.
_RETRY_POLICY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
    raise_on_status=False,
)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SentinelMCP/1.0"})
SESSION.mount("https://", HTTPAdapter(max_retries=_RETRY_POLICY))

mcp = FastMCP("SentinelMCP")

# ============================================================
# PATHS / CATALOG
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TABLE_CATALOG_PATH = os.path.join(BASE_DIR, "workspace_tables.json")

WORKSPACE_TABLE_CATALOG: Dict[str, List[str]] = {}
_CATALOG_LOADED = False
_CATALOG_LOCK = threading.Lock()

def _ensure_catalog_loaded() -> None:
    """Lazy-load the workspace table catalog on first use.
    Safe to call multiple times — loads only once (double-checked locking).
    """
    global WORKSPACE_TABLE_CATALOG, _CATALOG_LOADED
    if _CATALOG_LOADED:
        return
    with _CATALOG_LOCK:
        if _CATALOG_LOADED:          # re-check inside lock
            return
        try:
            with open(TABLE_CATALOG_PATH, "r", encoding="utf-8") as f:
                raw_catalog = json.load(f)
                if isinstance(raw_catalog, dict):
                    WORKSPACE_TABLE_CATALOG = {
                        str(k): [str(v) for v in vals if isinstance(v, str)]
                        for k, vals in raw_catalog.items()
                        if isinstance(vals, list)
                    }
                else:
                    logger.warning("Workspace catalog is not a JSON object")
        except Exception as e:
            logger.error("Failed to load workspace catalog: %s", e)
            WORKSPACE_TABLE_CATALOG = {}
        _CATALOG_LOADED = True

# ============================================================
# CONFIGURATION
# ============================================================

SUBSCRIPTION_ID = os.environ.get("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.environ.get("RESOURCE_GROUP")
WORKSPACE_NAME = os.environ.get("WORKSPACE_NAME")
WORKSPACE_ID = os.environ.get("WORKSPACE_ID")

LOG_ANALYTICS_RESOURCE = "https://api.loganalytics.io/"
ARM_RESOURCE = "https://management.azure.com/"
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"

MAX_ROWS_HARD = 200
DEFAULT_ROWS = 50

DEFAULT_TIMESPAN = os.environ.get("DEFAULT_TIMESPAN", "P3D")
HTTP_TIMEOUT_SECONDS = int(os.environ.get("LA_HTTP_TIMEOUT", "15"))

# Wall-clock cap (seconds) for parallel fan-out queries in analyze_entity /
# investigate_incident.  Individual per-request timeout is HTTP_TIMEOUT_SECONDS.
PARALLEL_WALL_CLOCK_TIMEOUT = int(os.environ.get("PARALLEL_WALL_CLOCK_TIMEOUT", "30"))

MAX_HOURS_RUN_QUERY = 72
MAX_HOURS_ANALYZE_ENTITY = 168
MAX_HOURS_INCIDENT = 168

# ============================================================
# RESPONSE HELPERS
# ============================================================

def _ok(data: Any, **meta) -> dict:
    out = {"ok": True, "data": data}
    if meta:
        out["meta"] = meta
    return out

def _fail(
    message: str,
    *,
    code: Optional[str] = None,
    status_code: Optional[int] = None,
    detail: Optional[str] = None,
    **meta,
) -> dict:
    out = {"ok": False, "error": {"message": message}}
    if code:
        out["error"]["code"] = code
    if status_code is not None:
        out["error"]["status_code"] = status_code
    if detail:
        out["error"]["detail"] = detail
    if meta:
        out["meta"] = meta
    return out

# ============================================================
# TOOL INVENTORY
# ============================================================

_TOOL_DEFS: List[dict] = []

def _register_tool_def(name: str, description: str, params: dict) -> None:
    _TOOL_DEFS.append({"name": name, "description": description, "params": params})

# ============================================================
# MANAGED IDENTITY  (thread-safe token cache)
# ============================================================

_TOKEN_CACHE: Dict[str, Dict[str, Any]] = {}
_TOKEN_CACHE_LOCK = threading.Lock()

def get_managed_identity_token(resource: str) -> str:
    now = int(time.time())

    with _TOKEN_CACHE_LOCK:
        cached = _TOKEN_CACHE.get(resource)
        if cached and cached.get("exp", 0) - now > 60:
            return cached["token"]

    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT") or os.environ.get("MSI_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER") or os.environ.get("MSI_SECRET")
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")

    # App Service / Function App managed identity endpoint
    if identity_endpoint and identity_header:
        sep = "&" if "?" in identity_endpoint else "?"
        extra = f"&client_id={client_id}" if client_id else ""
        url = f"{identity_endpoint}{sep}resource={resource}&api-version=2019-08-01{extra}"

        req = urllib.request.Request(
            url,
            headers={"X-IDENTITY-HEADER": identity_header, "Metadata": "true"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode())
            token = payload["access_token"]
            expires_in = int(payload.get("expires_in") or 300)
            with _TOKEN_CACHE_LOCK:
                _TOKEN_CACHE[resource] = {"token": token, "exp": now + expires_in}
            return token

    # Fallback: IMDS (VM / container)
    extra = f"&client_id={client_id}" if client_id else ""
    url = f"{IMDS_ENDPOINT}?api-version=2018-02-01&resource={resource}{extra}"
    req = urllib.request.Request(url, headers={"Metadata": "true"}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode())
        token = payload["access_token"]
        expires_in = int(payload.get("expires_in") or 300)
        with _TOKEN_CACHE_LOCK:
            _TOKEN_CACHE[resource] = {"token": token, "exp": now + expires_in}
        return token

# ============================================================
# GUARDRAILS / HELPERS
# ============================================================

_TABLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

def parse_timespan_to_hours(timespan: str) -> float:
    """
    Supports: PT#H, PT#M, PT#H#M, P#D
    """
    ts = (timespan or "").strip()

    m = re.fullmatch(r"PT(?:(\d+)H)?(?:(\d+)M)?", ts)
    if m:
        h = int(m.group(1) or 0)
        mins = int(m.group(2) or 0)
        total = h + mins / 60.0
        if total <= 0:
            raise ValueError("Timespan must be > 0")
        return total

    d = re.fullmatch(r"P(\d+)D", ts)
    if d:
        days = int(d.group(1))
        if days <= 0:
            raise ValueError("Timespan must be > 0")
        return days * 24.0

    raise ValueError("Invalid timespan format. Use PT1H, PT6H, PT24H or P1D, P7D.")

def clamp_rows(n: Any) -> int:
    try:
        v = int(n)
    except Exception:
        v = DEFAULT_ROWS
    return max(1, min(v, MAX_ROWS_HARD))

def escape_kql_string(s: str) -> str:
    return (s or "").replace('"', '""')

def validate_table_name(table: str) -> str:
    if not table or not isinstance(table, str):
        raise ValueError("Table name is required")
    table = table.strip()
    if not _TABLE_RE.fullmatch(table):
        raise ValueError("Invalid table name")
    return table

def kql_safety_check(kql: str):
    lowered = (kql or "").lower().strip()

    if not lowered:
        raise ValueError("KQL cannot be empty")

    if ";" in lowered:
        raise ValueError("Multiple KQL statements are not allowed")

    if re.fullmatch(r"\s*search\s+\*\s*", lowered):
        raise ValueError("KQL too broad: 'search *' not allowed")

    if re.search(r"\bunion\s+\*\b", lowered):
        raise ValueError("KQL too broad: 'union *' not allowed")

    blocked = [
        "externaldata", "evaluate", "make-series",
        ".drop", ".delete", ".alter", ".create",
        ".ingest", ".clear", ".set", ".append",
    ]
    for op in blocked:
        if op in lowered:
            raise ValueError(f"KQL contains blocked operator: {op}")

def _run_query_requires_reasonable_scope(kql: str) -> None:
    lowered = (kql or "").lower()
    if " where " not in f" {lowered} ":
        raise ValueError("Query must include at least one where clause")

def ensure_take_limit(kql: str, limit: int) -> str:
    lowered = (kql or "").lower()
    if "| take" in lowered or "| limit" in lowered:
        return kql
    return f"{kql}\n| take {limit}"

def detect_entity_type(value: str) -> str:
    v = (value or "").strip()

    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        try:
            parts = [int(x) for x in v.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return "ip"
        except Exception:
            pass

    if "@" in v:
        return "user"

    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"

    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"

    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"

    if "." in v:
        return "domain"

    return "host"

def _la_first_table_rows(payload: dict) -> Tuple[List[str], List[List[Any]]]:
    tables = payload.get("tables") or []
    if not tables:
        return [], []
    t0 = tables[0]
    columns = [c.get("name") for c in (t0.get("columns") or [])]
    rows = t0.get("rows") or []
    return columns, rows

def _la_first_table_dicts(payload: dict) -> List[dict]:
    columns, rows = _la_first_table_rows(payload)
    return [dict(zip(columns, r)) for r in rows]

def _flatten_catalog_tables() -> List[str]:
    _ensure_catalog_loaded()
    seen = set()
    out = []
    for tables in WORKSPACE_TABLE_CATALOG.values():
        for t in tables:
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out

def _catalog_domains_for_entity(entity_type: str) -> List[str]:
    mapping = {
        "ip": [
            "alerts_and_incidents",
            "identity_and_authentication",
            "endpoint_microsoft_defender",
            "network_security_devices",
            "network_and_proxy",
            "cmdb_and_asset_context",
        ],
        "user": [
            "alerts_and_incidents",
            "identity_and_authentication",
            "endpoint_microsoft_defender",
            "email_and_m365",
            "identity_governance_and_pam",
        ],
        "host": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "windows_servers",
            "linux_servers",
            "cmdb_and_asset_context",
        ],
        "domain": [
            "alerts_and_incidents",
            "network_and_proxy",
            "dns_and_ip_management",
            "email_and_m365",
        ],
        "sha256": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "security_and_behavior_analytics",
        ],
        "sha1": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "security_and_behavior_analytics",
        ],
        "md5": [
            "alerts_and_incidents",
            "endpoint_microsoft_defender",
            "security_and_behavior_analytics",
        ],
    }
    preferred = mapping.get(entity_type, ["alerts_and_incidents", "identity_and_authentication"])
    _ensure_catalog_loaded()
    return [d for d in preferred if d in WORKSPACE_TABLE_CATALOG]

def _catalog_tables_for_domains(domains: List[str]) -> List[str]:
    _ensure_catalog_loaded()
    seen = set()
    out = []
    for domain in domains:
        for table in WORKSPACE_TABLE_CATALOG.get(domain, []):
            if table not in seen:
                seen.add(table)
                out.append(table)
    return out

CMDB_TABLE = "COVERAGE_CMDB"

def _query_cmdb_entity(value: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    safe_value = escape_kql_string(value)

    structured_kql = f"""
{CMDB_TABLE}
| where
    tostring(Key) contains "{safe_value}"
    or tostring(Management_IP) contains "{safe_value}"
    or tostring(ApplicationAndComponentInstance) contains "{safe_value}"
    or tostring(Network_Interfaces) contains "{safe_value}"
    or tostring(BusinessEntity) contains "{safe_value}"
    or tostring(FQDN) contains "{safe_value}"
    or tostring(PSNC) contains "{safe_value}"
    or tostring(Scanning_Information) contains "{safe_value}"
    or tostring(logsource) contains "{safe_value}"
| project
    Key, Management_IP, ApplicationAndComponentInstance,
    Network_Interfaces, Updated, Scanning_Information,
    BusinessEntity, FQDN, PSNC, logsource
| take 20
""".strip()

    res = la_query(structured_kql, timespan)
    if not res.get("ok"):
        return res

    rows = _la_first_table_dicts(res["data"])
    if rows:
        return res

    fallback_kql = f"""
{CMDB_TABLE}
| where tostring(*) contains "{safe_value}"
| project
    Key, Management_IP, ApplicationAndComponentInstance,
    Network_Interfaces, Updated, Scanning_Information,
    BusinessEntity, FQDN, PSNC, logsource
| take 20
""".strip()

    return la_query(fallback_kql, timespan)

# ============================================================
# LOG ANALYTICS / ARM CLIENTS
# ============================================================

def la_query(kql: str, timespan: str) -> dict:
    if not WORKSPACE_ID:
        return _fail("WORKSPACE_ID not configured on the Function App", code="CONFIG_ERROR")

    try:
        token = get_managed_identity_token(LOG_ANALYTICS_RESOURCE)
    except Exception as e:
        return _fail(
            "Failed to acquire Managed Identity token",
            code="MANAGED_IDENTITY_ERROR",
            detail=str(e),
        )

    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    start = time.time()

    try:
        # SESSION already has the Retry adapter mounted — transient errors are
        # retried automatically with exponential backoff.
        response = SESSION.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"query": kql, "timespan": timespan},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except Exception as e:
        return _fail(
            "HTTP request to Log Analytics failed",
            code="HTTP_ERROR",
            detail=str(e),
            timespan=timespan,
        )

    elapsed_ms = int((time.time() - start) * 1000)

    if not response.ok:
        logger.warning(
            "Log Analytics query failed status=%s duration_ms=%s",
            response.status_code, elapsed_ms,
        )
        return _fail(
            "Log Analytics query failed",
            code="LOG_ANALYTICS_ERROR",
            status_code=response.status_code,
            detail=response.text,
            timespan=timespan,
        )

    try:
        payload = response.json()
        logger.info("Log Analytics query ok duration_ms=%s timespan=%s", elapsed_ms, timespan)
        return _ok(payload, timespan=timespan, duration_ms=elapsed_ms)
    except Exception as e:
        return _fail(
            "Failed to parse Log Analytics JSON response",
            code="PARSE_ERROR",
            detail=str(e),
            timespan=timespan,
        )

def _arm_get(url: str) -> dict:
    try:
        token = get_managed_identity_token(ARM_RESOURCE)
    except Exception as e:
        return _fail("Failed to acquire ARM token", code="MANAGED_IDENTITY_ERROR", detail=str(e))

    start = time.time()

    try:
        resp = SESSION.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except Exception as e:
        return _fail("HTTP request to ARM failed", code="HTTP_ERROR", detail=str(e))

    elapsed_ms = int((time.time() - start) * 1000)

    if not resp.ok:
        logger.warning("ARM request failed status=%s duration_ms=%s", resp.status_code, elapsed_ms)
        return _fail(
            "ARM request failed",
            code="ARM_ERROR",
            status_code=resp.status_code,
            detail=resp.text,
        )

    try:
        payload = resp.json()
        logger.info("ARM request ok duration_ms=%s", elapsed_ms)
        return _ok(payload, duration_ms=elapsed_ms)
    except Exception as e:
        return _fail("Failed to parse ARM JSON response", code="PARSE_ERROR", detail=str(e))

def _arm_get_paged(base_url: str) -> dict:
    """
    Follow ARM nextLink pagination and return all items in a single list.
    Handles workspaces with 200+ analytics rules etc.
    """
    all_items = []
    url = base_url

    while url:
        res = _arm_get(url)
        if not res.get("ok"):
            return res
        data = res["data"]
        all_items.extend(data.get("value") or [])
        url = data.get("nextLink")  # None when last page

    return _ok({"value": all_items})

# ============================================================
# PARALLEL QUERY HELPER
# ============================================================

def _run_queries_parallel(
    tasks: List[Tuple[str, str, str]],
    timespan: str,
    wall_clock_timeout: int = PARALLEL_WALL_CLOCK_TIMEOUT,
) -> Dict[str, dict]:
    """
    Execute multiple LA queries in parallel with a shared wall-clock timeout.

    tasks: list of (task_id, table_name, kql_string)
    Returns: dict mapping task_id → la_query result dict
    """
    results: Dict[str, dict] = {}

    def _run(task_id: str, kql: str) -> Tuple[str, dict]:
        return task_id, la_query(kql, timespan)

    with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as executor:
        futures = {
            executor.submit(_run, task_id, kql): task_id
            for task_id, _table, kql in tasks
        }
        deadline = time.time() + wall_clock_timeout

        for future in as_completed(futures, timeout=max(1, deadline - time.time())):
            try:
                task_id, result = future.result(timeout=1)
                results[task_id] = result
            except Exception as e:
                task_id = futures[future]
                results[task_id] = _fail(
                    "Query task failed or timed out",
                    code="TASK_ERROR",
                    detail=str(e),
                )

    # Tasks that never completed before the wall clock get a timeout entry
    for _task_id, table, _kql in tasks:
        if _task_id not in results:
            results[_task_id] = _fail(
                f"Query timed out after {wall_clock_timeout}s",
                code="TIMEOUT",
                detail=f"table={table}",
            )

    return results

# ============================================================
# ANALYTICS RULE HELPERS
# ============================================================

CONFLUENCE_TEMPLATE = """
<p><strong>TYPE:</strong> USE CASE - <strong>SEVERITY:</strong> {severity}</p>
<hr/>

<h1>USE CASE SUMMARY</h1>
<p><strong>Purpose</strong></p>
<p>The purpose of this document is to describe the detection logic and implementation of the use case <strong>{rule_name}</strong>.</p>

<hr/>

<h1>Threat Layer</h1>

<h2>MITRE ATT&CK</h2>
<table>
<tr><th>Tactic</th><th>Technique</th></tr>
{mitre_rows}
</table>

<h2>Cyber Kill Chain</h2>
<p>The use case primarily addresses the following phase:</p>
<p><strong>{kill_chain_phase}</strong></p>

<h2>References</h2>
<ul>
<li>Microsoft Sentinel analytic rule: {rule_name}</li>
</ul>

<hr/>

<h1>Implementation Layer</h1>

<h2>Log Sources</h2>
<p>{tables}</p>

<h2>Scope</h2>
<p>This rule runs every {query_frequency} with a lookback of {query_period}.</p>

<h2>Monitoring Rules</h2>
<pre>{kql}</pre>

<h2>Entities</h2>
<ul>
{entities}
</ul>
"""

def _extract_tables_from_kql(kql: str) -> List[str]:
    if not kql:
        return []
    candidates = re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\s*\|", kql)
    seen = set()
    out = []
    for t in candidates:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out

def _extract_ops_from_kql(kql: str) -> List[str]:
    if not kql:
        return []
    ops = [
        "where", "summarize", "join", "extend",
        "project", "project-away", "parse",
        "mv-expand", "evaluate", "union",
        "lookup", "distinct",
    ]
    lowered = kql.lower()
    return [op for op in ops if re.search(rf"\b{re.escape(op)}\b", lowered)]

def _extract_threshold_snippets(kql: str) -> List[str]:
    if not kql:
        return []
    matches = re.findall(
        r"(?i)\bwhere\b[^\n]{0,140}?(?:>=|<=|==|!=|>|<)\s*\d+(?:\.\d+)?",
        kql,
    )
    seen = set()
    out = []
    for m in matches:
        m2 = " ".join(m.split())
        if m2 not in seen:
            seen.add(m2)
            out.append(m2)
        if len(out) >= 10:
            break
    return out

def _detect_entity_hints(kql: str) -> List[str]:
    if not kql:
        return []
    fields = [
        "UserPrincipalName", "Account", "AccountName", "AadUserId",
        "IPAddress", "IpAddress", "CallerIpAddress", "RemoteIP",
        "DeviceName", "Computer", "HostName",
        "FileName", "SHA256", "SHA1", "MD5",
        "ProcessCommandLine", "CommandLine", "Url", "RemoteUrl",
    ]
    hits = []
    for f in fields:
        if re.search(rf"\b{re.escape(f)}\b", kql, re.IGNORECASE):
            hits.append(f)
    return hits[:20]

def _kql_one_liner_summary(kql: str) -> str:
    if not kql:
        return ""
    lines = [ln.strip() for ln in kql.splitlines() if ln.strip()]
    head = lines[0] if lines else ""
    ops = _extract_ops_from_kql(kql)
    if ops:
        return f"{head} (ops: {', '.join(ops[:8])})"
    return head

def _sentinel_rules_base_url() -> str:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        raise ValueError("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured")

    return (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{WORKSPACE_NAME}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
    )

def _fetch_rule_by_id(rule_id: str) -> dict:
    base = _sentinel_rules_base_url()
    url = f"{base}/{rule_id}?api-version=2023-09-01-preview"
    return _arm_get(url)

def _find_rule_id_by_name(rule_name: str) -> Optional[str]:
    base = _sentinel_rules_base_url()
    url = f"{base}?api-version=2023-09-01-preview"

    # Use paginated fetch so we don't miss rules on large workspaces
    res = _arm_get_paged(url)
    if not res.get("ok"):
        return None

    target = (rule_name or "").strip().lower()
    for it in (res["data"].get("value") or []):
        props = it.get("properties") or {}
        dn = (props.get("displayName") or "").strip().lower()
        if dn == target:
            return it.get("name")

    return None

def _build_confluence_html(doc: dict) -> str:
    mitre_rows = ""
    tactics = doc.get("mitre_tactics", [])

    if tactics:
        for t in tactics:
            mitre_rows += f"<tr><td>{t}</td><td></td></tr>"
    else:
        mitre_rows = "<tr><td>N/A</td><td>N/A</td></tr>"

    entities_html = ""
    for e in doc.get("kql", {}).get("entity_field_hints", []):
        entities_html += f"<li>{e}</li>"
    if not entities_html:
        entities_html = "<li>N/A</li>"

    tables = ", ".join(doc.get("kql", {}).get("tables_used", [])) or "Not detected"

    return CONFLUENCE_TEMPLATE.format(
        severity=doc.get("severity", "N/A"),
        rule_name=doc.get("rule_display_name", "N/A"),
        mitre_rows=mitre_rows,
        kill_chain_phase="Detection / Command & Control",
        tables=tables,
        query_frequency=doc.get("schedule", {}).get("query_frequency", "N/A"),
        query_period=doc.get("schedule", {}).get("query_period", "N/A"),
        kql=doc.get("kql", {}).get("query", ""),
        entities=entities_html,
    )

# ============================================================
# TOOLS
# ============================================================

_register_tool_def(
    "get_tools",
    (
        "Returns the full list of available MCP tools with their parameter formats. "
        "Call this first if you are unsure which tool to use for a task."
    ),
    {},
)

@mcp.tool
def get_tools() -> dict:
    return _ok({"tools": _TOOL_DEFS, "mcp_path": "/mcp"})

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "ping",
    (
        "Connectivity and configuration health check. Does not query Sentinel. "
        "Use this to verify the MCP endpoint is reachable and the workspace is configured "
        "before running any other tools."
    ),
    {},
)

@mcp.tool
def ping() -> dict:
    return _ok({
        "message": "pong",
        "workspace_configured": bool(WORKSPACE_ID),
        "catalog_loaded": bool((_ensure_catalog_loaded(), WORKSPACE_TABLE_CATALOG)[1]),
        "mcp_path": "/mcp",
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "debug_identity",
    (
        "Shows whether managed identity environment variables are present. "
        "Use when token acquisition is failing to diagnose the root cause."
    ),
    {},
)

@mcp.tool
def debug_identity() -> dict:
    return _ok({
        "IDENTITY_ENDPOINT_present": bool(os.environ.get("IDENTITY_ENDPOINT")),
        "IDENTITY_HEADER_present": bool(os.environ.get("IDENTITY_HEADER")),
        "MSI_ENDPOINT_present": bool(os.environ.get("MSI_ENDPOINT")),
        "MSI_SECRET_present": bool(os.environ.get("MSI_SECRET")),
        "MANAGED_IDENTITY_CLIENT_ID_present": bool(os.environ.get("MANAGED_IDENTITY_CLIENT_ID")),
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "get_workspace_table_catalog",
    (
        "Returns all workspace tables grouped by telemetry domain (e.g. identity_and_authentication, "
        "endpoint_microsoft_defender). Use this to understand what data sources are available before "
        "building queries or choosing which tables to search."
    ),
    {},
)

@mcp.tool
def get_workspace_table_catalog() -> dict:
    _ensure_catalog_loaded()
    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded", code="CATALOG_NOT_LOADED")
    return _ok({"catalog": WORKSPACE_TABLE_CATALOG})

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "debug_catalog_loaded",
    "Returns whether the workspace catalog JSON loaded successfully and which domain keys are present.",
    {},
)

@mcp.tool
def debug_catalog_loaded() -> dict:
    _ensure_catalog_loaded()
    return _ok({
        "loaded": bool(WORKSPACE_TABLE_CATALOG),
        "keys": list(WORKSPACE_TABLE_CATALOG.keys()),
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "list_workspace_tables",
    (
        "Returns a flat list of all unique table names from the workspace catalog. "
        "Use this when you need a simple table list. "
        "Prefer get_workspace_table_catalog if you also need domain groupings."
    ),
    {},
)

@mcp.tool
def list_workspace_tables() -> dict:
    _ensure_catalog_loaded()
    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded", code="CATALOG_NOT_LOADED")
    return _ok({"tables": _flatten_catalog_tables()})

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "list_tables",
    (
        "Lists tables that actively ingested data within the given timespan by querying the Usage table. "
        "Use this to discover which tables have recent data. "
        "Prefer list_workspace_tables if you only need the static catalog."
    ),
    {"timespan": "ISO8601 duration like P1D, PT6H, PT24H"},
)

@mcp.tool
def list_tables(timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    kql = """
Usage
| where Quantity > 0
| summarize Count=sum(Quantity) by DataType
| order by Count desc
| take 50
""".strip()

    res = la_query(kql, timespan)
    if not res.get("ok"):
        return res

    payload = res["data"]
    columns, rows = _la_first_table_rows(payload)

    if not columns:
        return _fail("No tables returned from Log Analytics", code="EMPTY_RESULT", timespan=timespan)

    if "DataType" not in columns:
        return _fail(
            "Unexpected response shape: DataType column not present",
            code="PARSE_ERROR",
            timespan=timespan,
        )

    idx = columns.index("DataType")
    return _ok({"tables": [row[idx] for row in rows]}, timespan=timespan)

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "preview_table",
    (
        "Returns 10 sample rows from the specified table. "
        "Use this to inspect raw log data or verify a table has the expected fields. "
        "Use get_table_schema if you only need column names and types, not data."
    ),
    {"table": "Table name string", "timespan": "ISO8601 duration"},
)

@mcp.tool
def preview_table(table: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        table = validate_table_name(table)
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    kql = f"{table} | take 10"
    return la_query(kql, timespan)

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "get_table_schema",
    (
        "Returns the column names and data types for the specified table using KQL getschema. "
        "Use this before writing a run_query KQL to understand available fields. "
        "Faster than preview_table when you only need structure, not data."
    ),
    {"table": "Table name string", "timespan": "ISO8601 duration"},
)

@mcp.tool
def get_table_schema(table: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        table = validate_table_name(table)
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    kql = f"{table} | getschema"
    return la_query(kql, timespan)

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "run_query",
    (
        "Runs a custom bounded KQL query against the Sentinel workspace. "
        "Use this for ad-hoc investigation queries that are not covered by the other tools. "
        "Prefer analyze_entity for IOC lookups, get_incident_report for incident listing, "
        "and investigate_incident for full incident deep-dives. "
        "Query MUST contain at least one where clause. Max timespan 72h, max rows 200."
    ),
    {
        "kql": "KQL string — must include at least one where clause",
        "timespan": "ISO8601 duration, max PT72H / P3D",
        "max_rows": "integer 1–200, default 50",
    },
)

@mcp.tool
def run_query(kql: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    if not kql or not isinstance(kql, str):
        return _fail("kql is required", code="VALIDATION_ERROR")

    try:
        kql_safety_check(kql)
        _run_query_requires_reasonable_scope(kql)
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid query input", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_RUN_QUERY:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_RUN_QUERY}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h",
        )

    bounded_kql = ensure_take_limit(kql, clamp_rows(max_rows))
    return la_query(bounded_kql, timespan)

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "get_recent_alerts",
    (
        "Returns recent Microsoft Sentinel security alerts filtered by severity and timespan. "
        "Use this for a quick triage feed of what is firing in the environment. "
        "Prefer investigate_incident when you already have an incident number."
    ),
    {
        "timespan": "ISO8601 duration like P1D, PT6H",
        "severity": "optional: High | Medium | Low | Informational (omit for all)",
        "max_rows": "integer 1–200, default 50",
    },
)

@mcp.tool
def get_recent_alerts(
    timespan: str = "P1D",
    severity: Optional[str] = None,
    max_rows: int = DEFAULT_ROWS,
) -> dict:
    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)",
            code="VALIDATION_ERROR",
        )

    severity_filter = ""
    if severity:
        valid_severities = {"high", "medium", "low", "informational"}
        if severity.lower() not in valid_severities:
            return _fail(
                f"Invalid severity. Must be one of: {', '.join(valid_severities)}",
                code="VALIDATION_ERROR",
            )
        safe_sev = escape_kql_string(severity)
        severity_filter = f'| where AlertSeverity =~ "{safe_sev}"'

    limit = clamp_rows(max_rows)
    kql = f"""
SecurityAlert
| where TimeGenerated >= ago({int(hours)}h)
{severity_filter}
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Status,
    CompromisedEntity,
    Tactics,
    Techniques,
    SystemAlertId,
    ProductName,
    Description
| order by TimeGenerated desc
| take {limit}
""".strip()

    return la_query(kql, timespan)

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "list_analytics_rules",
    (
        "Lists Microsoft Sentinel analytics rules in the configured workspace. "
        "Returns rule_id, display_name, kind, enabled status, and severity. "
        "Use analyze_use_case or generate_confluence_use_case to get full details for a single rule."
    ),
    {"top": "optional int, max rules to return (default 50, hard cap 200)"},
)

@mcp.tool
def list_analytics_rules(top: int = 50) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail(
            "SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
            code="CONFIG_ERROR",
        )

    try:
        top_i = int(top)
    except Exception:
        top_i = 50
    top_i = max(1, min(top_i, 200))

    base = _sentinel_rules_base_url()
    url = f"{base}?api-version=2023-09-01-preview"

    # Use paginated fetch — large workspaces have more than one ARM page of rules
    res = _arm_get_paged(url)
    if not res.get("ok"):
        return res

    items = res["data"].get("value") or []

    out = []
    for it in items[:top_i]:
        props = it.get("properties") or {}
        out.append({
            "rule_id": it.get("name"),
            "display_name": props.get("displayName"),
            "kind": it.get("kind"),
            "enabled": props.get("enabled"),
            "severity": props.get("severity"),
        })

    return _ok({"count": len(out), "rules": out})

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "analyze_use_case",
    (
        "Fetches a Sentinel analytic rule by rule_id or rule_name and extracts documentation-ready "
        "key points including KQL summary, MITRE mappings, schedule, trigger thresholds, and entity hints. "
        "Use list_analytics_rules first to find rule_id or exact display name."
    ),
    {
        "rule_id": "optional: analytic rule ARM resource name/GUID",
        "rule_name": "optional: displayName exact match (case-insensitive)",
    },
)

@mcp.tool
def analyze_use_case(
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail(
            "SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
            code="CONFIG_ERROR",
        )

    rid = (rule_id or "").strip()
    rname = (rule_name or "").strip()

    if not rid and not rname:
        return _fail("Provide rule_id or rule_name", code="VALIDATION_ERROR")

    if not rid and rname:
        rid = _find_rule_id_by_name(rname) or ""
        if not rid:
            return _fail("Rule not found by name", code="NOT_FOUND", detail="Try list_analytics_rules")

    res = _fetch_rule_by_id(rid)
    if not res.get("ok"):
        return res

    rule = res["data"] or {}
    props = rule.get("properties") or {}
    kql = props.get("query") or ""

    doc = {
        "rule_id": rule.get("name"),
        "rule_display_name": props.get("displayName"),
        "description": props.get("description"),
        "severity": props.get("severity"),
        "enabled": props.get("enabled"),
        "kind": rule.get("kind"),
        "mitre_tactics": props.get("tactics") or [],
        "mitre_techniques": props.get("techniques") or [],
        "schedule": {
            "query_frequency": props.get("queryFrequency"),
            "query_period": props.get("queryPeriod"),
        },
        "trigger": {
            "operator": props.get("triggerOperator"),
            "threshold": props.get("triggerThreshold"),
        },
        "kql": {
            "query": kql[:12000],
            "summary": _kql_one_liner_summary(kql),
            "tables_used": _extract_tables_from_kql(kql)[:25],
            "operators_used": _extract_ops_from_kql(kql),
            "threshold_hints": _extract_threshold_snippets(kql),
            "entity_field_hints": _detect_entity_hints(kql),
        },
    }

    return _ok(doc)

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "generate_confluence_use_case",
    (
        "Generates a Confluence-ready HTML documentation page for a Sentinel analytic rule, "
        "including MITRE ATT&CK table, KQL, log sources, and entity mapping. "
        "Use list_analytics_rules first to find the rule_id or exact display name."
    ),
    {
        "rule_id": "optional: analytic rule ARM resource name/GUID",
        "rule_name": "optional: displayName exact match (case-insensitive)",
    },
)

@mcp.tool
def generate_confluence_use_case(
    rule_id: Optional[str] = None,
    rule_name: Optional[str] = None,
) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail(
            "SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
            code="CONFIG_ERROR",
        )

    rid = (rule_id or "").strip()
    rname = (rule_name or "").strip()

    if not rid and not rname:
        return _fail("Provide rule_id or rule_name", code="VALIDATION_ERROR")

    if not rid and rname:
        rid = _find_rule_id_by_name(rname) or ""
        if not rid:
            return _fail("Rule not found by name", code="NOT_FOUND")

    res = _fetch_rule_by_id(rid)
    if not res.get("ok"):
        return res

    rule = res["data"] or {}
    props = rule.get("properties") or {}
    kql = props.get("query") or ""

    doc = {
        "rule_display_name": props.get("displayName"),
        "severity": props.get("severity"),
        "mitre_tactics": props.get("tactics") or [],
        "mitre_techniques": props.get("techniques") or [],
        "schedule": {
            "query_frequency": props.get("queryFrequency"),
            "query_period": props.get("queryPeriod"),
        },
        "kql": {
            "query": kql,
            "tables_used": _extract_tables_from_kql(kql),
            "entity_field_hints": _detect_entity_hints(kql),
        },
    }

    html = _build_confluence_html(doc)
    return _ok({"rule_name": props.get("displayName"), "confluence_html": html})

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "analyze_entity",
    (
        "SOC-style entity investigation across common Sentinel tables. "
        "Auto-detects entity type (ip, user/UPN, host, domain, sha256/sha1/md5) from the value string. "
        "Returns per-table event counts, first/last seen times, risk level, and CMDB context. "
        "Queries run in parallel so results arrive within the wall-clock timeout. "
        "Use run_query for custom follow-up queries on a specific table."
    ),
    {
        "value": "Entity string — IP address, UPN, hostname, domain, or file hash",
        "timespan": "ISO8601 duration (PT6H, P1D, P7D)",
        "max_rows": "integer 1–200 (default 50)",
    },
)

@mcp.tool
def analyze_entity(value: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    if not value:
        return _fail("value is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h",
        )

    entity_type = detect_entity_type(value)
    safe_value = escape_kql_string(value)
    max_rows = clamp_rows(max_rows)

    preferred_domains = _catalog_domains_for_entity(entity_type)

    # Build catalog-aware preferred set — but do NOT skip tables that are in
    # the hardcoded table_map just because they're absent from the catalog.
    # The catalog may be incomplete; we filter only when the catalog IS loaded.
    _ensure_catalog_loaded()
    preferred_tables = set(_catalog_tables_for_domains(preferred_domains)) if WORKSPACE_TABLE_CATALOG else set()

    table_map = {
        "ip": [
            ("SigninLogs",        f'IPAddress == "{safe_value}"'),
            ("SecurityAlert",     f'CompromisedEntity contains "{safe_value}" or tostring(Entities) contains "{safe_value}"'),
            ("AzureActivity",     f'CallerIpAddress == "{safe_value}"'),
            ("DeviceNetworkEvents", f'RemoteIP == "{safe_value}" or LocalIP == "{safe_value}"'),
        ],
        "user": [
            ("SigninLogs",        f'UserPrincipalName =~ "{safe_value}"'),
            ("SecurityEvent",     f'Account =~ "{safe_value}"'),          # now included
            ("AuditLogs",         f'tostring(InitiatedBy.user.userPrincipalName) =~ "{safe_value}"'),  # now included
            ("DeviceLogonEvents", f'AccountName =~ "{safe_value}" or InitiatingProcessAccountUpn =~ "{safe_value}"'),
        ],
        "domain": [
            ("DeviceNetworkEvents", f'RemoteUrl contains "{safe_value}"'),
            ("UrlClickEvents",      f'Url contains "{safe_value}"'),
            ("EmailUrlInfo",        f'Url contains "{safe_value}"'),
        ],
        "sha256": [
            ("DeviceFileEvents", f'SHA256 == "{safe_value}"'),
        ],
        "sha1": [
            ("DeviceFileEvents", f'SHA1 == "{safe_value}"'),
        ],
        "md5": [
            ("DeviceFileEvents", f'MD5 == "{safe_value}"'),
        ],
        "host": [
            ("DeviceInfo",     f'DeviceName =~ "{safe_value}"'),
            ("DeviceEvents",   f'DeviceName =~ "{safe_value}"'),
            ("DeviceProcessEvents", f'DeviceName =~ "{safe_value}"'),
            ("SecurityAlert",  f'CompromisedEntity contains "{safe_value}" or tostring(Entities) contains "{safe_value}"'),
        ],
    }

    raw_queries = table_map.get(entity_type, [])[:6]

    # Build parallel task list — include tables even if not in preferred_tables
    # (catalog may be incomplete). Only hard-skip when catalog is loaded AND
    # explicitly excludes a table from every domain we care about.
    tasks = []
    for table, where_clause in raw_queries:
        if preferred_tables and table not in preferred_tables:
            # Table not in catalog at all — still run it; just log a warning
            logger.debug("Table %s not in preferred set for %s — running anyway", table, entity_type)
        summary_kql = f"""
{table}
| where {where_clause}
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
""".strip()
        tasks.append((table, table, summary_kql))

    # ── Parallel execution ─────────────────────────────────────────────────
    query_results = _run_queries_parallel(tasks, timespan)

    findings = []
    total_events = 0
    risk_score = 0
    tables_checked = []

    for table, _table_label, _kql in tasks:
        tables_checked.append(table)
        res = query_results.get(table)
        if not res or not res.get("ok"):
            continue

        rows = _la_first_table_dicts(res["data"])
        if not rows:
            continue

        row = rows[0]
        count = int(row.get("Count") or 0)
        if count == 0:
            continue

        total_events += count

        if count > 100:
            risk_score += 2
        elif count > 20:
            risk_score += 1

        if table in ["SecurityEvent", "AuditLogs", "SecurityAlert"]:
            risk_score += 1

        findings.append({
            "table": table,
            "count": count,
            "first_seen": row.get("FirstSeen"),
            "last_seen": row.get("LastSeen"),
        })

    # CMDB enrichment (runs after parallel block — low latency, single query)
    cmdb_context = None
    if entity_type in {"ip", "host", "domain"}:
        cmdb_res = _query_cmdb_entity(value, timespan)
        if cmdb_res.get("ok"):
            cmdb_context = cmdb_res["data"]

    if risk_score >= 4:
        risk_level = "High"
    elif risk_score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return _ok({
        "entity": value,
        "entity_type": entity_type,
        "timespan": timespan,
        "telemetry_domains_checked": preferred_domains,
        "tables_checked": tables_checked,
        "tables_hit": len(findings),
        "total_events": total_events,
        "risk_level": risk_level,
        "cmdb_context": cmdb_context,
        "results": findings,
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "get_incident_report",
    (
        "Lists recent Sentinel incidents or generates a structured SOC report for a single incident. "
        "Omit incident_id to get a list of recent incidents. "
        "Provide incident_id (incident number or name) to get a detailed report including linked alerts, "
        "fully parsed and typed entities (hosts, accounts, IPs, URLs, files, processes, registry keys, "
        "cloud resources), tactics, techniques, and risk level. "
        "Uses three focused queries (incident metadata, alerts, entities) to avoid join fan-out and "
        "reliably extract all entity types. "
        "Use investigate_incident for a deeper investigation with parallel entity lookups across telemetry tables."
    ),
    {
        "incident_id": "optional: Sentinel incident number or IncidentName",
        "timespan": "ISO8601 duration like P1D, P7D",
        "top": "optional: number of incidents to list (default 50, max 200)",
    },
)

@mcp.tool
def get_incident_report(
    incident_id: Optional[str] = None,
    timespan: str = "P7D",
    top: int = 50,
) -> dict:
    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    top = clamp_rows(top)

    # ── MODE 1: LIST INCIDENTS ─────────────────────────────────────────────
    if not incident_id:
        ago_expr = f"{int(hours)}h" if hours.is_integer() else f"{hours}h"

        kql = f"""
SecurityIncident
| where Severity !~ "Informational"
| where CreatedTime >= ago({ago_expr})
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project
    IncidentNumber, Title, Severity, Status, Owner,
    CreatedTime, LastModifiedTime, ClosedTime,
    Classification, ClassificationReason, ClassificationComment
| order by CreatedTime desc
| take {top}
""".strip()

        res = la_query(kql, timespan)
        if not res.get("ok"):
            return res

        incidents = _la_first_table_dicts(res["data"])
        if not incidents:
            return _fail("No incidents found", code="EMPTY_RESULT")

        return _ok({"mode": "list", "count": len(incidents), "incidents": incidents})

    # ── MODE 2: INCIDENT REPORT ────────────────────────────────────────────
    safe_id = escape_kql_string(str(incident_id))

    # ── Query 1: Incident metadata ─────────────────────────────────────────
    kql_incident = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project
    IncidentNumber, Title, Severity, Status, Owner,
    CreatedTime, LastModifiedTime, ClosedTime,
    Classification, ClassificationReason, ClassificationComment,
    AlertIds, Labels, IncidentUrl
""".strip()

    res_inc = la_query(kql_incident, timespan)
    if not res_inc.get("ok"):
        return res_inc

    incidents = _la_first_table_dicts(res_inc["data"])
    if not incidents:
        return _fail("Incident not found", code="NOT_FOUND")

    incident = incidents[0]

    # ── Query 2: Linked alerts (full fields, deduplicated) ─────────────────
    kql_alerts = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| mv-expand AlertId = AlertIds to typeof(string)
| join kind=inner (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project
        SystemAlertId,
        AlertName,
        AlertSeverity,
        AlertDescription = Description,
        AlertStatus     = Status,
        AlertStartTime  = StartTime,
        AlertEndTime    = EndTime,
        ProductName,
        ProductComponentName,
        CompromisedEntity,
        Tactics,
        Techniques,
        SubTechniques,
        AlertLink,
        Entities
) on $left.AlertId == $right.SystemAlertId
| project
    AlertId,
    AlertName,
    AlertSeverity,
    AlertDescription,
    AlertStatus,
    AlertStartTime,
    AlertEndTime,
    ProductName,
    ProductComponentName,
    CompromisedEntity,
    Tactics,
    Techniques,
    SubTechniques,
    AlertLink,
    Entities
""".strip()

    res_alerts = la_query(kql_alerts, timespan)
    # Don't fail hard — incident may have no correlated alerts yet
    alert_rows = _la_first_table_dicts(res_alerts["data"]) if res_alerts.get("ok") else []

    # ── Query 3: Entities — parsed, expanded, typed by actual Sentinel schema ─
    # Sentinel entity objects use $id/$ref back-references. $ref entries have
    # no "Type" field — they are filtered out by isnotempty(EntityType).
    # Field names are type-specific: HostName (host), AccountName (account),
    # Address (ip), CommandLine (process), Name (file/url/dns).
    # IPs are also nested inside host objects as LastIpAddress.Address and
    # LastExternalIpAddress.Address — we extract those as separate ip rows.
    kql_entities = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| mv-expand AlertId = AlertIds to typeof(string)
| join kind=inner (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project SystemAlertId, Entities
) on $left.AlertId == $right.SystemAlertId
| mv-expand Entity = parse_json(Entities)
| where isnotempty(Entity)
| extend EntityType = tolower(tostring(Entity.Type))
| where isnotempty(EntityType)                              // drops $ref back-reference entries
// ── Primary name per type ────────────────────────────────────────────────
| extend EntityName = case(
    EntityType == "host",     tostring(Entity.HostName),
    EntityType == "account",  coalesce(tostring(Entity.AccountName), tostring(Entity.UserPrincipalName)),
    EntityType == "ip",       tostring(Entity.Address),
    EntityType == "process",  tostring(Entity.CommandLine),
    EntityType == "file",     tostring(Entity.Name),
    EntityType == "url",      tostring(Entity.Url),
    EntityType == "dns",      tostring(Entity.DomainName),
    EntityType == "registrykey", tostring(Entity.Key),
    EntityType == "cloudapplication", tostring(Entity.Name),
    tostring(Entity.Name)
)
| where isnotempty(EntityName) and EntityName != "null"
// ── Also unpack IPs nested inside host objects ───────────────────────────
| extend InternalIp  = iff(EntityType == "host", tostring(Entity.LastIpAddress.Address), "")
| extend ExternalIp  = iff(EntityType == "host", tostring(Entity.LastExternalIpAddress.Address), "")
| extend Fqdn        = iff(EntityType == "host", tostring(Entity.FQDN), "")
| summarize
    Hosts          = make_set_if(EntityName, EntityType == "host", 50),
    Fqdns          = make_set_if(Fqdn, EntityType == "host" and isnotempty(Fqdn) and Fqdn != "null", 50),
    Accounts       = make_set_if(EntityName, EntityType == "account", 50),
    IpAddresses    = make_set_if(EntityName, EntityType == "ip", 50),
    InternalIps    = make_set_if(InternalIp, isnotempty(InternalIp) and InternalIp != "null", 50),
    ExternalIps    = make_set_if(ExternalIp, isnotempty(ExternalIp) and ExternalIp != "null", 50),
    Urls           = make_set_if(EntityName, EntityType == "url", 50),
    Files          = make_set_if(EntityName, EntityType == "file", 50),
    Processes      = make_set_if(EntityName, EntityType == "process", 50),
    Domains        = make_set_if(EntityName, EntityType == "dns", 50),
    RegistryKeys   = make_set_if(EntityName, EntityType == "registrykey", 50),
    CloudResources = make_set_if(EntityName, EntityType in ("cloudapplication", "azureresource"), 50),
    AllEntities    = make_set(EntityName, 200)
by IncidentNumber
""".strip()

    res_ent = la_query(kql_entities, timespan)
    entity_row: dict = {}
    if res_ent.get("ok"):
        ent_rows = _la_first_table_dicts(res_ent["data"])
        if ent_rows:
            entity_row = ent_rows[0]

    # ── Assemble structured alert list ─────────────────────────────────────
    alerts_structured = []
    for a in alert_rows:
        alerts_structured.append({
            "alert_id":           a.get("AlertId"),
            "alert_name":         a.get("AlertName"),
            "severity":           a.get("AlertSeverity"),
            "description":        a.get("AlertDescription"),
            "status":             a.get("AlertStatus"),
            "start_time":         a.get("AlertStartTime"),
            "end_time":           a.get("AlertEndTime"),
            "product":            a.get("ProductName"),
            "component":          a.get("ProductComponentName"),
            "compromised_entity": a.get("CompromisedEntity"),
            "tactics":            a.get("Tactics"),
            "techniques":         a.get("Techniques"),
            "sub_techniques":     a.get("SubTechniques"),
            "alert_link":         a.get("AlertLink"),
        })

    # ── Risk scoring (severity + alert volume + entity spread) ─────────────
    severity    = (incident.get("Severity") or "").lower()
    alert_count = len(alerts_structured)
    entity_count = len(entity_row.get("AllEntities") or [])

    if severity == "high" or alert_count >= 5 or entity_count >= 10:
        risk = "Critical"
    elif severity == "medium" or alert_count >= 2 or entity_count >= 5:
        risk = "High"
    elif severity == "low":
        risk = "Medium"
    else:
        risk = "Low"

    # Merge internal + external IPs from host objects into the ip_addresses bucket
    all_ips = list({
        *entity_row.get("IpAddresses", []),
        *entity_row.get("InternalIps", []),
        *entity_row.get("ExternalIps", []),
    })

    return _ok({
        "mode": "report",
        # ── Incident core ──────────────────────────────────────────────────
        "incident_number":        incident.get("IncidentNumber"),
        "title":                  incident.get("Title"),
        "severity":               incident.get("Severity"),
        "status":                 incident.get("Status"),
        "owner":                  incident.get("Owner"),
        "created_time":           incident.get("CreatedTime"),
        "last_modified":          incident.get("LastModifiedTime"),
        "closed_time":            incident.get("ClosedTime"),
        "classification":         incident.get("Classification"),
        "classification_reason":  incident.get("ClassificationReason"),
        "classification_comment": incident.get("ClassificationComment"),
        "incident_url":           incident.get("IncidentUrl"),
        "labels":                 incident.get("Labels"),
        # ── Alerts ────────────────────────────────────────────────────────
        "alerts_count":           alert_count,
        "alerts":                 alerts_structured,
        # ── Entities — typed buckets ───────────────────────────────────────
        "entities": {
            "hosts":           entity_row.get("Hosts", []),
            "fqdns":           entity_row.get("Fqdns", []),
            "accounts":        entity_row.get("Accounts", []),
            "ip_addresses":    all_ips,
            "urls":            entity_row.get("Urls", []),
            "files":           entity_row.get("Files", []),
            "processes":       entity_row.get("Processes", []),
            "domains":         entity_row.get("Domains", []),
            "registry_keys":   entity_row.get("RegistryKeys", []),
            "cloud_resources": entity_row.get("CloudResources", []),
            "all":             entity_row.get("AllEntities", []),
        },
        "entity_count":           entity_count,
        # ── Risk ──────────────────────────────────────────────────────────
        "risk_level":             risk,
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "investigate_incident",
    (
        "Full SOC investigation of a Sentinel incident. "
        "Extracts alerts, parses entity lists (users, IPs, hosts, domains), "
        "builds MITRE timeline, enriches with CMDB context, and calculates risk level. "
        "Alert and CMDB queries run in parallel to stay within timeout. "
        "Use get_incident_report for a lighter-weight summary."
    ),
    {
        "incident_id": "Sentinel incident number",
        "timespan": "ISO8601 duration (P1D, P7D)",
    },
)

@mcp.tool
def investigate_incident(incident_id: str, timespan: str = "P7D") -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_INCIDENT:
        return _fail(
            f"Timespan exceeds allowed window ({MAX_HOURS_INCIDENT}h max)",
            code="VALIDATION_ERROR",
            detail=f"got {hours}h",
        )

    safe_id = escape_kql_string(str(incident_id))

    incident_kql = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| where Severity !~ "Informational"
| project IncidentNumber, Title, Severity, Status, Owner, CreatedTime, LastModifiedTime, AlertIds
""".strip()

    inc_res = la_query(incident_kql, timespan)
    if not inc_res.get("ok"):
        return inc_res

    incident_rows = _la_first_table_dicts(inc_res["data"])
    if not incident_rows:
        return _fail("Incident not found", code="NOT_FOUND")

    incident = incident_rows[0]
    alert_ids = incident.get("AlertIds") or []

    if isinstance(alert_ids, str):
        try:
            alert_ids = json.loads(alert_ids)
        except Exception:
            alert_ids = []

    if not alert_ids:
        return _ok({
            "incident": incident,
            "alerts": [],
            "entities": {},
            "timeline": {},
            "mitre": {},
            "risk_level": "Low",
            "assessment": "Incident has no linked alerts",
        })

    safe_alerts = [escape_kql_string(str(a)) for a in alert_ids if a]
    alert_list = ",".join([f'"{a}"' for a in safe_alerts])

    alerts_kql = f"""
SecurityAlert
| where SystemAlertId in ({alert_list})
| project
    AlertName = ProductName,
    Component = ProductComponentName,
    AlertTime = StartTime,
    Status,
    CompromisedEntity,
    Tactics,
    Techniques,
    Entities
""".strip()

    alert_res = la_query(alerts_kql, timespan)
    if not alert_res.get("ok"):
        return alert_res

    alerts = _la_first_table_dicts(alert_res["data"])

    users: set = set()
    ips: set = set()
    hosts: set = set()
    domains: set = set()
    processes: set = set()
    files: set = set()

    # id_map resolves $ref back-references: {"$ref": "3"} → object with $id "3"
    id_map: Dict[str, dict] = {}

    for alert in alerts:
        entities = alert.get("Entities")
        if not entities:
            continue
        try:
            ent_list = json.loads(entities) if isinstance(entities, str) else entities
        except Exception:
            continue
        if not isinstance(ent_list, list):
            continue

        # First pass — build $id → object map so $ref entries can be resolved
        for e in ent_list:
            if isinstance(e, dict) and "$id" in e:
                id_map[str(e["$id"])] = e

        # Second pass — extract entity values
        for e in ent_list:
            if not isinstance(e, dict):
                continue

            # Skip pure $ref back-references (no Type field)
            if "$ref" in e and "Type" not in e:
                continue

            etype = (e.get("Type") or "").lower()

            if etype in ("host", "machine"):
                name = e.get("HostName") or e.get("FQDN") or ""
                if name:
                    hosts.add(name.lower())
                # Extract nested IPs from host objects
                lip = (e.get("LastIpAddress") or {})
                if isinstance(lip, dict) and lip.get("Address"):
                    ips.add(lip["Address"])
                eip = (e.get("LastExternalIpAddress") or {})
                if isinstance(eip, dict) and eip.get("Address"):
                    ips.add(eip["Address"])

            elif etype == "account":
                # AccountName is the canonical field; Name is usually the same
                # UserPrincipalName appears for cloud/Entra accounts
                name = (
                    e.get("AccountName")
                    or e.get("UserPrincipalName")
                    or e.get("Name")
                    or ""
                )
                if name and name.lower() not in ("system", ""):
                    users.add(name.lower())

            elif etype == "ip":
                addr = e.get("Address") or ""
                if addr:
                    ips.add(addr)

            elif etype == "dns":
                d = e.get("DomainName") or ""
                if d:
                    domains.add(d.lower())

            elif etype == "process":
                cmd = e.get("CommandLine") or ""
                if cmd:
                    processes.add(cmd[:200])   # cap long command lines

            elif etype == "file":
                fname = e.get("Name") or ""
                if fname:
                    files.add(fname)

    alert_times = [a.get("AlertTime") for a in alerts if a.get("AlertTime")]
    first_alert = min(alert_times) if alert_times else None
    last_alert = max(alert_times) if alert_times else None

    tactics = sorted({a.get("Tactics") for a in alerts if a.get("Tactics")})
    techniques = sorted({a.get("Techniques") for a in alerts if a.get("Techniques")})

    cmdb_pivots = list(ips)[:3] + list(hosts)[:3] + list(domains)[:3]
    cmdb_tasks = [
        (pivot, pivot, f'{CMDB_TABLE} | where tostring(*) contains "{escape_kql_string(str(pivot))}" | take 5')
        for pivot in cmdb_pivots
    ]

    cmdb_context = []
    if cmdb_tasks:
        cmdb_results = _run_queries_parallel(cmdb_tasks, timespan)
        for pivot in cmdb_pivots:
            res = cmdb_results.get(pivot)
            if res and res.get("ok"):
                cmdb_context.append({"entity": pivot, "result": res["data"]})

    risk_score = 0
    sev = (incident.get("Severity") or "").lower()
    if sev == "high":
        risk_score += 4
    elif sev == "medium":
        risk_score += 2
    else:
        risk_score += 1

    if len(alerts) > 5:
        risk_score += 2
    if ips:
        risk_score += 1
    if users:
        risk_score += 1
    if hosts:
        risk_score += 1
    if processes:
        risk_score += 1

    if risk_score >= 6:
        risk_level = "High"
    elif risk_score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return _ok({
        "incident": {
            "id":                incident.get("IncidentNumber"),
            "title":             incident.get("Title"),
            "severity":          incident.get("Severity"),
            "status":            incident.get("Status"),
            "owner":             incident.get("Owner"),
            "created_time":      incident.get("CreatedTime"),
            "last_modified_time":incident.get("LastModifiedTime"),
        },
        "alerts": {
            "count":      len(alerts),
            "names":      sorted({a.get("AlertName") for a in alerts if a.get("AlertName")}),
            "components": sorted({a.get("Component") for a in alerts if a.get("Component")}),
        },
        "entities": {
            "users":     sorted(users),
            "ips":       sorted(ips),
            "hosts":     sorted(hosts),
            "domains":   sorted(domains),
            "processes": sorted(processes),
            "files":     sorted(files),
        },
        "timeline": {
            "first_alert": first_alert,
            "last_alert":  last_alert,
        },
        "mitre": {
            "tactics":    tactics,
            "techniques": techniques,
        },
        "asset_context": cmdb_context,
        "risk_level":    risk_level,
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "run_investigation_checklist",
    (
        "Executes a parallel server-side batch of telemetry queries for an incident and returns "
        "compact bucket summaries. Does NOT replace get_incident_report (use that for incident "
        "metadata and the authoritative entity list) or per-entity deep dives via run_query and "
        "analyze_entity. This tool is a fan-out helper: it runs 8-12 queries server-side and "
        "returns small row-count summaries so the agent can decide where to dig deeper. "
        "Buckets returned: process_events, network_events, file_events, registry_events, "
        "device_events, security_alerts_30d, behavior_analytics, signin_logs, entity_analysis, "
        "site_logs. Each bucket: status (ok/ok_empty/error/skipped), rows, summary string, up to "
        "3 truncated sample rows. Call get_incident_report first for the canonical incident view."
    ),
    {
        "incident_id":  "Sentinel incident number",
        "checklist":    "auto | execution | identity | lateral_movement | network | malware | cloud | behavioral | default",
        "timespan":     "ISO8601 duration, default P7D",
    },
)

# ── Checklist definitions: each entry is (bucket_id, query_fn_or_label, params_dict)
# query_fn values: "run_query", "analyze_entity", "cmdb", "investigate", "history"
# These are resolved at runtime against actual extracted entities.

def _checklist_execution(safe_host: str, safe_user: str, ts_short: str, ts_long: str) -> List[dict]:
    return [
        {"bucket": "cmdb",              "type": "cmdb",          "entity": safe_host},
        {"bucket": "process_events",    "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceProcessEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, SHA256 | order by TimeGenerated desc | take 100'},
        {"bucket": "device_events",     "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, AdditionalFields | order by TimeGenerated desc | take 100'},
        {"bucket": "network_events",    "type": "run_query",     "timespan": ts_long,
         "kql": f'DeviceNetworkEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "registry_events",   "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceRegistryEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueData, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "file_events",       "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceFileEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" or tostring(Entities) contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "behavior_analytics", "type": "run_query",    "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" or DeviceName contains "{safe_host}" | project TimeGenerated, UserName, DeviceName, ActivityType, ActionType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "signin_logs",        "type": "run_query",    "timespan": "P7D",
         "kql": f'SigninLogs | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, DeviceDetail | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",        "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
        {"bucket": "entity_user",        "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
    ]

def _checklist_identity(safe_user: str, safe_ip: str, ts_long: str) -> List[dict]:
    return [
        {"bucket": "signin_logs",        "type": "run_query",    "timespan": "P7D",
         "kql": f'SigninLogs | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, ConditionalAccessStatus, DeviceDetail | order by TimeGenerated desc | take 100'},
        {"bucket": "risk_events",        "type": "run_query",    "timespan": "P30D",
         "kql": f'AADUserRiskEvents | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, IpAddress | order by TimeGenerated desc | take 50'},
        {"bucket": "risky_users",        "type": "run_query",    "timespan": "P30D",
         "kql": f'AADRiskyUsers | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, RiskLevel, RiskState, RiskDetail | order by TimeGenerated desc | take 20'},
        {"bucket": "audit_logs",         "type": "run_query",    "timespan": "P2D",
         "kql": f'AuditLogs | where tostring(InitiatedBy) contains "{safe_user}" | project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources | order by TimeGenerated desc | take 50'},
        {"bucket": "identity_info",      "type": "run_query",    "timespan": "P30D",
         "kql": f'IdentityInfo | where AccountUPN contains "{safe_user}" | project TimeGenerated, AccountUPN, JobTitle, Department, Manager, AccountEnabled, Tags | take 5'},
        {"bucket": "behavior_analytics", "type": "run_query",    "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" | project TimeGenerated, UserName, ActivityType, ActionType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where tostring(Entities) contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_user",        "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
        {"bucket": "entity_ip",          "type": "analyze_entity", "value": safe_ip,   "timespan": "P7D"},
        {"bucket": "signin_by_ip",       "type": "run_query",    "timespan": "P7D",
         "kql": f'SigninLogs | where IPAddress == "{safe_ip}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName | order by TimeGenerated desc | take 50'},
    ]

def _checklist_malware(safe_host: str, safe_user: str, safe_hash: str, ts_short: str) -> List[dict]:
    hash_filter = f'| where SHA256 =~ "{safe_hash}" or SHA1 =~ "{safe_hash}" or MD5 =~ "{safe_hash}"' if safe_hash else ""
    return [
        {"bucket": "cmdb",               "type": "cmdb",         "entity": safe_host},
        {"bucket": "file_events",        "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceFileEvents | where DeviceName contains "{safe_host}" {hash_filter} | project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "process_events",     "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceProcessEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256 | order by TimeGenerated desc | take 100'},
        {"bucket": "device_events",      "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, AdditionalFields | order by TimeGenerated desc | take 100'},
        {"bucket": "network_events",     "type": "run_query",    "timespan": "P1D",
         "kql": f'DeviceNetworkEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "registry_events",    "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceRegistryEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueData | order by TimeGenerated desc | take 100'},
        {"bucket": "threat_intel",       "type": "run_query",    "timespan": "P90D",
         "kql": f'ThreatIntelIndicators | where IndicatorId contains "{safe_hash}" or NetworkIP contains "{safe_hash}" | take 20'},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",        "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
    ]

def _checklist_default(safe_host: str, safe_user: str) -> List[dict]:
    return [
        {"bucket": "cmdb",               "type": "cmdb",         "entity": safe_host},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" or tostring(Entities) contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "behavior_analytics", "type": "run_query",    "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" or DeviceName contains "{safe_host}" | project TimeGenerated, UserName, DeviceName, ActivityType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",        "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
        {"bucket": "entity_user",        "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
    ]

def _auto_detect_checklist(alert_names: List[str], tactics: List[str]) -> str:
    """Infer checklist type from alert names and MITRE tactics."""
    combined = " ".join((alert_names or []) + (tactics or [])).lower()
    if any(k in combined for k in ["powershell", "lolbin", "msbuild", "regsvr32", "rundll32", "mshta", "certutil",
                                    "wmic", "msiexec", "execution", "defense evasion", "download"]):
        return "execution"
    if any(k in combined for k in ["signin", "login", "mfa", "brute", "password", "credential", "token",
                                    "impossible travel", "risky user", "valid account"]):
        return "identity"
    if any(k in combined for k in ["smb", "psexec", "lateral", "dcom", "wmi remote", "pass-the-hash", "rdp"]):
        return "lateral_movement"
    if any(k in combined for k in ["beacon", "c2", "dns tunnel", "proxy", "outbound", "exfil", "network"]):
        return "network"
    if any(k in combined for k in ["malware", "ransomware", "virus", "trojan", "hash", "file", "dropper"]):
        return "malware"
    if any(k in combined for k in ["azure", "storage", "graph api", "service principal", "m365", "office"]):
        return "cloud"
    if any(k in combined for k in ["anomaly", "ueba", "behavioral", "peer analysis", "deviation"]):
        return "behavioral"
    return "default"

def _run_checklist_tasks(tasks: List[dict], timespan: str) -> Dict[str, dict]:
    """Fan out all non-entity tasks in parallel, run analyze_entity sequentially after."""
    parallel_tasks = []
    entity_tasks   = []
    cmdb_tasks_raw = []

    for t in tasks:
        ttype = t.get("type")
        if ttype == "run_query":
            parallel_tasks.append((t["bucket"], t["bucket"], t["kql"]))
        elif ttype == "analyze_entity":
            entity_tasks.append(t)
        elif ttype == "cmdb":
            cmdb_tasks_raw.append(t)

    results: Dict[str, dict] = {}

    # ── Parallel KQL queries ───────────────────────────────────────────────
    if parallel_tasks:
        raw = _run_queries_parallel(parallel_tasks, timespan)
        results.update(raw)

    # ── CMDB queries (sequential, no timespan) ────────────────────────────
    for ct in cmdb_tasks_raw:
        entity = ct["entity"]
        if not entity:
            results[ct["bucket"]] = _fail("No host entity — CMDB skipped", code="SKIPPED")
            continue
        safe_e = escape_kql_string(entity)
        # Strip to shortest unique segment (strip domain suffix)
        core = safe_e.split(".")[0] if "." in safe_e else safe_e

        cmdb_kql = f"""
COVERAGE_CMDB
| where FQDN contains "{core}"
   or Key contains "{core}"
   or logsource contains "{core}"
   or Management_IP contains "{core}"
   or ApplicationAndComponentInstance contains "{core}"
| project Key, FQDN, BusinessEntity, Management_IP, logsource, PSNC,
          ApplicationAndComponentInstance, Network_Interfaces,
          Scanning_Information, Environment, Operating_System, Status
| take 10
""".strip()
        res = la_query(cmdb_kql, "P90D")

        # Fallback 1: full hostname
        if res.get("ok") and not _la_first_table_dicts(res["data"]):
            fb1 = f'COVERAGE_CMDB | where FQDN contains "{safe_e}" or Key contains "{safe_e}" or logsource contains "{safe_e}" | project Key, FQDN, BusinessEntity, Management_IP, logsource, PSNC, ApplicationAndComponentInstance | take 10'
            res = la_query(fb1, "P90D")

        results[ct["bucket"]] = res

    # ── Entity analysis ────────────────────────────────────────────────────
    for et in entity_tasks:
        val = et.get("value", "")
        if not val:
            results[et["bucket"]] = _fail("Empty entity value — skipped", code="SKIPPED")
            continue
        results[et["bucket"]] = analyze_entity(val, timespan=et.get("timespan", "P7D"))

    return results

def _summarise_bucket(bucket_id: str, res: dict) -> dict:
    """Compress a bucket result into a compact summary safe for LLM context."""
    if not res:
        return {"status": "error", "rows": 0, "summary": "null result"}

    if not res.get("ok"):
        code = (res.get("error") or {}).get("code", "")
        if code == "SKIPPED":
            return {"status": "skipped", "rows": 0, "summary": (res.get("error") or {}).get("message", "")}
        return {"status": "error", "rows": 0, "summary": (res.get("error") or {}).get("message", "tool error")}

    # analyze_entity result shape
    data = res.get("data") or {}
    if "entity_type" in data:
        return {
            "status":  "ok",
            "rows":    data.get("total_events", 0),
            "summary": f"entity_type={data.get('entity_type')} risk={data.get('risk_level')} "
                       f"tables_hit={data.get('tables_hit')} events={data.get('total_events')}",
            "detail":  data,
        }

    # run_query / la_query result shape
    rows = _la_first_table_dicts(data)
    count = len(rows)
    status = "ok" if count > 0 else "ok_empty"

    # Build a compact field-value summary. Cap row count, field count, and
    # value length aggressively to keep checklist response size bounded.
    MAX_SAMPLE_ROWS    = 3
    MAX_FIELDS_PER_ROW = 10
    MAX_VALUE_CHARS    = 300

    def _truncate_value(v):
        if isinstance(v, str) and len(v) > MAX_VALUE_CHARS:
            return v[:MAX_VALUE_CHARS] + "...[truncated]"
        return v

    compact = []
    for r in rows[:MAX_SAMPLE_ROWS]:
        kept = {k: _truncate_value(v) for k, v in r.items() if v not in (None, "", [])}
        if len(kept) > MAX_FIELDS_PER_ROW:
            kept = dict(list(kept.items())[:MAX_FIELDS_PER_ROW])
            kept["_truncated_fields"] = True
        compact.append(kept)

    return {
        "status":    status,
        "rows":      count,
        "summary":   f"{count} rows returned",
        "sample":    compact,
        "truncated": count > MAX_SAMPLE_ROWS,
    }


@mcp.tool
def run_investigation_checklist(
    incident_id: str,
    checklist: str = "auto",
    timespan: str = "P7D",
) -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_INCIDENT:
        return _fail(f"Timespan too large (max {MAX_HOURS_INCIDENT}h)", code="VALIDATION_ERROR")

    # ── Step 1: Get incident + similar history in parallel ─────────────────
    safe_id = escape_kql_string(str(incident_id))

    inc_res     = investigate_incident(incident_id, timespan=timespan)
    hist_res    = get_similar_incident_history(incident_id, days=30)

    if not inc_res.get("ok"):
        return inc_res

    inc_data    = inc_res.get("data") or {}
    ents        = inc_data.get("entities") or {}
    alert_names = list((inc_data.get("alerts") or {}).get("names") or [])
    tactics     = list((inc_data.get("mitre") or {}).get("tactics") or [])

    # ── Extract primary entities ───────────────────────────────────────────
    hosts   = ents.get("hosts") or []
    users   = ents.get("users") or []
    ips     = ents.get("ips")   or []
    hashes  = []  # populated from file events if present

    safe_host = escape_kql_string(hosts[0].lower().split(".")[0]) if hosts else ""
    safe_user = escape_kql_string(users[0]) if users else ""
    safe_ip   = escape_kql_string(ips[0])   if ips   else ""
    safe_hash = ""

    # ── Step 2: Detect / validate checklist ───────────────────────────────
    cl = (checklist or "auto").strip().lower()
    if cl == "auto":
        cl = _auto_detect_checklist(alert_names, tactics)

    ts_short = "PT12H"
    ts_long  = "P1D"

    # ── Step 3: Build task list for chosen checklist ───────────────────────
    if cl == "execution":
        tasks = _checklist_execution(safe_host, safe_user, ts_short, ts_long)
    elif cl == "identity":
        tasks = _checklist_identity(safe_user, safe_ip, ts_long)
    elif cl == "malware":
        tasks = _checklist_malware(safe_host, safe_user, safe_hash, ts_short)
    else:
        tasks = _checklist_default(safe_host, safe_user)

    # ── Step 4: Execute all tasks ──────────────────────────────────────────
    raw_results = _run_checklist_tasks(tasks, timespan)

    # ── Step 5: Compress each bucket for LLM consumption ──────────────────
    buckets: Dict[str, dict] = {}
    for task in tasks:
        bid = task["bucket"]
        buckets[bid] = _summarise_bucket(bid, raw_results.get(bid))

    # ── Step 6: Escalation trigger scan across security_alerts_30d ────────
    escalation_triggers = []
    sa_bucket = buckets.get("security_alerts_30d", {})
    if sa_bucket.get("status") == "ok":
        for row in (sa_bucket.get("sample") or []):
            name = str(row.get("AlertName") or "").lower()
            desc = str(row.get("Description") or "").lower()
            for trigger in ["cobalt strike", "hands-on-keyboard", "amsi bypass",
                            "ransomware", "dll hijack", "suspicious dll load"]:
                if trigger in name or trigger in desc:
                    escalation_triggers.append({
                        "trigger": trigger,
                        "alert":   row.get("AlertName"),
                        "time":    row.get("TimeGenerated"),
                    })

    # ── Step 7: Execution-specific — expand sparse buckets ─────────────────
    expanded_buckets = []
    for bid in ["process_events", "file_events", "registry_events", "device_events"]:
        if bid in buckets and buckets[bid].get("rows", 0) == 0:
            # Expand to P1D
            expand_task = next((t for t in tasks if t["bucket"] == bid), None)
            if expand_task and expand_task.get("type") == "run_query":
                exp_res = la_query(expand_task["kql"], "P1D")
                buckets[f"{bid}_expanded"] = _summarise_bucket(f"{bid}_expanded", exp_res)
                expanded_buckets.append(bid)

    return _ok({
        "incident_id":          incident_id,
        "checklist_used":       cl,
        "checklist_auto":       checklist == "auto",
        # ── Only the distilled facts the agent needs to drive per-entity queries ──
        # Full incident metadata is NOT embedded — caller must use get_incident_report.
        "entities_extracted": {
            "hosts":        hosts,
            "users":        users,
            "ips":          ips,
            "primary_host": safe_host,
            "primary_user": safe_user,
            "primary_ip":   safe_ip,
        },
        "mitre": {
            "tactics":    tactics,
            "techniques": list((inc_data.get("mitre") or {}).get("techniques") or []),
        },
        # ── Telemetry buckets (compact summary format from _summarise_bucket) ──
        "telemetry":            buckets,
        "escalation_triggers":  escalation_triggers,
        "escalation_fired":     bool(escalation_triggers),
        "expanded_buckets":     expanded_buckets,
        "checklist_coverage": {
            t["bucket"]: buckets.get(t["bucket"], {}).get("status", "missing")
            for t in tasks
        },
        # ── Pointer instead of embedding similar_history ──
        "similar_history_available": bool(hist_res.get("ok")),
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def(
    "get_similar_incident_history",
    (
        "Looks up prior Sentinel incidents over the last N days that share the same title as the "
        "target incident. Returns classification history, status breakdown, and owner info for triage. "
        "Useful for determining if an incident is a known false positive or recurring pattern. "
        "Tries exact normalized title match first, falls back to contains match."
    ),
    {
        "incident_id": "Sentinel incident number",
        "days": "optional integer 1–90, default 30",
    },
)

@mcp.tool
def get_similar_incident_history(incident_id: str, days: int = 30) -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        days_i = int(days)
    except Exception:
        days_i = 30

    days_i = max(1, min(days_i, 90))
    safe_id = escape_kql_string(str(incident_id).strip())

    # ── STEP 1: get the reference incident and its title ───────────────────
    current_kql = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project IncidentNumber, IncidentName, Title, Severity, Status, CreatedTime, LastModifiedTime
""".strip()

    current_res = la_query(current_kql, f"P{days_i}D")
    if not current_res.get("ok"):
        return current_res

    current_rows = _la_first_table_dicts(current_res["data"])
    if not current_rows:
        return _fail("Incident not found", code="NOT_FOUND")

    current_incident = current_rows[0]
    title = current_incident.get("Title")

    if not title or not str(title).strip():
        return _fail("Incident title not found", code="PARSE_ERROR")

    normalized_title = str(title).strip().lower()
    safe_title = escape_kql_string(normalized_title)

    _HISTORY_PROJECT = """
| project
    IncidentNumber, IncidentName, Title, Severity, Status,
    Classification, ClassificationReason, ClassificationComment,
    Owner, CreatedTime, LastModifiedTime, ModifiedBy,
    Labels, AdditionalData, Tasks, IncidentUrl
| order by CreatedTime desc
""".strip()

    # ── STEP 2: exact normalized title match ──────────────────────────────
    exact_kql = f"""
SecurityIncident
| where CreatedTime >= ago({days_i}d)
| where Severity !~ "Informational"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| extend NormalizedTitle = tolower(trim(@" ", tostring(Title)))
| where NormalizedTitle == "{safe_title}"
{_HISTORY_PROJECT}
""".strip()

    exact_res = la_query(exact_kql, f"P{days_i}D")
    if not exact_res.get("ok"):
        return exact_res

    exact_incidents = _la_first_table_dicts(exact_res["data"])
    match_mode = "exact_normalized_title"

    # ── STEP 3: fallback to contains match ────────────────────────────────
    if exact_incidents:
        incidents = exact_incidents
    else:
        contains_kql = f"""
SecurityIncident
| where CreatedTime >= ago({days_i}d)
| where Severity !~ "Informational"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| extend NormalizedTitle = tolower(trim(@" ", tostring(Title)))
| where NormalizedTitle contains "{safe_title}"
{_HISTORY_PROJECT}
""".strip()

        contains_res = la_query(contains_kql, f"P{days_i}D")
        if not contains_res.get("ok"):
            return contains_res

        incidents = _la_first_table_dicts(contains_res["data"])
        match_mode = "contains_normalized_title"

    # ── STEP 4: recurrence summary ────────────────────────────────────────
    classification_summary: Dict[str, int] = {}
    status_summary: Dict[str, int] = {}

    for inc in incidents:
        cls = str(inc.get("Classification") or "Unclassified")
        st = str(inc.get("Status") or "Unknown")
        classification_summary[cls] = classification_summary.get(cls, 0) + 1
        status_summary[st] = status_summary.get(st, 0) + 1

    return _ok({
        "reference_incident": {
            "incident_number": current_incident.get("IncidentNumber"),
            "incident_name": current_incident.get("IncidentName"),
            "title": current_incident.get("Title"),
            "severity": current_incident.get("Severity"),
            "status": current_incident.get("Status"),
            "created_time": current_incident.get("CreatedTime"),
            "last_modified_time": current_incident.get("LastModifiedTime"),
        },
        "days_reviewed": days_i,
        "match_mode": match_mode,
        "count": len(incidents),
        "classification_summary": classification_summary,
        "status_summary": status_summary,
        "incidents": incidents,
    })

# ============================================================
# EXPORT ASGI APP
# ============================================================

asgi_app = mcp.http_app(path="/mcp", stateless_http=True)
