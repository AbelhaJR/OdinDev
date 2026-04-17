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
_RETRY_POLICY = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
    raise_on_status=False,
)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "SentinelMCP/1.2"})
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
    """Lazy-load the workspace table catalog on first use."""
    global WORKSPACE_TABLE_CATALOG, _CATALOG_LOADED
    if _CATALOG_LOADED:
        return
    with _CATALOG_LOCK:
        if _CATALOG_LOADED:
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

PARALLEL_WALL_CLOCK_TIMEOUT = int(os.environ.get("PARALLEL_WALL_CLOCK_TIMEOUT", "30"))

MAX_HOURS_RUN_QUERY = 72
MAX_HOURS_ANALYZE_ENTITY = 168
MAX_HOURS_INCIDENT = 168

# ============================================================
# IOC ENRICHMENT CONFIGURATION (VirusTotal + AbuseIPDB)
# ============================================================

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

def _load_vt_api_keys() -> List[str]:
    """
    Load VirusTotal API keys from env. Supports (in priority order):
      1. VIRUSTOTAL_API_KEYS      — comma-separated list
      2. VIRUSTOTAL_API_KEY_1..20 — numbered keys
      3. VIRUSTOTAL_API_KEY       — single key (legacy / back-compat)
    Duplicates removed, order preserved.
    """
    keys: List[str] = []

    multi = os.environ.get("VIRUSTOTAL_API_KEYS", "").strip()
    if multi:
        for k in multi.split(","):
            k = k.strip()
            if k and k not in keys:
                keys.append(k)

    for i in range(1, 21):
        k = os.environ.get(f"VIRUSTOTAL_API_KEY_{i}", "").strip()
        if k and k not in keys:
            keys.append(k)

    legacy = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if legacy and legacy not in keys:
        keys.append(legacy)

    return keys

_VT_API_KEYS: List[str] = _load_vt_api_keys()

# Per-key state for rate-limit tracking
_VT_KEY_STATE: List[Dict[str, Any]] = [
    {"key": k, "index": i, "last_call": 0.0, "cooldown_until": 0.0,
     "calls": 0, "rate_limited": 0}
    for i, k in enumerate(_VT_API_KEYS)
]

_VT_POOL_LOCK = threading.Lock()

def _vt_acquire_key(min_interval: float, max_wait: float = 30.0) -> Optional[Dict[str, Any]]:
    """
    Pick the VT key that will be ready soonest, sleep if needed, stamp last_call.
    Returns the key state dict, or None if the pool is empty.
    """
    if not _VT_KEY_STATE:
        return None

    with _VT_POOL_LOCK:
        def ready_at(s: Dict[str, Any]) -> float:
            return max(s["last_call"] + min_interval, s["cooldown_until"])

        best = min(_VT_KEY_STATE, key=ready_at)
        wait = ready_at(best) - time.time()

        if wait > 0:
            time.sleep(min(wait, max_wait))

        best["last_call"] = time.time()
        best["calls"] += 1
        return best

def _vt_mark_rate_limited(key_state: Dict[str, Any], retry_after_sec: float = 60.0) -> None:
    """Put this key in cooldown after a 429."""
    with _VT_POOL_LOCK:
        key_state["cooldown_until"] = time.time() + retry_after_sec
        key_state["rate_limited"] += 1
    logger.warning("VT key idx=%s rate-limited, cooldown=%.0fs",
                   key_state.get("index"), retry_after_sec)

# Cache TTL in seconds (default 1h)
IOC_CACHE_TTL = int(os.environ.get("IOC_CACHE_TTL", "3600"))

# Max IOCs auto-enriched per checklist run (stay under free-tier rate limits)
IOC_MAX_IPS_PER_INCIDENT     = int(os.environ.get("IOC_MAX_IPS_PER_INCIDENT", "5"))
IOC_MAX_DOMAINS_PER_INCIDENT = int(os.environ.get("IOC_MAX_DOMAINS_PER_INCIDENT", "3"))
IOC_MAX_HASHES_PER_INCIDENT  = int(os.environ.get("IOC_MAX_HASHES_PER_INCIDENT", "3"))

# Thresholds for auto-escalation to risk=High
VT_MALICIOUS_VOTES_THRESHOLD = int(os.environ.get("VT_MALICIOUS_VOTES_THRESHOLD", "5"))
ABUSEIPDB_SCORE_THRESHOLD    = int(os.environ.get("ABUSEIPDB_SCORE_THRESHOLD", "75"))

# Rate limit (approximate — token bucket)
#   VirusTotal free tier: 4 req/min, 500 req/day
#   AbuseIPDB free tier:  1000 req/day, ~1 req/sec
VT_MIN_INTERVAL_SEC        = float(os.environ.get("VT_MIN_INTERVAL_SEC", "16"))      # 60/4 + buffer
ABUSEIPDB_MIN_INTERVAL_SEC = float(os.environ.get("ABUSEIPDB_MIN_INTERVAL_SEC", "1"))

# Per-call timeout for IOC HTTP requests
IOC_HTTP_TIMEOUT = int(os.environ.get("IOC_HTTP_TIMEOUT", "10"))

# ============================================================
# SITE-PREFIX → SITE NAME MAP
# ============================================================
_SITE_PREFIX_MAP: Dict[str, str] = {
    "os":    "OsloBors",
    "obg":   "OsloBors",
    "osdc":  "OsloBors",
    "eun":   "Euronext",
    "eu":    "Euronext",
    "clr":   "Clearing",
    "clear": "Clearing",
    "ib":    "Interbolsa",
    "intb":  "Interbolsa",
    "mts":   "MTS",
    "dk":    "Denmark",
    "dn":    "Denmark",
    "eso":   "ESOslo",
    "cwc":   "CWC",
    "bor":   "Borsa",
    "bita":  "Bita",
    "slp":   "OsloBors",
}

def _detect_site_from_hostname(hostname: str) -> Optional[str]:
    if not hostname:
        return None
    h = hostname.lower().strip()
    if "." in h:
        h = h.split(".")[0]
    m = re.match(r"^([a-z]+)", h)
    if not m:
        return None
    head = m.group(1)
    for plen in range(min(len(head), 6), 1, -1):
        prefix = head[:plen]
        if prefix in _SITE_PREFIX_MAP:
            return _SITE_PREFIX_MAP[prefix]
    return None

def _site_tables_for(site: str) -> List[str]:
    if not site:
        return []
    _ensure_catalog_loaded()
    out = []
    for tables in WORKSPACE_TABLE_CATALOG.values():
        for t in tables:
            if site.lower() in t.lower() and t.endswith("_CL"):
                out.append(t)
    return out

# ============================================================
# RESPONSE HELPERS
# ============================================================

def _ok(data: Any, **meta) -> dict:
    out = {"ok": True, "data": data}
    if meta:
        out["meta"] = meta
    return out

def _fail(message: str, *, code: Optional[str] = None, status_code: Optional[int] = None,
          detail: Optional[str] = None, **meta) -> dict:
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
# MANAGED IDENTITY
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

def _normalize_entity_value(value: str) -> str:
    if not value:
        return value
    v = str(value).strip()
    m = re.fullmatch(r'\[\s*["\']?([^"\'\]]+)["\']?\s*\]', v)
    if m:
        v = m.group(1).strip()
    v = v.strip('"\'')
    return v

# ── NEW: flatten MITRE technique strings that may be double-JSON-encoded ─
def _flatten_mitre_field(raw_values) -> List[str]:
    """
    Sentinel sometimes returns Tactics/Techniques as:
      - a plain string "T1110"
      - a JSON-encoded list string like "[\"T1110\",\"T1078\"]"
      - a comma-separated string "T1110, T1078"
      - an already-parsed list ["T1110"]
    This flattens all cases into a clean sorted list.
    """
    out = set()
    for v in raw_values or []:
        if v is None:
            continue
        if isinstance(v, list):
            for x in v:
                if x:
                    out.add(str(x).strip())
            continue
        s = str(v).strip()
        if not s:
            continue
        if s.startswith("["):
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    for x in parsed:
                        if x:
                            out.add(str(x).strip())
                    continue
            except Exception:
                pass
        if "," in s:
            for part in s.split(","):
                p = part.strip().strip('"').strip("'")
                if p:
                    out.add(p)
            continue
        out.add(s)
    return sorted(out)

def detect_entity_type(value: str) -> str:
    v = _normalize_entity_value(value).strip()
    if not v:
        return "host"

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

    lowered = v.lower()

    if (lowered.endswith(".svc")
        or lowered.endswith("$")
        or lowered.startswith("svc-") or lowered.startswith("svc_")
        or "-svc-" in lowered or "_svc_" in lowered
        or re.search(r"\bservice\b", lowered)
        or re.search(r"\bsvc\b", lowered)):
        return "user"

    if "." in v:
        last_segment = lowered.split(".")[-1]
        if last_segment.isalpha() and 2 <= len(last_segment) <= 24:
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
            "alerts_and_incidents", "identity_and_authentication",
            "endpoint_microsoft_defender", "network_security_devices",
            "network_and_proxy", "cmdb_and_asset_context",
        ],
        "user": [
            "alerts_and_incidents", "identity_and_authentication",
            "endpoint_microsoft_defender", "email_and_m365",
            "identity_governance_and_pam", "security_and_behavior_analytics",
        ],
        "host": [
            "alerts_and_incidents", "endpoint_microsoft_defender",
            "windows_servers", "linux_servers",
            "cmdb_and_asset_context", "security_and_behavior_analytics",
        ],
        "domain": [
            "alerts_and_incidents", "network_and_proxy",
            "dns_and_ip_management", "email_and_m365",
            "security_and_behavior_analytics",
        ],
        "sha256": [
            "alerts_and_incidents", "endpoint_microsoft_defender",
            "security_and_behavior_analytics", "email_and_m365",
        ],
        "sha1": [
            "alerts_and_incidents", "endpoint_microsoft_defender",
            "security_and_behavior_analytics", "email_and_m365",
        ],
        "md5": [
            "alerts_and_incidents", "endpoint_microsoft_defender",
            "security_and_behavior_analytics", "email_and_m365",
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

def _query_cmdb_entity(value: str, timespan: str = "P90D") -> dict:
    safe_value = escape_kql_string(value)
    core = safe_value.split(".")[0] if "." in safe_value else safe_value

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
    if res.get("ok") and _la_first_table_dicts(res["data"]):
        return res

    if core != safe_value:
        core_kql = f"""
{CMDB_TABLE}
| where
    tostring(Key) contains "{core}"
    or tostring(FQDN) contains "{core}"
    or tostring(logsource) contains "{core}"
    or tostring(Management_IP) contains "{core}"
    or tostring(ApplicationAndComponentInstance) contains "{core}"
| project
    Key, Management_IP, ApplicationAndComponentInstance,
    Network_Interfaces, Updated, Scanning_Information,
    BusinessEntity, FQDN, PSNC, logsource
| take 20
""".strip()
        res2 = la_query(core_kql, timespan)
        if res2.get("ok") and _la_first_table_dicts(res2["data"]):
            return res2

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
        return _fail("Failed to acquire Managed Identity token",
                     code="MANAGED_IDENTITY_ERROR", detail=str(e))

    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    start = time.time()

    try:
        response = SESSION.post(
            url,
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            json={"query": kql, "timespan": timespan},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
    except Exception as e:
        return _fail("HTTP request to Log Analytics failed",
                     code="HTTP_ERROR", detail=str(e), timespan=timespan)

    elapsed_ms = int((time.time() - start) * 1000)

    if not response.ok:
        logger.warning("Log Analytics query failed status=%s duration_ms=%s",
                       response.status_code, elapsed_ms)
        return _fail("Log Analytics query failed", code="LOG_ANALYTICS_ERROR",
                     status_code=response.status_code, detail=response.text,
                     timespan=timespan)

    try:
        payload = response.json()
        logger.info("Log Analytics query ok duration_ms=%s timespan=%s",
                    elapsed_ms, timespan)
        return _ok(payload, timespan=timespan, duration_ms=elapsed_ms)
    except Exception as e:
        return _fail("Failed to parse Log Analytics JSON response",
                     code="PARSE_ERROR", detail=str(e), timespan=timespan)

def _arm_get(url: str) -> dict:
    try:
        token = get_managed_identity_token(ARM_RESOURCE)
    except Exception as e:
        return _fail("Failed to acquire ARM token", code="MANAGED_IDENTITY_ERROR", detail=str(e))

    start = time.time()

    try:
        resp = SESSION.get(url, headers={"Authorization": f"Bearer {token}"},
                           timeout=HTTP_TIMEOUT_SECONDS)
    except Exception as e:
        return _fail("HTTP request to ARM failed", code="HTTP_ERROR", detail=str(e))

    elapsed_ms = int((time.time() - start) * 1000)

    if not resp.ok:
        logger.warning("ARM request failed status=%s duration_ms=%s",
                       resp.status_code, elapsed_ms)
        return _fail("ARM request failed", code="ARM_ERROR",
                     status_code=resp.status_code, detail=resp.text)

    try:
        payload = resp.json()
        logger.info("ARM request ok duration_ms=%s", elapsed_ms)
        return _ok(payload, duration_ms=elapsed_ms)
    except Exception as e:
        return _fail("Failed to parse ARM JSON response", code="PARSE_ERROR", detail=str(e))

def _arm_get_paged(url: str) -> dict:
    all_items = []
    url = url

    while url:
        res = _arm_get(url)
        if not res.get("ok"):
            return res
        data = res["data"]
        all_items.extend(data.get("value") or [])
        url = data.get("nextLink")

    return _ok({"value": all_items})

# ============================================================
# PARALLEL QUERY HELPER
# ============================================================

def _run_queries_parallel(
    tasks: List[Tuple[str, str, str]],
    timespan: str,
    wall_clock_timeout: int = PARALLEL_WALL_CLOCK_TIMEOUT,
) -> Dict[str, dict]:
    results: Dict[str, dict] = {}

    def _run(task_id: str, kql: str) -> Tuple[str, dict]:
        return task_id, la_query(kql, timespan)

    if not tasks:
        return results

    with ThreadPoolExecutor(max_workers=min(len(tasks), 8)) as executor:
        futures = {
            executor.submit(_run, task_id, kql): task_id
            for task_id, _table, kql in tasks
        }
        deadline = time.time() + wall_clock_timeout

        try:
            for future in as_completed(futures, timeout=max(1, deadline - time.time())):
                try:
                    task_id, result = future.result(timeout=1)
                    results[task_id] = result
                except Exception as e:
                    task_id = futures[future]
                    results[task_id] = _fail(
                        "Query task failed or timed out",
                        code="TASK_ERROR", detail=str(e))
        except FuturesTimeoutError:
            pass

    for _task_id, table, _kql in tasks:
        if _task_id not in results:
            results[_task_id] = _fail(
                f"Query timed out after {wall_clock_timeout}s",
                code="TIMEOUT", detail=f"table={table}")

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
# IOC ENRICHMENT — VirusTotal + AbuseIPDB
# ============================================================
#
# Provider routing (VT free-tier quota conservation):
#   VirusTotal   — domain, URL, hash (sha256/sha1/md5)   [IPs intentionally excluded]
#   AbuseIPDB    — IP only                               [sole IP reputation source]
#
# Rationale: VirusTotal free tier caps at 4 req/min / 500 req/day. IPs are the
# highest-volume IOC surfaced from Sentinel telemetry (SigninLogs, DeviceNetworkEvents,
# CallerIpAddress, etc.), so sending them exclusively to AbuseIPDB — which allows
# 1000 req/day and is arguably the better IP reputation source anyway — preserves
# VT budget for domains, URLs, and file hashes that AbuseIPDB cannot score.
#
# Thread-safe cache keyed by (provider, normalized_ioc).
# Simple token-bucket rate limit per provider to respect free tiers.
#
# Required env vars:
#   VIRUSTOTAL_API_KEY (or VIRUSTOTAL_API_KEYS / VIRUSTOTAL_API_KEY_1..20)
#   ABUSEIPDB_API_KEY
#
# Optional env vars (see CONFIGURATION):
#   IOC_CACHE_TTL, VT_MIN_INTERVAL_SEC, ABUSEIPDB_MIN_INTERVAL_SEC,
#   VT_MALICIOUS_VOTES_THRESHOLD, ABUSEIPDB_SCORE_THRESHOLD

_IOC_CACHE: Dict[str, Dict[str, Any]] = {}
_IOC_CACHE_LOCK = threading.Lock()

_IOC_RATE_LOCK = threading.Lock()
_IOC_LAST_CALL: Dict[str, float] = {"virustotal": 0.0, "abuseipdb": 0.0}

def _ioc_cache_get(key: str) -> Optional[dict]:
    now = time.time()
    with _IOC_CACHE_LOCK:
        entry = _IOC_CACHE.get(key)
        if entry and entry.get("exp", 0) > now:
            return entry["value"]
        if entry:
            _IOC_CACHE.pop(key, None)
    return None

def _ioc_cache_set(key: str, value: dict) -> None:
    with _IOC_CACHE_LOCK:
        _IOC_CACHE[key] = {"value": value, "exp": time.time() + IOC_CACHE_TTL}

def _ioc_rate_wait(provider: str, min_interval: float) -> None:
    """Enforce a minimum inter-call gap per provider (token bucket)."""
    with _IOC_RATE_LOCK:
        now = time.time()
        last = _IOC_LAST_CALL.get(provider, 0.0)
        wait = (last + min_interval) - now
        if wait > 0:
            time.sleep(min(wait, 30))  # never sleep more than 30s
        _IOC_LAST_CALL[provider] = time.time()

def _detect_ioc_type(value: str) -> str:
    """Classify an IOC string for routing to the right API endpoint."""
    v = _normalize_entity_value(value).strip()
    if not v:
        return "unknown"
    # IP
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        try:
            if all(0 <= int(p) <= 255 for p in v.split(".")):
                return "ip"
        except Exception:
            pass
    # File hashes
    if re.fullmatch(r"[a-fA-F0-9]{64}", v):
        return "sha256"
    if re.fullmatch(r"[a-fA-F0-9]{40}", v):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{32}", v):
        return "md5"
    # URL
    if v.lower().startswith(("http://", "https://")):
        return "url"
    # Domain (has a dot and alpha TLD)
    if "." in v:
        tld = v.lower().split(".")[-1]
        if tld.isalpha() and 2 <= len(tld) <= 24:
            return "domain"
    return "unknown"

# ── VirusTotal ────────────────────────────────────────────────────────
def _vt_parse_analysis(attributes: dict) -> dict:
    """Extract the fields we care about from a VT /attributes block."""
    stats = attributes.get("last_analysis_stats") or {}
    votes = attributes.get("total_votes") or {}
    return {
        "malicious_engines":  int(stats.get("malicious") or 0),
        "suspicious_engines": int(stats.get("suspicious") or 0),
        "harmless_engines":   int(stats.get("harmless") or 0),
        "undetected_engines": int(stats.get("undetected") or 0),
        "community_malicious_votes": int(votes.get("malicious") or 0),
        "community_harmless_votes":  int(votes.get("harmless") or 0),
        "reputation":         attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "first_seen":         attributes.get("first_submission_date") or attributes.get("creation_date"),
        "tags":               attributes.get("tags") or [],
        "categories":         attributes.get("categories") or {},
        "as_owner":           attributes.get("as_owner"),
        "asn":                attributes.get("asn"),
        "country":            attributes.get("country"),
        "network":            attributes.get("network"),
        "meaningful_name":    attributes.get("meaningful_name"),
        "type_description":   attributes.get("type_description"),
    }


def _enrich_virustotal(value: str, ioc_type: str) -> dict:
    """
    Query VirusTotal for domain, URL, or hash — with automatic key rotation.
    IPs are NOT sent to VirusTotal (routed to AbuseIPDB instead — see _enrich_ioc).
    On 429, marks the current key as cooling down and retries with the next one.
    """
    if not _VT_API_KEYS:
        return {"ok": False, "error": "No VirusTotal API keys configured",
                "skipped": True}

    cache_key = f"vt:{ioc_type}:{value.lower()}"
    cached = _ioc_cache_get(cache_key)
    if cached is not None:
        return {"ok": True, "data": cached, "cached": True}

    # Map IOC type → VT URL path
    # Note: "ip" is intentionally absent — IPs go to AbuseIPDB only.
    if ioc_type == "domain":
        path = f"domains/{value}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        path = f"urls/{url_id}"
    elif ioc_type in ("sha256", "sha1", "md5"):
        path = f"files/{value}"
    else:
        return {"ok": False, "error": f"Unsupported IOC type for VT: {ioc_type}"}

    # Retry across up to min(pool_size, 3) keys on rate-limit / transient error
    last_error = None
    max_attempts = min(len(_VT_API_KEYS), 3)

    for attempt in range(max_attempts):
        key_state = _vt_acquire_key(VT_MIN_INTERVAL_SEC)
        if not key_state:
            return {"ok": False, "error": "No VT keys available"}

        try:
            resp = SESSION.get(
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": key_state["key"],
                         "Accept": "application/json"},
                timeout=IOC_HTTP_TIMEOUT,
            )
        except Exception as e:
            last_error = f"HTTP error on key idx={key_state['index']}: {e}"
            continue

        # 429 → cooldown this key, try the next
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            try:
                cooldown = float(retry_after) if retry_after else 60.0
            except ValueError:
                cooldown = 60.0
            _vt_mark_rate_limited(key_state, cooldown)
            last_error = f"429 on key idx={key_state['index']}, rotating"
            continue

        if resp.status_code == 401:
            return {"ok": False,
                    "error": f"VirusTotal auth failed on key idx={key_state['index']}"}

        if resp.status_code == 404:
            result = {
                "provider": "virustotal",
                "ioc": value,
                "ioc_type": ioc_type,
                "status": "not_found",
                "summary": "Not seen by VirusTotal",
            }
            _ioc_cache_set(cache_key, result)
            return {"ok": True, "data": result}

        if not resp.ok:
            return {"ok": False,
                    "error": f"VirusTotal HTTP {resp.status_code}: {resp.text[:200]}"}

        # Success
        try:
            payload = resp.json()
        except Exception as e:
            return {"ok": False, "error": f"VT JSON parse error: {e}"}

        attrs = (payload.get("data") or {}).get("attributes") or {}
        analysis = _vt_parse_analysis(attrs)
        malicious = analysis["malicious_engines"]

        result = {
            "provider": "virustotal",
            "ioc": value,
            "ioc_type": ioc_type,
            "status": "found",
            "malicious_engines":  malicious,
            "suspicious_engines": analysis["suspicious_engines"],
            "harmless_engines":   analysis["harmless_engines"],
            "community_malicious_votes": analysis["community_malicious_votes"],
            "reputation":         analysis["reputation"],
            "last_analysis_date": analysis["last_analysis_date"],
            "first_seen":         analysis["first_seen"],
            "tags":               analysis["tags"],
            "categories":         analysis["categories"],
            "as_owner":           analysis["as_owner"],
            "asn":                analysis["asn"],
            "country":            analysis["country"],
            "meaningful_name":    analysis["meaningful_name"],
            "type_description":   analysis["type_description"],
            "verdict": ("malicious" if malicious >= VT_MALICIOUS_VOTES_THRESHOLD
                        else "suspicious" if malicious > 0 or analysis["suspicious_engines"] > 0
                        else "clean"),
            "gui_link": f"https://www.virustotal.com/gui/{ioc_type}/{value}",
        }
        _ioc_cache_set(cache_key, result)
        return {"ok": True, "data": result}

    return {"ok": False, "error": last_error or "All VT keys exhausted"}

# ── AbuseIPDB ─────────────────────────────────────────────────────────

def _enrich_abuseipdb(ip: str) -> dict:
    """Query AbuseIPDB for an IP address. Sole provider for IP IOCs."""
    if not ABUSEIPDB_API_KEY:
        return {"ok": False, "error": "ABUSEIPDB_API_KEY not configured",
                "skipped": True}

    cache_key = f"abuseipdb:ip:{ip}"
    cached = _ioc_cache_get(cache_key)
    if cached is not None:
        return {"ok": True, "data": cached, "cached": True}

    _ioc_rate_wait("abuseipdb", ABUSEIPDB_MIN_INTERVAL_SEC)

    try:
        resp = SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            timeout=IOC_HTTP_TIMEOUT,
        )
    except Exception as e:
        return {"ok": False, "error": f"HTTP error: {e}"}

    if resp.status_code == 429:
        return {"ok": False, "error": "AbuseIPDB rate limit hit (429)"}

    if resp.status_code in (401, 403):
        return {"ok": False, "error": "AbuseIPDB auth failed (check API key)"}

    if not resp.ok:
        return {"ok": False, "error": f"AbuseIPDB HTTP {resp.status_code}: {resp.text[:200]}"}

    try:
        d = (resp.json() or {}).get("data") or {}
    except Exception as e:
        return {"ok": False, "error": f"AbuseIPDB JSON parse error: {e}"}

    score = int(d.get("abuseConfidenceScore") or 0)
    result = {
        "provider": "abuseipdb",
        "ioc": ip,
        "ioc_type": "ip",
        "status": "found",
        "abuse_confidence_score": score,
        "total_reports":   d.get("totalReports"),
        "num_distinct_users": d.get("numDistinctUsers"),
        "last_reported_at": d.get("lastReportedAt"),
        "country_code":    d.get("countryCode"),
        "country_name":    d.get("countryName"),
        "usage_type":      d.get("usageType"),
        "isp":             d.get("isp"),
        "domain":          d.get("domain"),
        "is_tor":          d.get("isTor"),
        "is_whitelisted":  d.get("isWhitelisted"),
        "verdict":         ("malicious" if score >= ABUSEIPDB_SCORE_THRESHOLD
                            else "suspicious" if score >= 25
                            else "clean"),
        "gui_link":        f"https://www.abuseipdb.com/check/{ip}",
    }

    _ioc_cache_set(cache_key, result)
    return {"ok": True, "data": result}

# ── Combined enrichment ───────────────────────────────────────────────

def _enrich_ioc(value: str, value_type: Optional[str] = None) -> dict:
    """
    Run the appropriate IOC provider(s) for a given value.

    Provider routing:
      • IPs        → AbuseIPDB only (VT quota conservation)
      • Everything → VirusTotal only (domains/URLs/hashes)

    Returns:
      {
        "ioc": "...",
        "ioc_type": "ip" | "domain" | "sha256" | ...,
        "virustotal": {...} | null,
        "abuseipdb":  {...} | null,
        "verdict":    "malicious" | "suspicious" | "clean" | "unknown",
        "escalate":   true | false
      }
    """
    value = _normalize_entity_value(value)
    if not value:
        return {"ok": False, "error": "empty value"}

    ioc_type = (value_type or "").strip().lower() or _detect_ioc_type(value)

    if ioc_type == "unknown":
        return {"ok": False, "error": f"Could not detect IOC type for: {value}"}

    result = {
        "ioc": value,
        "ioc_type": ioc_type,
        "virustotal": None,
        "abuseipdb":  None,
        "verdict":    "unknown",
        "escalate":   False,
    }

    # ── Provider routing ────────────────────────────────────────────
    # IPs go to AbuseIPDB ONLY. Everything else goes to VirusTotal ONLY.
    # This conserves VT's scarce free-tier quota (4/min, 500/day) by
    # offloading the high-volume IP traffic to AbuseIPDB (1000/day).
    if ioc_type == "ip":
        # Mark VT as skipped-by-design so the client can see it wasn't an error.
        result["virustotal"] = {
            "provider": "virustotal",
            "status":   "skipped",
            "reason":   "IP routed to AbuseIPDB only (VT quota conservation)",
        }
        ab_res = _enrich_abuseipdb(value)
        if ab_res.get("ok"):
            result["abuseipdb"] = ab_res["data"]
        else:
            result["abuseipdb"] = {
                "provider": "abuseipdb",
                "status":   "error",
                "error":    ab_res.get("error"),
                "skipped":  ab_res.get("skipped", False),
            }
    else:
        # Non-IP IOCs: VirusTotal only (AbuseIPDB can't score domains/URLs/hashes).
        vt_res = _enrich_virustotal(value, ioc_type)
        if vt_res.get("ok"):
            result["virustotal"] = vt_res["data"]
        else:
            result["virustotal"] = {
                "provider": "virustotal",
                "status":   "error",
                "error":    vt_res.get("error"),
                "skipped":  vt_res.get("skipped", False),
            }

    # ── Aggregate verdict ──────────────────────────────────────────
    vt = result["virustotal"] if isinstance(result["virustotal"], dict) else {}
    ab = result["abuseipdb"]  if isinstance(result["abuseipdb"], dict) else {}

    vt_malicious  = int(vt.get("malicious_engines") or 0)
    vt_suspicious = int(vt.get("suspicious_engines") or 0)
    ab_score      = int(ab.get("abuse_confidence_score") or 0)

    if (vt_malicious >= VT_MALICIOUS_VOTES_THRESHOLD
            or ab_score >= ABUSEIPDB_SCORE_THRESHOLD):
        result["verdict"]  = "malicious"
        result["escalate"] = True
    elif vt_malicious > 0 or vt_suspicious > 0 or ab_score >= 25:
        result["verdict"] = "suspicious"
    elif vt.get("status") == "found" or ab.get("status") == "found":
        result["verdict"] = "clean"
    else:
        result["verdict"] = "unknown"

    return {"ok": True, "data": result}

def _enrich_iocs_parallel(iocs: List[Tuple[str, str]],
                          max_workers: int = 4) -> Dict[str, dict]:
    """
    Enrich a list of (value, ioc_type) tuples in parallel.
    Returns dict keyed by ioc value.
    Rate limits are still enforced inside each enrichment call, so parallel
    execution doesn't bypass provider caps — it just reduces idle time on
    cache hits.
    """
    results: Dict[str, dict] = {}
    if not iocs:
        return results

    def _one(item):
        val, vt_type = item
        res = _enrich_ioc(val, vt_type)
        return val, res

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, 4))) as ex:
        futures = {ex.submit(_one, it): it[0] for it in iocs}
        for fut in as_completed(futures):
            try:
                key, res = fut.result(timeout=IOC_HTTP_TIMEOUT * 4)
                results[key] = res
            except Exception as e:
                key = futures[fut]
                results[key] = {"ok": False, "error": str(e)}
    return results

# ============================================================
# TOOLS — diagnostics
# ============================================================

_register_tool_def("get_tools",
    ("Returns the full list of available MCP tools with their parameter formats. "
     "Call this first if you are unsure which tool to use for a task."), {})

@mcp.tool
def get_tools() -> dict:
    return _ok({"tools": _TOOL_DEFS, "mcp_path": "/mcp"})

_register_tool_def("ping",
    ("Connectivity and configuration health check. Does not query Sentinel. "
     "Use this to verify the MCP endpoint is reachable and the workspace is configured."), {})

@mcp.tool
def ping() -> dict:
    return _ok({
        "message": "pong",
        "workspace_configured": bool(WORKSPACE_ID),
        "catalog_loaded": bool((_ensure_catalog_loaded(), WORKSPACE_TABLE_CATALOG)[1]),
        "mcp_path": "/mcp",
    })

_register_tool_def("debug_identity",
    "Shows whether managed identity environment variables are present.", {})

@mcp.tool
def debug_identity() -> dict:
    return _ok({
        "IDENTITY_ENDPOINT_present": bool(os.environ.get("IDENTITY_ENDPOINT")),
        "IDENTITY_HEADER_present": bool(os.environ.get("IDENTITY_HEADER")),
        "MSI_ENDPOINT_present": bool(os.environ.get("MSI_ENDPOINT")),
        "MSI_SECRET_present": bool(os.environ.get("MSI_SECRET")),
        "MANAGED_IDENTITY_CLIENT_ID_present": bool(os.environ.get("MANAGED_IDENTITY_CLIENT_ID")),
    })

_register_tool_def("get_workspace_table_catalog",
    "Returns all workspace tables grouped by telemetry domain.", {})

@mcp.tool
def get_workspace_table_catalog() -> dict:
    _ensure_catalog_loaded()
    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded", code="CATALOG_NOT_LOADED")
    return _ok({"catalog": WORKSPACE_TABLE_CATALOG})

_register_tool_def("debug_catalog_loaded",
    "Returns whether the workspace catalog JSON loaded successfully and which domain keys are present.", {})

@mcp.tool
def debug_catalog_loaded() -> dict:
    _ensure_catalog_loaded()
    return _ok({
        "loaded": bool(WORKSPACE_TABLE_CATALOG),
        "keys": list(WORKSPACE_TABLE_CATALOG.keys()),
    })

_register_tool_def("list_workspace_tables",
    "Returns a flat list of all unique table names from the workspace catalog.", {})

@mcp.tool
def list_workspace_tables() -> dict:
    _ensure_catalog_loaded()
    if not WORKSPACE_TABLE_CATALOG:
        return _fail("Workspace table catalog not loaded", code="CATALOG_NOT_LOADED")
    return _ok({"tables": _flatten_catalog_tables()})

_register_tool_def("list_tables",
    "Lists tables that actively ingested data within the given timespan by querying the Usage table.",
    {"timespan": "ISO8601 duration like P1D, PT6H, PT24H"})

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
        return _fail("Unexpected response shape: DataType column not present",
                     code="PARSE_ERROR", timespan=timespan)

    idx = columns.index("DataType")
    return _ok({"tables": [row[idx] for row in rows]}, timespan=timespan)

_register_tool_def("preview_table",
    "Returns 10 sample rows from the specified table.",
    {"table": "Table name string", "timespan": "ISO8601 duration"})

@mcp.tool
def preview_table(table: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        table = validate_table_name(table)
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    kql = f"{table} | take 10"
    return la_query(kql, timespan)

_register_tool_def("get_table_schema",
    "Returns the column names and data types for the specified table using KQL getschema.",
    {"table": "Table name string", "timespan": "ISO8601 duration"})

@mcp.tool
def get_table_schema(table: str, timespan: str = DEFAULT_TIMESPAN) -> dict:
    try:
        table = validate_table_name(table)
        _ = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid input", code="VALIDATION_ERROR", detail=str(e))

    kql = f"{table} | getschema"
    return la_query(kql, timespan)

_register_tool_def("run_query",
    ("Runs a custom bounded KQL query against the Sentinel workspace. "
     "Query MUST contain at least one where clause. Max timespan 72h (P3D), max rows 200. "
     "NOTE: The 72h cap applies ONLY to run_query — analyze_entity, investigate_incident, "
     "and run_investigation_checklist support up to 168h."),
    {"kql": "KQL string — must include at least one where clause",
     "timespan": "ISO8601 duration, max PT72H / P3D",
     "max_rows": "integer 1–200, default 50"})

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
            f"Timespan exceeds allowed window ({MAX_HOURS_RUN_QUERY}h max for run_query)",
            code="VALIDATION_ERROR", detail=f"got {hours}h")

    bounded_kql = ensure_take_limit(kql, clamp_rows(max_rows))
    return la_query(bounded_kql, timespan)

_register_tool_def("get_recent_alerts",
    "Returns recent Microsoft Sentinel security alerts filtered by severity and timespan.",
    {"timespan": "ISO8601 duration like P1D, PT6H",
     "severity": "optional: High | Medium | Low | Informational",
     "max_rows": "integer 1–200, default 50"})

@mcp.tool
def get_recent_alerts(timespan: str = "P1D", severity: Optional[str] = None,
                      max_rows: int = DEFAULT_ROWS) -> dict:
    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)",
                     code="VALIDATION_ERROR")

    severity_filter = ""
    if severity:
        valid_severities = {"high", "medium", "low", "informational"}
        if severity.lower() not in valid_severities:
            return _fail(f"Invalid severity. Must be one of: {', '.join(valid_severities)}",
                         code="VALIDATION_ERROR")
        safe_sev = escape_kql_string(severity)
        severity_filter = f'| where AlertSeverity =~ "{safe_sev}"'

    limit = clamp_rows(max_rows)
    kql = f"""
SecurityAlert
| where TimeGenerated >= ago({int(hours)}h)
{severity_filter}
| project TimeGenerated, AlertName, AlertSeverity, Status, CompromisedEntity,
  Tactics, Techniques, SystemAlertId, ProductName, Description
| order by TimeGenerated desc
| take {limit}
""".strip()

    return la_query(kql, timespan)

_register_tool_def("list_analytics_rules",
    "Lists Microsoft Sentinel analytics rules.",
    {"top": "optional int, max rules to return (default 50, hard cap 200)"})

@mcp.tool
def list_analytics_rules(top: int = 50) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
                     code="CONFIG_ERROR")

    try:
        top_i = int(top)
    except Exception:
        top_i = 50
    top_i = max(1, min(top_i, 200))

    base = _sentinel_rules_base_url()
    url = f"{base}?api-version=2023-09-01-preview"

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

_register_tool_def("analyze_use_case",
    ("Fetches a Sentinel analytic rule by rule_id or rule_name and extracts documentation-ready "
     "key points."),
    {"rule_id": "optional: analytic rule ARM resource name/GUID",
     "rule_name": "optional: displayName exact match (case-insensitive)"})

@mcp.tool
def analyze_use_case(rule_id: Optional[str] = None, rule_name: Optional[str] = None) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
                     code="CONFIG_ERROR")

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

_register_tool_def("generate_confluence_use_case",
    "Generates a Confluence-ready HTML documentation page for a Sentinel analytic rule.",
    {"rule_id": "optional: analytic rule ARM resource name/GUID",
     "rule_name": "optional: displayName exact match (case-insensitive)"})

@mcp.tool
def generate_confluence_use_case(rule_id: Optional[str] = None,
                                  rule_name: Optional[str] = None) -> dict:
    if not SUBSCRIPTION_ID or not RESOURCE_GROUP or not WORKSPACE_NAME:
        return _fail("SUBSCRIPTION_ID, RESOURCE_GROUP, WORKSPACE_NAME not configured",
                     code="CONFIG_ERROR")

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

# ============================================================
# analyze_entity
# ============================================================

_register_tool_def("analyze_entity",
    ("SOC-style entity investigation across workspace tables. "
     "Auto-detects entity type (ip, user/UPN/service-account, host, domain, sha256/sha1/md5). "
     "Returns per-table event counts, first/last seen times, risk level, and CMDB context."),
    {"value": "Entity string",
     "timespan": "ISO8601 duration (PT6H, P1D, P7D)",
     "max_rows": "integer 1–200 (default 50)"})

@mcp.tool
def analyze_entity(value: str, timespan: str = DEFAULT_TIMESPAN, max_rows: int = DEFAULT_ROWS) -> dict:
    if not value:
        return _fail("value is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_ANALYZE_ENTITY:
        return _fail(f"Timespan exceeds allowed window ({MAX_HOURS_ANALYZE_ENTITY}h max)",
                     code="VALIDATION_ERROR", detail=f"got {hours}h")

    raw_value = value
    value = _normalize_entity_value(value)
    entity_type = detect_entity_type(value)
    safe_value = escape_kql_string(value)
    max_rows = clamp_rows(max_rows)

    preferred_domains = _catalog_domains_for_entity(entity_type)

    _ensure_catalog_loaded()

    host_core = safe_value.split(".")[0] if "." in safe_value else safe_value

    table_map = {
        "ip": [
            ("SigninLogs",                    f'IPAddress == "{safe_value}"'),
            ("SecurityAlert",                 f'CompromisedEntity contains "{safe_value}" or tostring(Entities) contains "{safe_value}"'),
            ("AzureActivity",                 f'CallerIpAddress == "{safe_value}"'),
            ("DeviceNetworkEvents",           f'RemoteIP == "{safe_value}" or LocalIP == "{safe_value}"'),
            ("OfficeActivity",                f'ClientIP == "{safe_value}" or Client_IPAddress contains "{safe_value}"'),
            ("AADServicePrincipalSignInLogs", f'IPAddress == "{safe_value}"'),
            ("AADManagedIdentitySignInLogs",  f'IPAddress == "{safe_value}"'),
            ("ThreatIntelIndicators",         f'NetworkIP == "{safe_value}" or NetworkSourceIP == "{safe_value}"'),
            ("EmailEvents",                   f'SenderIPv4 == "{safe_value}" or SenderIPv6 == "{safe_value}"'),
        ],
        "user": [
            ("SigninLogs",              f'UserPrincipalName =~ "{safe_value}" or AlternateSignInName =~ "{safe_value}"'),
            ("SecurityEvent",           f'Account =~ "{safe_value}" or TargetAccount =~ "{safe_value}" or SubjectAccount =~ "{safe_value}"'),
            ("AuditLogs",               f'tostring(InitiatedBy.user.userPrincipalName) =~ "{safe_value}" or tostring(TargetResources) contains "{safe_value}"'),
            ("DeviceLogonEvents",       f'AccountName =~ "{safe_value}" or InitiatingProcessAccountUpn =~ "{safe_value}" or InitiatingProcessAccountName =~ "{safe_value}"'),
            ("IdentityLogonEvents",     f'AccountName =~ "{safe_value}" or AccountUpn =~ "{safe_value}"'),
            ("IdentityDirectoryEvents", f'AccountName =~ "{safe_value}" or tostring(AdditionalFields) contains "{safe_value}"'),
            ("BehaviorAnalytics",       f'UserName =~ "{safe_value}" or UserPrincipalName =~ "{safe_value}"'),
            ("OfficeActivity",          f'UserId =~ "{safe_value}"'),
            ("AADRiskyUsers",           f'UserPrincipalName =~ "{safe_value}"'),
            ("AADUserRiskEvents",       f'UserPrincipalName =~ "{safe_value}"'),
            ("SecurityAlert",           f'tostring(Entities) contains "{safe_value}" or CompromisedEntity contains "{safe_value}"'),
            ("EmailEvents",             f'RecipientEmailAddress =~ "{safe_value}" or SenderFromAddress =~ "{safe_value}"'),
        ],
        "host": [
            ("DeviceInfo",            f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("DeviceEvents",          f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("DeviceProcessEvents",   f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("DeviceNetworkEvents",   f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("DeviceFileEvents",      f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("DeviceLogonEvents",     f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("DeviceRegistryEvents",  f'DeviceName =~ "{safe_value}" or DeviceName startswith "{host_core}"'),
            ("BehaviorAnalytics",     f'DeviceName =~ "{safe_value}" or SourceDevice =~ "{safe_value}"'),
            ("SecurityAlert",         f'CompromisedEntity contains "{safe_value}" or tostring(Entities) contains "{safe_value}"'),
            ("Heartbeat",             f'Computer =~ "{safe_value}" or Computer startswith "{host_core}"'),
        ],
        "domain": [
            ("DeviceNetworkEvents",   f'RemoteUrl contains "{safe_value}"'),
            ("UrlClickEvents",        f'Url contains "{safe_value}"'),
            ("EmailUrlInfo",          f'Url contains "{safe_value}" or UrlDomain contains "{safe_value}"'),
            ("ThreatIntelIndicators", f'DomainName contains "{safe_value}" or Url contains "{safe_value}"'),
            ("SecurityAlert",         f'tostring(Entities) contains "{safe_value}"'),
        ],
        "sha256": [
            ("DeviceFileEvents",      f'SHA256 == "{safe_value}"'),
            ("DeviceProcessEvents",   f'SHA256 == "{safe_value}"'),
            ("EmailAttachmentInfo",   f'SHA256 == "{safe_value}"'),
            ("ThreatIntelIndicators", f'FileHashValue == "{safe_value}"'),
            ("SecurityAlert",         f'tostring(Entities) contains "{safe_value}"'),
        ],
        "sha1": [
            ("DeviceFileEvents",      f'SHA1 == "{safe_value}"'),
            ("DeviceProcessEvents",   f'SHA1 == "{safe_value}"'),
            ("EmailAttachmentInfo",   f'SHA1 == "{safe_value}"'),
            ("ThreatIntelIndicators", f'FileHashValue == "{safe_value}"'),
            ("SecurityAlert",         f'tostring(Entities) contains "{safe_value}"'),
        ],
        "md5": [
            ("DeviceFileEvents",      f'MD5 == "{safe_value}"'),
            ("DeviceProcessEvents",   f'MD5 == "{safe_value}"'),
            ("EmailAttachmentInfo",   f'MD5 == "{safe_value}"'),
            ("ThreatIntelIndicators", f'FileHashValue == "{safe_value}"'),
            ("SecurityAlert",         f'tostring(Entities) contains "{safe_value}"'),
        ],
    }

    raw_queries = table_map.get(entity_type, [])[:12]

    tasks = []
    for table, where_clause in raw_queries:
        summary_kql = f"""
{table}
| where {where_clause}
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
""".strip()
        tasks.append((table, table, summary_kql))

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

        if table in ["SecurityEvent", "AuditLogs", "SecurityAlert",
                     "AADRiskyUsers", "AADUserRiskEvents", "ThreatIntelIndicators"]:
            risk_score += 1

        findings.append({
            "table": table,
            "count": count,
            "first_seen": row.get("FirstSeen"),
            "last_seen": row.get("LastSeen"),
        })

    cmdb_context = None
    if entity_type in {"ip", "host", "domain"}:
        cmdb_res = _query_cmdb_entity(value)
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
        "entity_raw": raw_value,
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

# ============================================================
# get_incident_report  (unchanged from previous version)
# ============================================================

_register_tool_def("get_incident_report",
    ("Lists recent Sentinel incidents (no incident_id) or returns a structured SOC report for one. "
     "Entity values are normalized — JSON-array wrapping like [\"name\"] is stripped automatically."),
    {"incident_id": "optional: Sentinel incident number or IncidentName",
     "timespan": "ISO8601 duration like P1D, P7D",
     "top": "optional: number of incidents to list (default 50, max 200)"})

@mcp.tool
def get_incident_report(incident_id: Optional[str] = None, timespan: str = "P7D",
                        top: int = 50) -> dict:
    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    top = clamp_rows(top)

    if not incident_id:
        ago_expr = f"{int(hours)}h" if hours.is_integer() else f"{hours}h"

        kql = f"""
SecurityIncident
| where Severity !~ "Informational"
| where CreatedTime >= ago({ago_expr})
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, Owner,
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

    safe_id = escape_kql_string(str(incident_id))

    kql_incident = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, Owner,
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

    kql_alerts = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| mv-expand AlertId = AlertIds to typeof(string)
| join kind=inner (
    SecurityAlert
    | summarize arg_max(TimeGenerated, *) by SystemAlertId
    | project SystemAlertId, AlertName, AlertSeverity,
      AlertDescription = Description, AlertStatus = Status,
      AlertStartTime = StartTime, AlertEndTime = EndTime,
      ProductName, ProductComponentName, CompromisedEntity,
      Tactics, Techniques, SubTechniques, AlertLink, Entities
) on $left.AlertId == $right.SystemAlertId
| project AlertId, AlertName, AlertSeverity, AlertDescription, AlertStatus,
  AlertStartTime, AlertEndTime, ProductName, ProductComponentName,
  CompromisedEntity, Tactics, Techniques, SubTechniques, AlertLink, Entities
""".strip()

    res_alerts = la_query(kql_alerts, timespan)
    alert_rows = _la_first_table_dicts(res_alerts["data"]) if res_alerts.get("ok") else []

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
| where isnotempty(EntityType)
| extend EntityName = case(
    EntityType == "host", tostring(Entity.HostName),
    EntityType == "account", coalesce(tostring(Entity.AccountName), tostring(Entity.UserPrincipalName)),
    EntityType == "ip", tostring(Entity.Address),
    EntityType == "process", tostring(Entity.CommandLine),
    EntityType == "file", tostring(Entity.Name),
    EntityType == "url", tostring(Entity.Url),
    EntityType == "dns", tostring(Entity.DomainName),
    EntityType == "registrykey", tostring(Entity.Key),
    EntityType == "cloudapplication", tostring(Entity.Name),
    tostring(Entity.Name)
)
| where isnotempty(EntityName) and EntityName != "null"
| extend InternalIp = iff(EntityType == "host", tostring(Entity.LastIpAddress.Address), "")
| extend ExternalIp = iff(EntityType == "host", tostring(Entity.LastExternalIpAddress.Address), "")
| extend Fqdn = iff(EntityType == "host", tostring(Entity.FQDN), "")
| summarize
    Hosts = make_set_if(EntityName, EntityType == "host", 50),
    Fqdns = make_set_if(Fqdn, EntityType == "host" and isnotempty(Fqdn) and Fqdn != "null", 50),
    Accounts = make_set_if(EntityName, EntityType == "account", 50),
    IpAddresses = make_set_if(EntityName, EntityType == "ip", 50),
    InternalIps = make_set_if(InternalIp, isnotempty(InternalIp) and InternalIp != "null", 50),
    ExternalIps = make_set_if(ExternalIp, isnotempty(ExternalIp) and ExternalIp != "null", 50),
    Urls = make_set_if(EntityName, EntityType == "url", 50),
    Files = make_set_if(EntityName, EntityType == "file", 50),
    Processes = make_set_if(EntityName, EntityType == "process", 50),
    Domains = make_set_if(EntityName, EntityType == "dns", 50),
    RegistryKeys = make_set_if(EntityName, EntityType == "registrykey", 50),
    CloudResources = make_set_if(EntityName, EntityType in ("cloudapplication", "azureresource"), 50),
    AllEntities = make_set(EntityName, 200)
by IncidentNumber
""".strip()

    res_ent = la_query(kql_entities, timespan)
    entity_row: dict = {}
    if res_ent.get("ok"):
        ent_rows = _la_first_table_dicts(res_ent["data"])
        if ent_rows:
            entity_row = ent_rows[0]

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

    severity = (incident.get("Severity") or "").lower()
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

    all_ips = list({
        *entity_row.get("IpAddresses", []),
        *entity_row.get("InternalIps", []),
        *entity_row.get("ExternalIps", []),
    })

    accounts_normalized = [_normalize_entity_value(a) for a in entity_row.get("Accounts", [])]
    hosts_normalized = [_normalize_entity_value(h) for h in entity_row.get("Hosts", [])]

    return _ok({
        "mode": "report",
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
        "alerts_count":           alert_count,
        "alerts":                 alerts_structured,
        "entities": {
            "hosts":           hosts_normalized,
            "fqdns":           entity_row.get("Fqdns", []),
            "accounts":        accounts_normalized,
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
        "risk_level":             risk,
    })

# ============================================================
# get_incident_entities
# ============================================================
# Dedicated, thorough entity extractor. More complete than what
# get_incident_report / investigate_incident surface:
#   • Parses the FULL alert Entity JSON (not just a subset of fields)
#   • Resolves $ref pointers using the $id map inside each alert
#   • Extracts per-type useful fields (hosts → FQDN + IPs + OS + AzureID,
#     accounts → UPN + SID + NTDomain + AadUserId, files → hashes + path,
#     processes → commandline + PID + parent, etc.)
#   • Deduplicates entities across alerts by a normalized key
#   • Returns both a grouped-by-type view and a flat list
#   • Per-entity trace: which alert(s) referenced each entity

# Entity types seen in Sentinel SecurityAlert.Entities:
#   host/machine, account, ip, process, file, filehash, url, dns,
#   registrykey, registryvalue, cloudapplication, azureresource,
#   mailbox, mailmessage, mailcluster, submissionmail, malware,
#   securitygroup, cloud-logon-session, iotdevice, sentinelentities

def _build_id_map(root: Any) -> Dict[str, dict]:
    """
    Walk the entire entity tree (any depth) and build a $id → node map.
    Sentinel's $id tags can be nested arbitrarily deep — inside FileHashes[],
    ImageFile, Account, ParentProcess, etc. — so we must recurse.
    """
    id_map: Dict[str, dict] = {}
    seen_py_ids: set = set()

    def walk(obj):
        pyid = id(obj)
        if pyid in seen_py_ids:
            return
        seen_py_ids.add(pyid)

        if isinstance(obj, dict):
            if "$id" in obj:
                id_map[str(obj["$id"])] = obj
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(root)
    return id_map


def _resolve_refs_in_place(root: Any, id_map: Dict[str, dict]) -> None:
    """
    Walk the tree and replace any {"$ref": "X"} placeholder with the real
    object from id_map. Mutates in place so subsequent tree walks see the
    resolved structure.

    Sentinel places $ref at ANY depth: Process.Account={"$ref":"8"},
    Process.ParentProcess.ImageFile={"$ref":"5"}, File.FileHashes=[{"$ref":"12"}].
    The old single-level resolver missed all of these.
    """
    seen_py_ids: set = set()

    def walk(obj):
        pyid = id(obj)
        if pyid in seen_py_ids:
            return
        seen_py_ids.add(pyid)

        if isinstance(obj, dict):
            for k, v in list(obj.items()):
                if isinstance(v, dict) and "$ref" in v and "Type" not in v:
                    target = id_map.get(str(v["$ref"]))
                    if target is not None:
                        obj[k] = target  # replace with the real node
                else:
                    walk(v)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, dict) and "$ref" in item and "Type" not in item:
                    target = id_map.get(str(item["$ref"]))
                    if target is not None:
                        obj[i] = target
                else:
                    walk(item)

    walk(root)


def _collect_typed_entities(root: Any) -> List[dict]:
    """
    Walk the (already ref-resolved) tree and collect every dict that carries
    a `Type` field — at any depth. This mirrors what the Sentinel incident
    entity panel does: it surfaces Process.ImageFile, Process.Account,
    Process.ParentProcess, File.FileHashes[], Host.LastIpAddress, etc. as
    separate entity rows.

    Dedup rules:
      - If the same $id is seen twice (via $ref collapse), add it only once.
      - If the same python object is seen twice (post-resolution), skip re-walk.
      - Objects without $id that are semantic duplicates get collapsed later
        by _entity_dedup_key() in the caller.
    """
    collected: List[dict] = []
    seen_py_ids: set = set()
    seen_dollar_ids: set = set()

    def walk(obj):
        pyid = id(obj)
        if pyid in seen_py_ids:
            return
        seen_py_ids.add(pyid)

        if isinstance(obj, dict):
            if obj.get("Type"):
                dollar_id = obj.get("$id")
                if dollar_id is not None:
                    did = str(dollar_id)
                    if did not in seen_dollar_ids:
                        seen_dollar_ids.add(did)
                        collected.append(obj)
                else:
                    # No $id — include and let field-key dedup handle collisions
                    collected.append(obj)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(root)
    return collected

def _extract_host_fields(e: dict) -> dict:
    out = {
        "hostname":        e.get("HostName") or e.get("Name"),
        "fqdn":            e.get("FQDN"),
        "nt_domain":       e.get("NTDomain"),
        "dns_domain":      e.get("DnsDomain"),
        "os_family":       e.get("OSFamily"),
        "os_version":      e.get("OSVersion"),
        "azure_id":        e.get("AzureID"),
        "mdatp_device_id": e.get("MdatpDeviceId"),
        "oms_agent_id":    e.get("OMSAgentID"),
        "is_domain_joined":e.get("IsDomainJoined"),
    }
    lip = e.get("LastIpAddress") or {}
    if isinstance(lip, dict) and lip.get("Address"):
        out["last_ip"] = lip["Address"]
    eip = e.get("LastExternalIpAddress") or {}
    if isinstance(eip, dict) and eip.get("Address"):
        out["last_external_ip"] = eip["Address"]
    return out

def _extract_account_fields(e: dict) -> dict:
    # Construct a canonical account name if we only got parts
    name = e.get("Name") or e.get("AccountName")
    nt_domain = e.get("NTDomain")
    upn_suffix = e.get("UPNSuffix")
    upn = e.get("UserPrincipalName")
    if not upn and name and upn_suffix:
        upn = f"{name}@{upn_suffix}"

    display_name = name
    if nt_domain and name:
        display_name = f"{nt_domain}\\{name}"

    return {
        "name":            name,
        "display_name":    display_name,
        "upn":             upn,
        "upn_suffix":      upn_suffix,
        "nt_domain":       nt_domain,
        "sid":             e.get("Sid"),
        "aad_user_id":     e.get("AadUserId"),
        "aad_tenant_id":   e.get("AadTenantId"),
        "is_domain_joined":e.get("IsDomainJoined"),
        "object_guid":     e.get("ObjectGuid"),
        "puid":            e.get("PUID"),
    }

def _extract_ip_fields(e: dict) -> dict:
    out = {"address": e.get("Address")}
    loc = e.get("Location") or {}
    if isinstance(loc, dict):
        out["country"] = loc.get("CountryName") or loc.get("Country")
        out["city"]    = loc.get("City")
        out["state"]   = loc.get("State")
        out["asn"]     = loc.get("Asn")
        out["isp"]     = loc.get("CarrierName")
    return out

def _extract_process_fields(e: dict) -> dict:
    out = {
        "command_line":        e.get("CommandLine"),
        "process_id":          e.get("ProcessId"),
        "elevation_token":     e.get("ElevationToken"),
        "creation_time_utc":   e.get("CreationTimeUtc"),
    }
    img = e.get("ImageFile") or {}
    if isinstance(img, dict):
        out["image_name"] = img.get("Name")
        out["image_dir"]  = img.get("Directory")
        # File hashes attached to the image
        fhs = img.get("FileHashes") or []
        if isinstance(fhs, list):
            out["image_hashes"] = [
                {"algorithm": fh.get("Algorithm"), "value": fh.get("Value")}
                for fh in fhs if isinstance(fh, dict)
            ]
    parent = e.get("ParentProcess") or {}
    if isinstance(parent, dict):
        out["parent_command_line"] = parent.get("CommandLine")
        out["parent_process_id"]   = parent.get("ProcessId")
    return out

def _extract_file_fields(e: dict) -> dict:
    out = {
        "name":      e.get("Name"),
        "directory": e.get("Directory"),
    }
    fhs = e.get("FileHashes") or []
    if isinstance(fhs, list):
        out["hashes"] = [
            {"algorithm": fh.get("Algorithm"), "value": fh.get("Value")}
            for fh in fhs if isinstance(fh, dict)
        ]
    return out

def _extract_filehash_fields(e: dict) -> dict:
    return {
        "algorithm": e.get("Algorithm"),
        "value":     e.get("Value") or e.get("HashValue"),
    }

def _extract_url_fields(e: dict) -> dict:
    return {"url": e.get("Url")}

def _extract_dns_fields(e: dict) -> dict:
    out = {"domain_name": e.get("DomainName")}
    ips = e.get("IpAddresses")
    if isinstance(ips, list):
        out["ip_addresses"] = [
            ip.get("Address") if isinstance(ip, dict) else ip
            for ip in ips
        ]
    dns_server = e.get("DnsServerIp") or {}
    if isinstance(dns_server, dict) and dns_server.get("Address"):
        out["dns_server_ip"] = dns_server["Address"]
    return out

def _extract_registrykey_fields(e: dict) -> dict:
    return {
        "hive": e.get("Hive"),
        "key":  e.get("Key"),
    }

def _extract_registryvalue_fields(e: dict) -> dict:
    out = {
        "name":       e.get("Name"),
        "value":      e.get("Value"),
        "value_type": e.get("ValueType"),
    }
    key = e.get("Key") or {}
    if isinstance(key, dict):
        out["key_hive"] = key.get("Hive")
        out["key_path"] = key.get("Key")
    return out

def _extract_cloudapp_fields(e: dict) -> dict:
    return {
        "name":          e.get("Name"),
        "app_id":        e.get("AppId"),
        "instance_name": e.get("InstanceName"),
    }

def _extract_azureresource_fields(e: dict) -> dict:
    return {
        "resource_id":   e.get("ResourceId"),
        "subscription":  e.get("SubscriptionId"),
    }

def _extract_mailbox_fields(e: dict) -> dict:
    return {
        "primary_address": e.get("MailboxPrimaryAddress"),
        "display_name":    e.get("DisplayName"),
        "upn":             e.get("Upn"),
        "risk_level":      e.get("RiskLevel"),
    }

def _extract_mailmessage_fields(e: dict) -> dict:
    return {
        "network_message_id":  e.get("NetworkMessageId"),
        "internet_message_id": e.get("InternetMessageId"),
        "recipient":           e.get("Recipient"),
        "sender":              e.get("Sender") or e.get("SenderAddress"),
        "sender_display_name": e.get("SenderDisplayName"),
        "subject":             e.get("Subject"),
        "delivery_location":   e.get("DeliveryLocation"),
        "delivery_action":     e.get("DeliveryAction"),
        "p1_sender":           e.get("P1Sender"),
        "p2_sender":           e.get("P2Sender"),
        "threats":             e.get("Threats"),
        "urls":                e.get("Urls"),
    }

def _extract_malware_fields(e: dict) -> dict:
    return {
        "name":     e.get("Name"),
        "category": e.get("Category"),
    }

def _extract_securitygroup_fields(e: dict) -> dict:
    return {
        "distinguished_name": e.get("DistinguishedName"),
        "sid":                e.get("Sid"),
        "object_guid":        e.get("ObjectGuid"),
    }

def _extract_generic_fields(e: dict) -> dict:
    """Fallback for types we don't specifically handle — keep everything useful."""
    return {
        k: v for k, v in e.items()
        if not k.startswith("$") and k != "Type"
        and v not in (None, "", [], {})
    }

# Type → (normalized_type, extractor)
_ENTITY_EXTRACTORS = {
    "host":                ("host",           _extract_host_fields),
    "machine":             ("host",           _extract_host_fields),
    "account":             ("account",        _extract_account_fields),
    "ip":                  ("ip",             _extract_ip_fields),
    "process":             ("process",        _extract_process_fields),
    "file":                ("file",           _extract_file_fields),
    "filehash":            ("filehash",       _extract_filehash_fields),
    "url":                 ("url",            _extract_url_fields),
    "dns":                 ("dns",            _extract_dns_fields),
    "registrykey":         ("registry_key",   _extract_registrykey_fields),
    "registry-key":        ("registry_key",   _extract_registrykey_fields),
    "registryvalue":       ("registry_value", _extract_registryvalue_fields),
    "registry-value":      ("registry_value", _extract_registryvalue_fields),
    "cloudapplication":    ("cloud_app",      _extract_cloudapp_fields),
    "cloud-application":   ("cloud_app",      _extract_cloudapp_fields),
    "azureresource":       ("azure_resource", _extract_azureresource_fields),
    "azure-resource":      ("azure_resource", _extract_azureresource_fields),
    "mailbox":             ("mailbox",        _extract_mailbox_fields),
    "mailmessage":         ("mail_message",   _extract_mailmessage_fields),
    "mail-message":        ("mail_message",   _extract_mailmessage_fields),
    "malware":             ("malware",        _extract_malware_fields),
    "securitygroup":       ("security_group", _extract_securitygroup_fields),
    "security-group":      ("security_group", _extract_securitygroup_fields),
}

def _entity_dedup_key(normalized_type: str, fields: dict) -> str:
    """
    Build a stable dedup key per entity. Uses the most identifying field
    for each type so the same entity seen across multiple alerts collapses.
    """
    def _low(v):
        return str(v).strip().lower() if v else ""

    if normalized_type == "host":
        # Prefer FQDN, then hostname
        return f"host::{_low(fields.get('fqdn') or fields.get('hostname'))}"
    if normalized_type == "account":
        # UPN first, else domain\name, else SID
        return f"account::{_low(fields.get('upn') or fields.get('display_name') or fields.get('sid') or fields.get('aad_user_id'))}"
    if normalized_type == "ip":
        return f"ip::{_low(fields.get('address'))}"
    if normalized_type == "process":
        # Prefer PID alone — Sentinel frequently emits the same process twice:
        # once with full command line, once as a sibling/parent stub (PID only).
        # These should merge. Fall back to command line if PID is missing.
        pid = _low(fields.get("process_id"))
        if pid:
            return f"proc::pid::{pid}"
        return f"proc::cmd::{_low(fields.get('command_line'))[:200]}"
    if normalized_type == "file":
        # Try hash first, else path+name
        hashes = fields.get("hashes") or []
        if hashes and isinstance(hashes, list) and hashes[0].get("value"):
            return f"file::hash::{_low(hashes[0].get('value'))}"
        return f"file::{_low(fields.get('directory'))}::{_low(fields.get('name'))}"
    if normalized_type == "filehash":
        return f"hash::{_low(fields.get('value'))}"
    if normalized_type == "url":
        return f"url::{_low(fields.get('url'))}"
    if normalized_type == "dns":
        return f"dns::{_low(fields.get('domain_name'))}"
    if normalized_type == "registry_key":
        return f"rk::{_low(fields.get('hive'))}::{_low(fields.get('key'))}"
    if normalized_type == "registry_value":
        return f"rv::{_low(fields.get('key_hive'))}::{_low(fields.get('key_path'))}::{_low(fields.get('name'))}"
    if normalized_type == "cloud_app":
        return f"app::{_low(fields.get('app_id') or fields.get('name'))}"
    if normalized_type == "azure_resource":
        return f"azres::{_low(fields.get('resource_id'))}"
    if normalized_type == "mailbox":
        return f"mbox::{_low(fields.get('primary_address') or fields.get('upn'))}"
    if normalized_type == "mail_message":
        return f"msg::{_low(fields.get('network_message_id') or fields.get('internet_message_id'))}"
    if normalized_type == "malware":
        return f"mw::{_low(fields.get('name'))}::{_low(fields.get('category'))}"
    if normalized_type == "security_group":
        return f"sg::{_low(fields.get('sid') or fields.get('distinguished_name'))}"
    # Fallback: hash-ish of all values
    return f"{normalized_type}::{_low(json.dumps(fields, sort_keys=True, default=str))[:300]}"


# ============================================================
# Shared entity extraction pipeline
# ============================================================
# Used by both investigate_incident and get_incident_entities so there's
# exactly one place where Sentinel's $id/$ref JSON gets materialized and
# walked. Any future fix to entity parsing only needs to happen here.

# Well-known local/service machine accounts. These appear in every MDE
# endpoint alert (every Windows process runs as one of them at some point)
# but are NOT actionable identity pivots. They must NOT leak into the
# `users` list that drives checklist branch detection — otherwise every
# endpoint incident would trip the identity branch the moment we started
# surfacing nested Process.Account entities.
_LOCAL_ACCOUNT_NAMES = {
    "system", "local service", "network service",
    "localsystem", "local system", "anonymous logon",
    "dwm", "umfd",  # Desktop Window Manager, User-Mode Font Driver
}
_LOCAL_ACCOUNT_DOMAINS = {"nt authority", "builtin", "font driver host",
                           "window manager"}
# S-1-5-18: LocalSystem, S-1-5-19: LocalService, S-1-5-20: NetworkService
_LOCAL_ACCOUNT_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


def _is_local_account(fields: dict) -> bool:
    """
    Return True for well-known local/service accounts (SYSTEM, LOCAL SERVICE,
    NETWORK SERVICE, ANONYMOUS LOGON, DWM-*, UMFD-*).

    These accounts appear in MDE alerts because every process runs as one of
    them at some point — they are not actionable identity pivots and must be
    excluded from the `users` list used for pivot analysis and checklist
    branch detection. They remain visible in the entity inventory.
    """
    sid = (fields.get("sid") or "").strip().upper()
    if sid in _LOCAL_ACCOUNT_SIDS:
        return True

    name      = (fields.get("name") or "").strip().lower()
    upn       = (fields.get("upn")  or "").strip().lower()
    disp      = (fields.get("display_name") or "").strip().lower()
    nt_domain = (fields.get("nt_domain") or "").strip().lower()

    # Direct match on name or UPN
    if name in _LOCAL_ACCOUNT_NAMES or upn in _LOCAL_ACCOUNT_NAMES:
        return True

    # Domain\Name form with a machine-local domain
    if nt_domain in _LOCAL_ACCOUNT_DOMAINS and name in _LOCAL_ACCOUNT_NAMES:
        return True

    # display_name in "NT AUTHORITY\SYSTEM" form
    for d in _LOCAL_ACCOUNT_DOMAINS:
        for n in _LOCAL_ACCOUNT_NAMES:
            if disp == f"{d}\\{n}":
                return True

    # DWM-N and UMFD-N virtual accounts (indexed session accounts)
    if re.fullmatch(r"(dwm|umfd)-\d+", name):
        return True

    return False


def _extract_all_entities_from_alerts(alerts: List[dict],
                                      snapshot_raw: bool = False) -> dict:
    """
    Canonical entity-extraction pipeline shared by investigate_incident and
    get_incident_entities. For each alert dict (must carry an `Entities`
    field, either as a JSON string or already-parsed list):

      1. Parse Entities JSON
      2. Build a $id → node map across the ENTIRE tree (any depth)
      3. Resolve every $ref at any depth (in-place mutation)
      4. Collect every Type-tagged dict recursively (any depth)
      5. Run through _ENTITY_EXTRACTORS for structured per-type fields
      6. Dedup across alerts via _entity_dedup_key + field merge

    The caller decides what to do with the resulting rich entity map —
    flatten into string sets (investigate_incident) or shape into the
    grouped-by-type view (get_incident_entities).

    Args:
      alerts:        list of alert dicts from SecurityAlert projection.
                     Each should carry 'SystemAlertId', 'AlertName',
                     'TimeGenerated' (or 'StartTime' / 'AlertTime'), and
                     'Entities'.
      snapshot_raw:  if True, deep-copies each alert's Entities BEFORE
                     mutation so callers can expose the original shape
                     (used by get_incident_entities with include_raw=true).

    Returns:
      {
        "merged":        dict keyed by _entity_dedup_key → entity record
                          { "type", "raw_type", "fields",
                            "seen_in_alerts": set[str],
                            "first_alert_time": str|None },
        "parse_errors":  int,
        "unknown_types": dict[str, int] — entity types with no extractor,
        "raw_snapshots": list of {alert_id, alert_name, entities} (if snapshot_raw),
      }
    """
    merged: Dict[str, Dict[str, Any]] = {}
    parse_errors = 0
    unknown_types: Dict[str, int] = {}
    raw_snapshots: List[Dict[str, Any]] = []

    for alert in alerts:
        alert_id = alert.get("SystemAlertId") or alert.get("AlertId")
        alert_nm = alert.get("AlertName")
        alert_tm = (alert.get("TimeGenerated") or alert.get("AlertTime")
                    or alert.get("StartTime"))
        entities_raw = alert.get("Entities")

        if not entities_raw:
            continue

        if isinstance(entities_raw, str):
            try:
                parsed = json.loads(entities_raw)
            except Exception:
                parse_errors += 1
                continue
        else:
            parsed = entities_raw

        if not isinstance(parsed, list):
            continue

        if snapshot_raw:
            # Deep copy via JSON round-trip BEFORE we mutate in place
            raw_snapshots.append({
                "alert_id":   alert_id,
                "alert_name": alert_nm,
                "entities":   json.loads(json.dumps(parsed, default=str)),
            })

        # Three-pass pipeline: build → resolve → collect
        id_map = _build_id_map(parsed)
        _resolve_refs_in_place(parsed, id_map)
        collected = _collect_typed_entities(parsed)

        # Extract + dedup into merged dict
        for e in collected:
            if not isinstance(e, dict):
                continue
            etype = (e.get("Type") or "").lower()
            if not etype:
                continue

            handler = _ENTITY_EXTRACTORS.get(etype)
            if handler:
                normalized_type, extractor = handler
                fields = extractor(e)
            else:
                normalized_type = etype.replace("-", "_")
                fields = _extract_generic_fields(e)
                unknown_types[etype] = unknown_types.get(etype, 0) + 1

            # Strip empty values
            fields = {k: v for k, v in fields.items()
                      if v not in (None, "", [], {})}

            if not fields:
                continue

            key = _entity_dedup_key(normalized_type, fields)
            if key in merged:
                if alert_id:
                    merged[key]["seen_in_alerts"].add(str(alert_id))
                # Merge new non-empty fields we didn't have yet
                for fk, fv in fields.items():
                    if fk not in merged[key]["fields"] and fv not in (None, "", [], {}):
                        merged[key]["fields"][fk] = fv
            else:
                merged[key] = {
                    "type":             normalized_type,
                    "raw_type":         etype,
                    "fields":           fields,
                    "seen_in_alerts":   {str(alert_id)} if alert_id else set(),
                    "first_alert_time": alert_tm,
                }

    return {
        "merged":        merged,
        "parse_errors":  parse_errors,
        "unknown_types": unknown_types,
        "raw_snapshots": raw_snapshots,
    }


def _flatten_entities_to_string_sets(entity_map: Dict[str, Dict[str, Any]]) -> dict:
    """
    Given the rich entity map from _extract_all_entities_from_alerts, flatten
    into the simple string-set shape that investigate_incident has always
    returned. Additionally surfaces `hashes` and `local_accounts` which the
    old hand-rolled extraction couldn't produce (because it didn't recurse
    into FileHashes[] or Process.Account).

    Returns:
      {
        "users":          sorted list of user UPNs/display names (LOCAL accts filtered),
        "ips":            sorted list of IP address strings,
        "hosts":          sorted list of hostnames / FQDNs,
        "domains":        sorted list of DNS domain names,
        "processes":      sorted list of process command lines (truncated 200),
        "files":          sorted list of file names,
        "hashes":         sorted list of hash values (sha256/sha1/md5) — NEW,
        "local_accounts": sorted list of machine-local accounts (SYSTEM etc.) — NEW,
      }
    """
    users: set = set()
    ips: set = set()
    hosts: set = set()
    domains: set = set()
    processes: set = set()
    files: set = set()
    hashes: set = set()
    local_accounts: set = set()

    for entry in entity_map.values():
        t = entry["type"]
        f = entry["fields"]

        if t == "host":
            name = (f.get("fqdn") or f.get("hostname") or "").strip()
            if name:
                hosts.add(_normalize_entity_value(name).lower())

        elif t == "account":
            if _is_local_account(f):
                # Still visible, but separated from actionable user list
                local = (f.get("display_name") or f.get("name")
                         or f.get("upn") or "").strip()
                if local:
                    local_accounts.add(local)
                continue
            name = (f.get("upn") or f.get("display_name")
                    or f.get("name") or "").strip()
            name = _normalize_entity_value(name)
            if name:
                users.add(name.lower())

        elif t == "ip":
            addr = f.get("address")
            if addr:
                ips.add(addr)

        elif t == "dns":
            d = f.get("domain_name")
            if d:
                domains.add(d.lower())

        elif t == "process":
            cmd = f.get("command_line")
            if cmd:
                processes.add(cmd[:200])

        elif t == "file":
            fname = f.get("name")
            if fname:
                files.add(fname)
            # File can carry nested hashes inline — capture them too
            for h in (f.get("hashes") or []):
                if isinstance(h, dict) and h.get("value"):
                    hashes.add(h["value"])

        elif t == "filehash":
            val = f.get("value")
            if val:
                hashes.add(val)

    return {
        "users":          sorted(users),
        "ips":            sorted(ips),
        "hosts":          sorted(hosts),
        "domains":        sorted(domains),
        "processes":      sorted(processes),
        "files":          sorted(files),
        "hashes":         sorted(hashes),
        "local_accounts": sorted(local_accounts),
    }


_register_tool_def("get_incident_entities",
    ("Returns the COMPLETE entity inventory extracted from every alert linked to a "
     "Sentinel incident. More thorough than get_incident_report / investigate_incident: "
     "parses the full Entity JSON, resolves $ref references, extracts every useful field "
     "per entity type (hosts get FQDN + IPs + OS + AzureID; accounts get UPN + SID + "
     "NTDomain + AadUserId; files get hashes + path; processes get command line + PID + "
     "parent; mail messages get sender + recipient + subject; etc.), and deduplicates "
     "entities seen across multiple alerts. Each entity carries a 'seen_in_alerts' list "
     "so you can trace which alert(s) surfaced it. Use this when you want the full entity "
     "picture — for IOC enrichment, scoping, or feeding downstream tools."),
    {"incident_id": "Sentinel incident number or IncidentName",
     "timespan":    "ISO8601 duration, default P7D",
     "include_raw_entities": "optional bool, default false — include the raw Entity JSON per alert for debugging"})

@mcp.tool
def get_incident_entities(incident_id: str, timespan: str = "P7D",
                          include_raw_entities: bool = False) -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_INCIDENT:
        return _fail(f"Timespan exceeds allowed window ({MAX_HOURS_INCIDENT}h max)",
                     code="VALIDATION_ERROR", detail=f"got {hours}h")

    safe_id = escape_kql_string(str(incident_id))

    # Step 1: resolve incident → alert ids
    inc_kql = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, AlertIds
""".strip()

    inc_res = la_query(inc_kql, timespan)
    if not inc_res.get("ok"):
        return inc_res

    inc_rows = _la_first_table_dicts(inc_res["data"])
    if not inc_rows:
        return _fail("Incident not found", code="NOT_FOUND")

    incident = inc_rows[0]
    alert_ids = incident.get("AlertIds") or []

    if isinstance(alert_ids, str):
        try:
            alert_ids = json.loads(alert_ids)
        except Exception:
            alert_ids = []

    if not alert_ids:
        return _ok({
            "incident": {
                "number":   incident.get("IncidentNumber"),
                "title":    incident.get("Title"),
                "severity": incident.get("Severity"),
                "status":   incident.get("Status"),
            },
            "alert_count":    0,
            "entity_count":   0,
            "entities_by_type": {},
            "entities_flat":  [],
            "assessment":     "Incident has no linked alerts",
        })

    # Step 2: fetch alert entities
    safe_alerts = [escape_kql_string(str(a)) for a in alert_ids if a]
    alert_list = ",".join([f'"{a}"' for a in safe_alerts])

    alerts_kql = f"""
SecurityAlert
| where SystemAlertId in ({alert_list})
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, TimeGenerated, Entities
""".strip()

    alerts_res = la_query(alerts_kql, timespan)
    if not alerts_res.get("ok"):
        return alerts_res

    alerts = _la_first_table_dicts(alerts_res["data"])

    # Step 3: shared extraction pipeline (parse → resolve refs recursively →
    #         collect typed entities → dedup across alerts). Single source of
    #         truth — same code powers investigate_incident.
    extraction = _extract_all_entities_from_alerts(
        alerts, snapshot_raw=include_raw_entities
    )
    merged        = extraction["merged"]
    parse_errors  = extraction["parse_errors"]
    unknown_types = extraction["unknown_types"]
    raw_per_alert = extraction["raw_snapshots"]

    # Step 4: shape output
    entities_flat: List[dict] = []
    entities_by_type: Dict[str, List[dict]] = {}

    for entry in merged.values():
        obj = {
            "type":             entry["type"],
            "raw_type":         entry["raw_type"],
            "fields":           entry["fields"],
            "seen_in_alerts":   sorted(entry["seen_in_alerts"]),
            "alert_count":      len(entry["seen_in_alerts"]),
            "first_alert_time": entry["first_alert_time"],
        }
        entities_flat.append(obj)
        entities_by_type.setdefault(entry["type"], []).append(obj)

    # Deterministic ordering: most-seen entities first, then by type
    entities_flat.sort(key=lambda x: (-x["alert_count"], x["type"]))
    for t in entities_by_type:
        entities_by_type[t].sort(key=lambda x: -x["alert_count"])

    # Summary counts per type
    type_counts = {t: len(v) for t, v in entities_by_type.items()}

    out = {
        "incident": {
            "number":   incident.get("IncidentNumber"),
            "title":    incident.get("Title"),
            "severity": incident.get("Severity"),
            "status":   incident.get("Status"),
        },
        "alert_count":       len(alerts),
        "entity_count":      len(entities_flat),
        "type_counts":       type_counts,
        "entities_by_type":  entities_by_type,
        "entities_flat":     entities_flat,
        "parse_errors":      parse_errors,
        "unknown_types":     unknown_types,  # so we learn about types we should add
    }

    if include_raw_entities:
        out["raw_entities_per_alert"] = raw_per_alert

    return _ok(out)

# ============================================================
# investigate_incident
# ============================================================
# CHANGES vs previous version:
#   • Incident query now projects Title (needed by run_investigation_checklist
#     for keyword-based branch detection).
#   • Alerts query now projects REAL AlertName (not ProductName). ProductName
#     is kept in a separate field. This is the root cause of the "cloud"
#     misrouting bug — the old code aliased AlertName=ProductName which made
#     every alert_names list contain "Azure Sentinel".
#   • Return shape includes incident.title and alerts.product_names for
#     downstream use.
#   • Techniques/Tactics are flattened via _flatten_mitre_field to undo
#     Sentinel's JSON-string-in-list encoding (fixes `["[\"T1110\"]"]`).

_register_tool_def("investigate_incident",
    ("Full SOC investigation of a Sentinel incident. Extracts alerts, parses entity lists, "
     "builds MITRE timeline, enriches with CMDB, calculates risk. Returns the REAL alert name "
     "(not ProductName) so downstream branch-detection works correctly."),
    {"incident_id": "Sentinel incident number",
     "timespan": "ISO8601 duration (P1D, P7D)"})

@mcp.tool
def investigate_incident(incident_id: str, timespan: str = "P7D") -> dict:
    if not incident_id:
        return _fail("incident_id is required", code="VALIDATION_ERROR")

    try:
        hours = parse_timespan_to_hours(timespan)
    except Exception as e:
        return _fail("Invalid timespan", code="VALIDATION_ERROR", detail=str(e))

    if hours <= 0 or hours > MAX_HOURS_INCIDENT:
        return _fail(f"Timespan exceeds allowed window ({MAX_HOURS_INCIDENT}h max)",
                     code="VALIDATION_ERROR", detail=f"got {hours}h")

    safe_id = escape_kql_string(str(incident_id))

    # Project Title so we can use it for branch detection.
    incident_kql = f"""
SecurityIncident
| where IncidentNumber == toint("{safe_id}") or tostring(IncidentName) =~ "{safe_id}"
| where Severity !~ "Informational"
| summarize arg_max(LastModifiedTime, *) by IncidentNumber
| project IncidentNumber, Title, Severity, Status, Owner,
  CreatedTime, LastModifiedTime, AlertIds
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
            "incident": {
                "id":                incident.get("IncidentNumber"),
                "title":             incident.get("Title"),
                "severity":          incident.get("Severity"),
                "status":            incident.get("Status"),
                "owner":             incident.get("Owner"),
                "created_time":      incident.get("CreatedTime"),
                "last_modified_time":incident.get("LastModifiedTime"),
            },
            "alerts": {"count": 0, "names": [], "product_names": [], "components": []},
            "entities": {},
            "timeline": {},
            "mitre": {"tactics": [], "techniques": []},
            "risk_level": "Low",
            "assessment": "Incident has no linked alerts",
        })

    safe_alerts = [escape_kql_string(str(a)) for a in alert_ids if a]
    alert_list = ",".join([f'"{a}"' for a in safe_alerts])

    # Keep REAL AlertName, don't overwrite with ProductName.
    # Include SystemAlertId + TimeGenerated + dedup-by-id so the shared
    # extraction helper can attribute entities to specific alerts and so
    # duplicate ingestions of the same alert don't inflate counts.
    alerts_kql = f"""
SecurityAlert
| where SystemAlertId in ({alert_list})
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project
    SystemAlertId,
    AlertName,
    ProductName,
    Component = ProductComponentName,
    AlertTime = StartTime,
    TimeGenerated,
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

    # Run the shared extraction pipeline — same code that powers
    # get_incident_entities. Handles nested $id/$ref resolution, recursive
    # collection of typed sub-entities (Process.Account, Process.ImageFile,
    # File.FileHashes[], Host.LastIpAddress, etc.), and cross-alert dedup.
    extraction = _extract_all_entities_from_alerts(alerts, snapshot_raw=False)
    entity_map = extraction["merged"]

    # Flatten the rich map into the legacy string-set shape (backwards
    # compatible) + two new fields: `hashes` (scraped from File.FileHashes[]
    # and standalone FileHash entities) and `local_accounts` (SYSTEM,
    # LOCAL SERVICE, etc. — filtered out of `users` so they don't trip the
    # identity checklist branch, but still visible).
    flat = _flatten_entities_to_string_sets(entity_map)

    users     = set(flat["users"])
    ips       = set(flat["ips"])
    hosts     = set(flat["hosts"])
    domains   = set(flat["domains"])
    processes = set(flat["processes"])
    files     = set(flat["files"])
    hashes          = set(flat["hashes"])
    local_accounts  = set(flat["local_accounts"])

    alert_times = [a.get("AlertTime") for a in alerts if a.get("AlertTime")]
    first_alert = min(alert_times) if alert_times else None
    last_alert = max(alert_times) if alert_times else None

    # Flatten Tactics/Techniques — they come back from Sentinel as
    # JSON-stringified lists. This undoes `["[\"T1110\"]"]` → `["T1110"]`.
    tactics = _flatten_mitre_field([a.get("Tactics") for a in alerts])
    techniques = _flatten_mitre_field([a.get("Techniques") for a in alerts])

    cmdb_pivots = list(ips)[:3] + list(hosts)[:3] + list(domains)[:3]
    cmdb_tasks = [
        (pivot, pivot, f'{CMDB_TABLE} | where tostring(*) contains "{escape_kql_string(str(pivot))}" | take 5')
        for pivot in cmdb_pivots
    ]

    cmdb_context = []
    if cmdb_tasks:
        cmdb_results = _run_queries_parallel(cmdb_tasks, "P90D")
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
            "count":         len(alerts),
            # Real alert/rule names — what the auto-detect needs.
            "names":         sorted({a.get("AlertName") for a in alerts if a.get("AlertName")}),
            # ProductName preserved separately (informational).
            "product_names": sorted({a.get("ProductName") for a in alerts if a.get("ProductName")}),
            "components":    sorted({a.get("Component") for a in alerts if a.get("Component")}),
        },
        "entities": {
            "users":          sorted(users),
            "ips":            sorted(ips),
            "hosts":          sorted(hosts),
            "domains":        sorted(domains),
            "processes":      sorted(processes),
            "files":          sorted(files),
            # New since shared-helper refactor:
            #   hashes — sha256/sha1/md5 scraped from nested File.FileHashes[]
            #            and standalone FileHash entities. run_investigation_checklist
            #            feeds these into IOC enrichment automatically.
            #   local_accounts — SYSTEM, LOCAL SERVICE, etc. extracted from
            #            Process.Account but filtered out of `users` so they
            #            don't trip the identity checklist branch.
            "hashes":         sorted(hashes),
            "local_accounts": sorted(local_accounts),
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

# ============================================================
# CHECKLIST DEFINITIONS
# ============================================================

def _checklist_execution(safe_host: str, safe_user: str, ts_short: str, ts_long: str) -> List[dict]:
    return [
        {"bucket": "cmdb",              "type": "cmdb",          "entity": safe_host},
        {"bucket": "process_events",    "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceProcessEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, AccountName, InitiatingProcessCommandLine, ProcessCommandLine, FileName, SHA256, FolderPath | order by TimeGenerated desc | take 100'},
        {"bucket": "device_events",     "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, InitiatingProcessCommandLine, AdditionalFields, FileName | order by TimeGenerated desc | take 100'},
        {"bucket": "network_events",    "type": "run_query",     "timespan": ts_long,
         "kql": f'DeviceNetworkEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName | order by TimeGenerated desc | take 100'},
        {"bucket": "registry_events",   "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceRegistryEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "file_events",       "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceFileEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "logon_events",      "type": "run_query",     "timespan": ts_short,
         "kql": f'DeviceLogonEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, LogonType, AccountName, InitiatingProcessCommandLine, RemoteIP | order by TimeGenerated desc | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" or tostring(Entities) contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "behavior_analytics", "type": "run_query",    "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" or DeviceName contains "{safe_host}" | project TimeGenerated, UserName, DeviceName, ActivityType, ActionType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "signin_logs",        "type": "run_query",    "timespan": "P7D",
         "kql": f'SigninLogs | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, DeviceDetail | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",        "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
        {"bucket": "entity_user",        "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
    ]

def _checklist_identity(safe_user: str, safe_ip: str, safe_host: str, ts_long: str) -> List[dict]:
    tasks = [
        {"bucket": "signin_logs",        "type": "run_query",    "timespan": "P7D",
         "kql": f'SigninLogs | where UserPrincipalName contains "{safe_user}" or AlternateSignInName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, ConditionalAccessStatus, DeviceDetail | order by TimeGenerated desc | take 100'},
        {"bucket": "risk_events",        "type": "run_query",    "timespan": "P30D",
         "kql": f'AADUserRiskEvents | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, IpAddress | order by TimeGenerated desc | take 50'},
        {"bucket": "risky_users",        "type": "run_query",    "timespan": "P30D",
         "kql": f'AADRiskyUsers | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, RiskLevel, RiskState, RiskDetail | order by TimeGenerated desc | take 20'},
        {"bucket": "audit_logs",         "type": "run_query",    "timespan": "P2D",
         "kql": f'AuditLogs | where tostring(InitiatedBy) contains "{safe_user}" or tostring(TargetResources) contains "{safe_user}" | project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources | order by TimeGenerated desc | take 50'},
        {"bucket": "identity_info",      "type": "run_query",    "timespan": "P30D",
         "kql": f'IdentityInfo | where AccountUPN contains "{safe_user}" or AccountName contains "{safe_user}" | project TimeGenerated, AccountUPN, AccountName, JobTitle, Department, Manager, AccountEnabled, Tags | take 5'},
        {"bucket": "identity_logon",     "type": "run_query",    "timespan": "P7D",
         "kql": f'IdentityLogonEvents | where AccountName =~ "{safe_user}" or AccountUpn =~ "{safe_user}" | project TimeGenerated, ActionType, AccountName, AccountUpn, DeviceName, IPAddress, LogonType, Application, Protocol | order by TimeGenerated desc | take 100'},
        {"bucket": "identity_directory", "type": "run_query",    "timespan": "P30D",
         "kql": f'IdentityDirectoryEvents | where AccountName =~ "{safe_user}" or tostring(AdditionalFields) contains "{safe_user}" | project TimeGenerated, ActionType, AccountName, TargetAccountUpn, AdditionalFields | order by TimeGenerated desc | take 50'},
        {"bucket": "group_changes",      "type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityEvent | where EventID in (4728, 4729, 4732, 4733, 4756, 4757) | where TargetAccount contains "{safe_user}" or MemberName contains "{safe_user}" | project TimeGenerated, EventID, Activity, SubjectAccount, TargetAccount, MemberName | take 50'},
        {"bucket": "behavior_analytics", "type": "run_query",    "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" | project TimeGenerated, UserName, ActivityType, ActionType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where tostring(Entities) contains "{safe_user}" or CompromisedEntity contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "office_activity",    "type": "run_query",    "timespan": "P2D",
         "kql": f'OfficeActivity | where UserId contains "{safe_user}" | project TimeGenerated, Operation, RecordType, UserId, ClientIP, ResultStatus | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_user",        "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
    ]
    if safe_ip:
        tasks.append({"bucket": "entity_ip",   "type": "analyze_entity", "value": safe_ip, "timespan": "P7D"})
        tasks.append({"bucket": "signin_by_ip","type": "run_query", "timespan": "P7D",
                      "kql": f'SigninLogs | where IPAddress == "{safe_ip}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName | order by TimeGenerated desc | take 50'})
    if safe_host:
        tasks.append({"bucket": "cmdb",        "type": "cmdb", "entity": safe_host})
        tasks.append({"bucket": "entity_host", "type": "analyze_entity", "value": safe_host, "timespan": "P7D"})
    return tasks

def _checklist_lateral_movement(safe_host: str, safe_user: str) -> List[dict]:
    return [
        {"bucket": "cmdb",              "type": "cmdb", "entity": safe_host},
        {"bucket": "network_lateral",   "type": "run_query", "timespan": "P1D",
         "kql": f'DeviceNetworkEvents | where DeviceName contains "{safe_host}" | where RemotePort in (445, 135, 5985, 5986, 3389, 22, 23) | project TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "logon_events",      "type": "run_query", "timespan": "PT12H",
         "kql": f'DeviceLogonEvents | where DeviceName contains "{safe_host}" or AccountName =~ "{safe_user}" | where LogonType in (3, 10, "Network", "RemoteInteractive") | project TimeGenerated, DeviceName, ActionType, LogonType, AccountName, RemoteIP, RemoteDeviceName | order by TimeGenerated desc | take 100'},
        {"bucket": "process_events",    "type": "run_query", "timespan": "PT12H",
         "kql": f'DeviceProcessEvents | where DeviceName contains "{safe_host}" | where FileName in~ ("psexec.exe", "psexesvc.exe", "wmic.exe", "schtasks.exe", "winrs.exe", "powershell.exe") or ProcessCommandLine has_any ("psexec", "wmiexec", "smbexec", "schtasks /create", "Invoke-Command", "Enter-PSSession") | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "identity_logon",    "type": "run_query", "timespan": "PT12H",
         "kql": f'IdentityLogonEvents | where DeviceName contains "{safe_host}" or AccountName =~ "{safe_user}" | project TimeGenerated, ActionType, AccountName, DeviceName, IPAddress, LogonType, Protocol | order by TimeGenerated desc | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query", "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" or tostring(Entities) contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "behavior_analytics","type": "run_query", "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" or DeviceName contains "{safe_host}" or SourceDevice contains "{safe_host}" | project TimeGenerated, UserName, DeviceName, SourceDevice, ActivityType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",       "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
        {"bucket": "entity_user",       "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
    ]

def _checklist_network(safe_host: str, safe_ip: str, safe_domain: str) -> List[dict]:
    pivot = safe_ip or safe_domain
    return [
        {"bucket": "cmdb",              "type": "cmdb", "entity": safe_host},
        {"bucket": "network_events",    "type": "run_query", "timespan": "P1D",
         "kql": f'DeviceNetworkEvents | where DeviceName contains "{safe_host}" or RemoteIP == "{safe_ip}" or RemoteUrl contains "{safe_domain}" | project TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName | order by TimeGenerated desc | take 200'},
        {"bucket": "process_events",    "type": "run_query", "timespan": "PT12H",
         "kql": f'DeviceProcessEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256 | order by TimeGenerated desc | take 100'},
        {"bucket": "threat_intel",      "type": "run_query", "timespan": "P90D",
         "kql": f'ThreatIntelIndicators | where NetworkIP == "{safe_ip}" or DomainName contains "{safe_domain}" or Url contains "{safe_domain}" | project TimeGenerated, IndicatorId, NetworkIP, DomainName, Url, ConfidenceScore, Description, Active | take 20'},
        {"bucket": "url_clicks",        "type": "run_query", "timespan": "P7D",
         "kql": f'UrlClickEvents | where Url contains "{safe_domain}" or Url contains "{safe_ip}" | project TimeGenerated, AccountUpn, Url, ActionType, NetworkMessageId | take 50'},
        {"bucket": "email_url_info",    "type": "run_query", "timespan": "P7D",
         "kql": f'EmailUrlInfo | where Url contains "{safe_domain}" or Url contains "{safe_ip}" | project TimeGenerated, NetworkMessageId, Url, UrlDomain, UrlLocation | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query", "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{pivot}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",       "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
        {"bucket": "entity_pivot",      "type": "analyze_entity", "value": pivot, "timespan": "P7D"},
    ]

def _checklist_malware(safe_host: str, safe_user: str, safe_hash: str, ts_short: str) -> List[dict]:
    hash_filter = f'| where SHA256 =~ "{safe_hash}" or SHA1 =~ "{safe_hash}" or MD5 =~ "{safe_hash}"' if safe_hash else ""
    return [
        {"bucket": "cmdb",               "type": "cmdb",         "entity": safe_host},
        {"bucket": "file_events",        "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceFileEvents | where DeviceName contains "{safe_host}" {hash_filter} | project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5, InitiatingProcessCommandLine, RequestAccountName | order by TimeGenerated desc | take 100'},
        {"bucket": "process_events",     "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceProcessEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, SHA256, FolderPath | order by TimeGenerated desc | take 100'},
        {"bucket": "device_events",      "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, AdditionalFields, InitiatingProcessCommandLine, FileName | order by TimeGenerated desc | take 100'},
        {"bucket": "network_events",     "type": "run_query",    "timespan": "P1D",
         "kql": f'DeviceNetworkEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine | order by TimeGenerated desc | take 100'},
        {"bucket": "registry_events",    "type": "run_query",    "timespan": ts_short,
         "kql": f'DeviceRegistryEvents | where DeviceName contains "{safe_host}" | project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData | order by TimeGenerated desc | take 100'},
        {"bucket": "email_attachments",  "type": "run_query",    "timespan": "P7D",
         "kql": (f'EmailAttachmentInfo | where SHA256 =~ "{safe_hash}" or SHA1 =~ "{safe_hash}" or MD5 =~ "{safe_hash}" | project TimeGenerated, NetworkMessageId, FileName, SHA256, FileType | take 30'
                 if safe_hash else 'EmailAttachmentInfo | where TimeGenerated > ago(1d) | take 1')},
        {"bucket": "threat_intel",       "type": "run_query",    "timespan": "P90D",
         "kql": (f'ThreatIntelIndicators | where FileHashValue =~ "{safe_hash}" | project TimeGenerated, IndicatorId, FileHashValue, FileHashType, ConfidenceScore, Description | take 20'
                 if safe_hash else 'ThreatIntelIndicators | where TimeGenerated > ago(1d) | take 1')},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" or tostring(Entities) contains "{safe_user}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_host",        "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
    ]

def _checklist_cloud(safe_user: str, safe_ip: str) -> List[dict]:
    return [
        {"bucket": "azure_activity",     "type": "run_query", "timespan": "P2D",
         "kql": f'AzureActivity | where Caller contains "{safe_user}" or CallerIpAddress == "{safe_ip}" | project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, ActivityStatusValue, Properties | order by TimeGenerated desc | take 100'},
        {"bucket": "graph_activity",     "type": "run_query", "timespan": "P2D",
         "kql": f'MicrosoftGraphActivityLogs | where UserId contains "{safe_user}" or IPAddress == "{safe_ip}" | project TimeGenerated, UserId, IPAddress, RequestUri, RequestMethod, ResponseStatusCode, AppId | order by TimeGenerated desc | take 100'},
        {"bucket": "sp_signin",          "type": "run_query", "timespan": "P7D",
         "kql": f'AADServicePrincipalSignInLogs | where ServicePrincipalName contains "{safe_user}" or IPAddress == "{safe_ip}" | project TimeGenerated, ServicePrincipalName, IPAddress, Location, ResultType, AppDisplayName | order by TimeGenerated desc | take 50'},
        {"bucket": "audit_logs",         "type": "run_query", "timespan": "P2D",
         "kql": f'AuditLogs | where tostring(InitiatedBy) contains "{safe_user}" | project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources | order by TimeGenerated desc | take 50'},
        {"bucket": "office_activity",    "type": "run_query", "timespan": "P2D",
         "kql": f'OfficeActivity | where UserId contains "{safe_user}" or ClientIP == "{safe_ip}" | project TimeGenerated, Operation, RecordType, UserId, ClientIP, ResultStatus, OfficeWorkload | order by TimeGenerated desc | take 100'},
        {"bucket": "storage_blob",       "type": "run_query", "timespan": "P2D",
         "kql": f'StorageBlobLogs | where CallerIpAddress == "{safe_ip}" or RequesterObjectId contains "{safe_user}" | project TimeGenerated, OperationName, CallerIpAddress, Uri, StatusCode, RequesterObjectId | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query", "timespan": "P30D",
         "kql": f'SecurityAlert | where tostring(Entities) contains "{safe_user}" or tostring(Entities) contains "{safe_ip}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_user",        "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
        {"bucket": "entity_ip",          "type": "analyze_entity", "value": safe_ip,   "timespan": "P7D"},
    ]

def _checklist_behavioral(safe_user: str, safe_host: str) -> List[dict]:
    return [
        {"bucket": "cmdb",              "type": "cmdb", "entity": safe_host},
        {"bucket": "behavior_analytics","type": "run_query", "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" or DeviceName contains "{safe_host}" | project TimeGenerated, UserName, DeviceName, SourceDevice, ActivityType, ActionType, InvestigationPriority, UsersInsights, DevicesInsights | order by TimeGenerated desc | take 100'},
        {"bucket": "peer_analytics",    "type": "run_query", "timespan": "P30D",
         "kql": f'UserPeerAnalytics | where UserName contains "{safe_user}" | project TimeGenerated, UserName, PeerUserName, Rank, PeerGroupId | take 50'},
        {"bucket": "anomalies",         "type": "run_query", "timespan": "P30D",
         "kql": f'Anomalies | where tostring(UserName) contains "{safe_user}" or tostring(DeviceName) contains "{safe_host}" | project TimeGenerated, AnomalyTemplateName, AnomalyReasons, Score, RuleStatus | take 50'},
        {"bucket": "signin_logs",       "type": "run_query", "timespan": "P7D",
         "kql": f'SigninLogs | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName, RiskLevelDuringSignIn | order by TimeGenerated desc | take 100'},
        {"bucket": "audit_logs",        "type": "run_query", "timespan": "P2D",
         "kql": f'AuditLogs | where tostring(InitiatedBy) contains "{safe_user}" | project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources | order by TimeGenerated desc | take 50'},
        {"bucket": "security_alerts_30d","type": "run_query", "timespan": "P30D",
         "kql": f'SecurityAlert | where tostring(Entities) contains "{safe_user}" or tostring(Entities) contains "{safe_host}" | project TimeGenerated, AlertName, AlertSeverity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "entity_user",       "type": "analyze_entity", "value": safe_user, "timespan": "P7D"},
        {"bucket": "entity_host",       "type": "analyze_entity", "value": safe_host, "timespan": "P7D"},
    ]

def _checklist_default(safe_host: str, safe_user: str, safe_ip: str) -> List[dict]:
    tasks = [
        {"bucket": "cmdb",               "type": "cmdb",         "entity": safe_host},
        {"bucket": "security_alerts_30d","type": "run_query",    "timespan": "P30D",
         "kql": f'SecurityAlert | where CompromisedEntity contains "{safe_host}" or tostring(Entities) contains "{safe_host}" or tostring(Entities) contains "{safe_user}" or tostring(Entities) contains "{safe_ip}" | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Description, Tactics, Techniques | order by TimeGenerated desc | take 50'},
        {"bucket": "behavior_analytics", "type": "run_query",    "timespan": "P30D",
         "kql": f'BehaviorAnalytics | where UserName contains "{safe_user}" or DeviceName contains "{safe_host}" | project TimeGenerated, UserName, DeviceName, ActivityType, InvestigationPriority | order by TimeGenerated desc | take 50'},
        {"bucket": "signin_logs",        "type": "run_query",    "timespan": "P7D",
         "kql": f'SigninLogs | where UserPrincipalName contains "{safe_user}" | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType, AppDisplayName | order by TimeGenerated desc | take 50'},
    ]
    if safe_host:
        tasks.append({"bucket": "entity_host", "type": "analyze_entity", "value": safe_host, "timespan": "P7D"})
    if safe_user:
        tasks.append({"bucket": "entity_user", "type": "analyze_entity", "value": safe_user, "timespan": "P7D"})
    if safe_ip:
        tasks.append({"bucket": "entity_ip",   "type": "analyze_entity", "value": safe_ip,   "timespan": "P7D"})
    return tasks

def _append_site_cl_tasks(tasks: List[dict], safe_host: str) -> List[dict]:
    if not safe_host:
        return tasks
    site = _detect_site_from_hostname(safe_host)
    if not site:
        return tasks
    site_tables = _site_tables_for(site)
    keep_prefixes = ("Windows", "Linux", "Cisco", "Fortinet", "PaloAlto",
                     "Firepower", "VMware", "Checkpoint", "Zscaler")
    filtered = [t for t in site_tables if any(t.startswith(p) for p in keep_prefixes)]
    for table in filtered[:6]:
        tasks.append({
            "bucket": f"site_{table}", "type": "run_query", "timespan": "PT12H",
            "kql": f'{table} | where tostring(*) contains "{safe_host}" | take 30',
        })
    return tasks

# ─────────────────────────────────────────────────────────────
# _auto_detect_checklist — tactic-first shortcut + reordered keyword matching
# ─────────────────────────────────────────────────────────────
def _auto_detect_checklist(alert_names: List[str], tactics: List[str],
                            incident_title: str = "") -> str:
    """
    Route an incident to the correct checklist branch.

    IMPORTANT ORDER:
      1. MITRE tactic shortcut (most reliable signal)
      2. lateral_movement / network / malware (specific tech keywords)
      3. identity (BEFORE cloud — brute-force/signin/credential are identity)
      4. cloud (specific phrases only — never bare "azure")
      5. behavioral / execution
      6. default

    The incident_title is the PRIMARY source of keywords.
    """
    combined = " ".join(
        ([incident_title] if incident_title else [])
        + (alert_names or [])
        + (tactics or [])
    ).lower()

    tactics_lower = [str(t).lower() for t in (tactics or [])]

    # ── 1. MITRE tactic shortcut ──────────────────────────────────────
    if any("credentialaccess" in t or "initialaccess" in t for t in tactics_lower):
        if not any(t in tactics_lower for t in
                   ["execution", "lateralmovement", "defenseevasion",
                    "persistence", "privilegeescalation"]):
            return "identity"

    # ── 2. Specific technique keywords ────────────────────────────────
    if any(k in combined for k in ["smb", "psexec", "lateral", "dcom", "wmi remote",
                                    "pass-the-hash", "rdp anomaly", "remote services"]):
        return "lateral_movement"

    if any(k in combined for k in ["beacon", "c2", "command and control", "dns tunnel",
                                    "proxy anomaly", "outbound anomaly", "exfil"]):
        return "network"

    if any(k in combined for k in ["malware", "ransomware", "virus", "trojan",
                                    "dropper", "hash match"]):
        return "malware"

    # ── 3. Identity BEFORE cloud — brute force is identity, not cloud ─
    if any(k in combined for k in [
        "brute force", "brute-force", "bruteforce",
        "signin", "sign-in", "sign in", "login", "logon",
        "mfa", "credential", "password", "token",
        "impossible travel", "risky user", "risky sign-in",
        "valid account", "break the glass", "break-the-glass",
        "privileged group", "group membership",
        "adaudit", "ad audit", "account compromise",
    ]):
        return "identity"

    # ── 4. Cloud — SPECIFIC phrases only (never bare "azure") ─────────
    if any(k in combined for k in [
        "azure activity", "azure resource", "azure storage", "azure vm",
        "graph api", "service principal sign",
        "sharepoint", "exchange online", "onedrive",
        "storage blob", "power automate", "teams admin",
        "m365 admin", "o365 admin",
    ]):
        return "cloud"

    # ── 5. Behavioral / execution ─────────────────────────────────────
    if any(k in combined for k in ["anomaly", "ueba", "behavioral", "peer analysis",
                                    "deviation"]):
        return "behavioral"

    if any(k in combined for k in ["powershell", "lolbin", "msbuild", "regsvr32",
                                    "rundll32", "mshta", "certutil", "wmic", "msiexec",
                                    "execution chain", "defense evasion", "download cradle"]):
        return "execution"

    return "default"

def _run_checklist_tasks(tasks: List[dict], timespan: str) -> Dict[str, dict]:
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

    if parallel_tasks:
        results.update(_run_queries_parallel(parallel_tasks, timespan))

    for ct in cmdb_tasks_raw:
        entity = ct["entity"]
        if not entity:
            results[ct["bucket"]] = _fail("No host entity — CMDB skipped", code="SKIPPED")
            continue
        results[ct["bucket"]] = _query_cmdb_entity(entity)

    for et in entity_tasks:
        val = et.get("value", "")
        if not val:
            results[et["bucket"]] = _fail("Empty entity value — skipped", code="SKIPPED")
            continue
        results[et["bucket"]] = analyze_entity(val, timespan=et.get("timespan", "P7D"))

    return results

HIGH_SIGNAL_BUCKETS = {
    "process_events", "device_events", "network_events", "network_lateral",
    "file_events", "registry_events", "logon_events",
    "security_alerts_30d", "signin_logs", "behavior_analytics",
    "identity_logon", "identity_directory", "group_changes",
    "audit_logs", "office_activity", "azure_activity", "graph_activity",
    "threat_intel", "url_clicks", "email_url_info", "email_attachments",
    "anomalies",
}

def _summarise_bucket(bucket_id: str, res: dict) -> dict:
    if not res:
        return {"status": "error", "rows": 0, "summary": "null result"}

    if not res.get("ok"):
        code = (res.get("error") or {}).get("code", "")
        if code == "SKIPPED":
            return {"status": "skipped", "rows": 0,
                    "summary": (res.get("error") or {}).get("message", "")}
        return {"status": "error", "rows": 0,
                "summary": (res.get("error") or {}).get("message", "tool error")}

    data = res.get("data") or {}

    if "entity_type" in data:
        return {
            "status":  "ok" if data.get("tables_hit", 0) > 0 else "ok_empty",
            "rows":    data.get("total_events", 0),
            "summary": (f"entity_type={data.get('entity_type')} "
                        f"risk={data.get('risk_level')} "
                        f"tables_hit={data.get('tables_hit')} "
                        f"events={data.get('total_events')}"),
            "detail":  data,
        }

    rows = _la_first_table_dicts(data)
    count = len(rows)
    status = "ok" if count > 0 else "ok_empty"

    if bucket_id in HIGH_SIGNAL_BUCKETS or bucket_id.startswith("site_"):
        MAX_SAMPLE_ROWS, MAX_FIELDS_PER_ROW, MAX_VALUE_CHARS = 15, 25, 1500
    else:
        MAX_SAMPLE_ROWS, MAX_FIELDS_PER_ROW, MAX_VALUE_CHARS = 5, 15, 500

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

def _scan_for_surfaced_hosts(buckets: Dict[str, dict], known_hosts: List[str]) -> List[str]:
    known_lower = {h.lower().split(".")[0] for h in known_hosts if h}
    surfaced = set()
    host_field_candidates = ["DeviceName", "Computer", "HostName", "SourceDevice",
                              "RemoteDeviceName", "Hostname"]
    for bid, b in buckets.items():
        for r in (b.get("sample") or []):
            for f in host_field_candidates:
                v = r.get(f)
                if isinstance(v, str) and v:
                    vlow = v.lower().split(".")[0]
                    if vlow and vlow not in known_lower and len(vlow) > 3:
                        surfaced.add(v)
    return sorted(surfaced)[:5]

# ============================================================
# enrich_ioc tool  (standalone, on-demand)
# ============================================================

_register_tool_def("enrich_ioc",
    ("Look up an IOC (IP, domain, URL, SHA256/SHA1/MD5) in threat-intel feeds. "
     "Provider routing: IPs → AbuseIPDB only; domains / URLs / hashes → VirusTotal only. "
     "(This split conserves VT free-tier quota since AbuseIPDB is the better IP reputation "
     "source anyway and handles far more daily calls.) "
     "Returns reputation verdict ('malicious' / 'suspicious' / 'clean' / 'unknown'), "
     "AV detection counts, community votes, geolocation, ASN, categories, and first-seen dates. "
     "Results are cached in-memory for 1 hour to respect free-tier API rate limits. "
     "Use this when you want ground-truth reputation on an IP/domain/hash surfaced by the "
     "checklist or mentioned in an alert. Automatically runs for primary entities inside "
     "run_investigation_checklist — only call this tool for additional IOCs not already covered."),
    {"value":      "IOC string — IP, domain, URL, SHA256, SHA1, or MD5",
     "value_type": "optional: 'ip' | 'domain' | 'url' | 'sha256' | 'sha1' | 'md5' (auto-detected if omitted)"})

@mcp.tool
def enrich_ioc(value: str, value_type: Optional[str] = None) -> dict:
    if not value:
        return _fail("value is required", code="VALIDATION_ERROR")
    res = _enrich_ioc(value, value_type)
    if not res.get("ok"):
        return _fail(res.get("error", "enrichment failed"), code="ENRICHMENT_ERROR")
    return _ok(res["data"])

# ============================================================
# run_investigation_checklist
# ============================================================

_register_tool_def("run_investigation_checklist",
    ("Executes a parallel server-side batch of telemetry queries for an incident and returns "
     "compact bucket summaries. Auto-detects checklist branch from incident title + alert names "
     "+ MITRE tactics (title is the primary source, alert names and tactics are supplementary). "
     "Also auto-enriches primary IOCs: IPs go to AbuseIPDB; domains and hashes go to VirusTotal. "
     "Escalates the incident if any IOC scores above threshold."),
    {"incident_id":  "Sentinel incident number",
     "checklist":    "auto | execution | identity | lateral_movement | network | malware | cloud | behavioral | default",
     "timespan":     "ISO8601 duration, default P7D"})

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

    inc_res     = investigate_incident(incident_id, timespan=timespan)
    hist_res    = get_similar_incident_history(incident_id, days=30)

    if not inc_res.get("ok"):
        return inc_res

    inc_data    = inc_res.get("data") or {}
    incident    = inc_data.get("incident") or {}
    ents        = inc_data.get("entities") or {}
    alert_names = list((inc_data.get("alerts") or {}).get("names") or [])
    tactics     = list((inc_data.get("mitre") or {}).get("tactics") or [])
    techniques  = list((inc_data.get("mitre") or {}).get("techniques") or [])

    # Pass incident title to the auto-detect so it can use the real rule name
    # rather than relying on ProductName which is always "Azure Sentinel".
    incident_title = str(incident.get("title") or "")

    hosts   = ents.get("hosts") or []
    users   = ents.get("users") or []
    ips     = ents.get("ips")   or []
    domains = ents.get("domains") or []

    hosts = [_normalize_entity_value(h) for h in hosts]
    users = [_normalize_entity_value(u) for u in users]

    safe_host   = escape_kql_string(hosts[0].lower().split(".")[0]) if hosts else ""
    safe_user   = escape_kql_string(users[0]) if users else ""
    safe_ip     = escape_kql_string(ips[0])   if ips   else ""
    safe_domain = escape_kql_string(domains[0]) if domains else ""
    safe_hash   = ""

    cl = (checklist or "auto").strip().lower()
    if cl == "auto":
        cl = _auto_detect_checklist(alert_names, tactics, incident_title=incident_title)

    ts_short = "PT12H"
    ts_long  = "P1D"

    if cl == "execution":
        tasks = _checklist_execution(safe_host, safe_user, ts_short, ts_long)
    elif cl == "identity":
        tasks = _checklist_identity(safe_user, safe_ip, safe_host, ts_long)
    elif cl == "lateral_movement":
        tasks = _checklist_lateral_movement(safe_host, safe_user)
    elif cl == "network":
        tasks = _checklist_network(safe_host, safe_ip, safe_domain)
    elif cl == "malware":
        tasks = _checklist_malware(safe_host, safe_user, safe_hash, ts_short)
    elif cl == "cloud":
        tasks = _checklist_cloud(safe_user, safe_ip)
    elif cl == "behavioral":
        tasks = _checklist_behavioral(safe_user, safe_host)
    else:
        tasks = _checklist_default(safe_host, safe_user, safe_ip)

    tasks = _append_site_cl_tasks(tasks, safe_host)

    raw_results = _run_checklist_tasks(tasks, timespan)

    buckets: Dict[str, dict] = {}
    for task in tasks:
        bid = task["bucket"]
        buckets[bid] = _summarise_bucket(bid, raw_results.get(bid))

    escalation_triggers = []
    sa_bucket = buckets.get("security_alerts_30d", {})
    if sa_bucket.get("status") == "ok":
        for row in (sa_bucket.get("sample") or []):
            name = str(row.get("AlertName") or "").lower()
            desc = str(row.get("Description") or "").lower()
            for trigger in ["cobalt strike", "hands-on-keyboard", "amsi bypass",
                            "ransomware", "dll hijack", "suspicious dll load",
                            "lsass", "mimikatz"]:
                if trigger in name or trigger in desc:
                    escalation_triggers.append({
                        "trigger": trigger,
                        "alert":   row.get("AlertName"),
                        "time":    row.get("TimeGenerated"),
                    })

    expanded_buckets = []
    for bid in ["process_events", "file_events", "registry_events",
                "device_events", "logon_events"]:
        if bid in buckets and buckets[bid].get("rows", 0) == 0:
            expand_task = next((t for t in tasks if t["bucket"] == bid), None)
            if expand_task and expand_task.get("type") == "run_query":
                exp_res = la_query(expand_task["kql"], "P1D")
                buckets[f"{bid}_expanded"] = _summarise_bucket(f"{bid}_expanded", exp_res)
                expanded_buckets.append(bid)

    surfaced_hosts = _scan_for_surfaced_hosts(buckets, hosts)
    surfaced_cmdb = []
    for sh in surfaced_hosts:
        res = _query_cmdb_entity(sh)
        if res.get("ok"):
            rows = _la_first_table_dicts(res["data"])
            if rows:
                surfaced_cmdb.append({"host": sh, "cmdb_rows": len(rows), "sample": rows[:3]})

    site_detected = _detect_site_from_hostname(safe_host) if safe_host else None

    # ── IOC ENRICHMENT ──────────────────────────────────────────────────
    # Provider routing (enforced inside _enrich_ioc):
    #   • IPs        → AbuseIPDB only (VT quota conservation)
    #   • Domains    → VirusTotal only
    #   • URLs       → VirusTotal only
    #   • Hashes     → VirusTotal only
    #
    # Build the IOC list from extracted entities + IPs surfaced in telemetry
    # samples (SigninLogs IPAddress, DeviceNetworkEvents RemoteIP, etc.).
    # Capped per-type to stay within free-tier API limits.
    ioc_list: List[Tuple[str, str]] = []
    seen_iocs = set()

    def _add_ioc(val: str, vt_type: str):
        if not val:
            return
        norm = _normalize_entity_value(str(val))
        if not norm or norm.lower() in seen_iocs:
            return
        seen_iocs.add(norm.lower())
        ioc_list.append((norm, vt_type))

    # IPs — primary + up to N from entities + surfaced from telemetry
    ips_to_enrich: List[str] = []
    if safe_ip:
        ips_to_enrich.append(safe_ip)
    for ip in (ips or []):
        if ip and ip not in ips_to_enrich:
            ips_to_enrich.append(ip)
    # Pull IPs that appeared in telemetry samples
    ip_fields = ["IPAddress", "IpAddress", "RemoteIP", "ClientIP", "CallerIpAddress",
                 "SourceIP", "LocalIP"]
    for bid, b in buckets.items():
        for row in (b.get("sample") or []):
            for f in ip_fields:
                v = row.get(f)
                if isinstance(v, str) and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
                    if v not in ips_to_enrich:
                        ips_to_enrich.append(v)
        if len(ips_to_enrich) >= IOC_MAX_IPS_PER_INCIDENT * 3:
            break
    for ip in ips_to_enrich[:IOC_MAX_IPS_PER_INCIDENT]:
        _add_ioc(ip, "ip")

    # Domains — cap at N
    for dom in (domains or [])[:IOC_MAX_DOMAINS_PER_INCIDENT]:
        _add_ioc(dom, "domain")

    # Hashes — look in FOUR places (priority order, highest first):
    #   0. Incident alert JSON — entities.hashes (from shared extraction
    #      helper; catches hashes nested in Process.ImageFile.FileHashes[]
    #      and standalone FileHash entities that the old path missed)
    #   1. Incident entity list — entities.files, entities.processes
    #      (only catches hash-shaped file names)
    #   2. Telemetry sample rows (SHA256, SHA1, MD5,
    #      InitiatingProcessSHA256, etc.)
    hashes_found: List[Tuple[str, str]] = []
    _seen_hashes: set = set()

    def _collect_hash(val: str):
        if not val or not isinstance(val, str):
            return
        v = val.strip()
        if v.lower() in _seen_hashes:
            return
        t = _detect_ioc_type(v)
        if t in ("sha256", "sha1", "md5"):
            _seen_hashes.add(v.lower())
            hashes_found.append((v, t))

    # Source 0: hashes extracted by the shared entity helper (highest-fidelity —
    # these are guaranteed-real hashes from File.FileHashes[] in alert JSON)
    for v in (ents.get("hashes") or []):
        _collect_hash(str(v))

    # Source 1: entity list — only catches hash-shaped strings in file/process names
    for entity_list in [(ents.get("files") or []),
                        (ents.get("processes") or [])]:
        for v in entity_list:
            _collect_hash(str(v))

    # Source 2: telemetry samples — scan for known hash column names
    hash_fields = [
        "SHA256", "SHA1", "MD5",
        "InitiatingProcessSHA256", "InitiatingProcessSHA1", "InitiatingProcessMD5",
        "FileHashSha256", "FileHashSha1", "FileHashMd5",
        "FileSHA256",
    ]
    for bid, b in buckets.items():
        for row in (b.get("sample") or []):
            for f in hash_fields:
                v = row.get(f)
                if v:
                    _collect_hash(str(v))
        # Stop scanning once we have enough candidates
        if len(hashes_found) >= IOC_MAX_HASHES_PER_INCIDENT * 3:
            break

    for h, ht in hashes_found[:IOC_MAX_HASHES_PER_INCIDENT]:
        _add_ioc(h, ht)

    # Run enrichment in parallel (rate-limited per provider internally)
    ioc_enrichment: Dict[str, dict] = {}
    if ioc_list and (_VT_API_KEYS or ABUSEIPDB_API_KEY):
        enrichment_raw = _enrich_iocs_parallel(ioc_list, max_workers=4)
        for key, res in enrichment_raw.items():
            if res.get("ok"):
                ioc_enrichment[key] = res["data"]
            else:
                ioc_enrichment[key] = {
                    "ioc": key,
                    "status": "error",
                    "error": res.get("error"),
                }

    # Feed malicious IOCs into the escalation trigger list
    for ioc_key, ioc_data in ioc_enrichment.items():
        if not isinstance(ioc_data, dict):
            continue
        if ioc_data.get("escalate") is True:
            vt = ioc_data.get("virustotal") or {}
            ab = ioc_data.get("abuseipdb") or {}
            escalation_triggers.append({
                "trigger": "ioc_malicious",
                "ioc":     ioc_key,
                "ioc_type":ioc_data.get("ioc_type"),
                "verdict": ioc_data.get("verdict"),
                "vt_malicious_engines":  vt.get("malicious_engines") if isinstance(vt, dict) else None,
                "abuseipdb_score":       ab.get("abuse_confidence_score") if isinstance(ab, dict) else None,
                "vt_link":  vt.get("gui_link") if isinstance(vt, dict) else None,
                "ab_link":  ab.get("gui_link") if isinstance(ab, dict) else None,
            })

    # Summary counts for the agent
    ioc_summary = {
        "total":         len(ioc_enrichment),
        "malicious":     sum(1 for v in ioc_enrichment.values()
                             if isinstance(v, dict) and v.get("verdict") == "malicious"),
        "suspicious":    sum(1 for v in ioc_enrichment.values()
                             if isinstance(v, dict) and v.get("verdict") == "suspicious"),
        "clean":         sum(1 for v in ioc_enrichment.values()
                             if isinstance(v, dict) and v.get("verdict") == "clean"),
        "unknown":       sum(1 for v in ioc_enrichment.values()
                             if isinstance(v, dict) and v.get("verdict") == "unknown"),
        "errors":        sum(1 for v in ioc_enrichment.values()
                             if isinstance(v, dict) and v.get("status") == "error"),
        "providers_enabled": {
            "virustotal": bool(_VT_API_KEYS),
            "abuseipdb":  bool(ABUSEIPDB_API_KEY),
        },
        "routing": {
            "ip":     "abuseipdb_only",
            "domain": "virustotal_only",
            "url":    "virustotal_only",
            "hash":   "virustotal_only",
        },
    }

    return _ok({
        "incident_id":          incident_id,
        "incident_title":       incident_title,
        "checklist_used":       cl,
        "checklist_auto":       checklist == "auto",
        "site_detected":        site_detected,
        "entities_extracted": {
            "hosts":        hosts,
            "users":        users,
            "ips":          ips,
            "domains":      domains,
            "primary_host": safe_host,
            "primary_user": safe_user,
            "primary_ip":   safe_ip,
        },
        "mitre": {
            "tactics":    tactics,
            "techniques": techniques,
        },
        "telemetry":            buckets,
        "escalation_triggers":  escalation_triggers,
        "escalation_fired":     bool(escalation_triggers),
        "expanded_buckets":     expanded_buckets,
        "surfaced_hosts":       surfaced_hosts,
        "surfaced_hosts_cmdb":  surfaced_cmdb,
        "ioc_enrichment":       ioc_enrichment,
        "ioc_summary":          ioc_summary,
        "checklist_coverage": {
            t["bucket"]: buckets.get(t["bucket"], {}).get("status", "missing")
            for t in tasks
        },
        "similar_history_available": bool(hist_res.get("ok")),
    })

# ─────────────────────────────────────────────────────────────
_register_tool_def("get_similar_incident_history",
    ("Looks up prior Sentinel incidents over the last N days that share the same title. "
     "Returns classification history, status breakdown, owner."),
    {"incident_id": "Sentinel incident number",
     "days": "optional integer 1–90, default 30"})

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
