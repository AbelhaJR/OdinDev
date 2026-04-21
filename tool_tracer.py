"""
tool_tracer.py
==============

Thread-local audit trail for every MCP tool call made during an
investigation. The checklist tool starts a trace, the inner helpers
(la_query, _enrich_ioc, _query_cmdb_entity, …) append to it, and the
report renderer reads it back out.

Zero overhead when no trace is active — the add() call becomes a no-op.

Usage in mcp_server.py:

    from tool_tracer import tracer, traced

    # Option A — explicit block:
    with tracer.start("run_investigation_checklist"):
        result = _run_checklist(...)
        trace = tracer.finish()
        result["tool_trace"] = trace

    # Option B — wrap the helpers once, then every call site is traced:
    la_query      = traced("la_query",      summarize_input=_summarize_kql)(la_query)
    _enrich_ioc   = traced("enrich_ioc")(_enrich_ioc)
    _query_cmdb_entity = traced("query_cmdb")(_query_cmdb_entity)
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional


class _Tracer:
    """Per-thread tool-call accumulator. Safe under ThreadPoolExecutor."""

    def __init__(self) -> None:
        self._tls = threading.local()
        # Tracking of child-thread traces that need to flush back to parent
        self._child_traces: Dict[int, List[dict]] = {}
        self._lock = threading.Lock()
        self._parent_tls_map: Dict[int, "_Tracer"] = {}

    # ── public API ────────────────────────────────────────────────

    @contextmanager
    def start(self, label: str):
        """Begin a new trace. `label` is just a name for logging."""
        events: List[dict] = []
        t0 = time.time()
        self._set(events, t0, label)
        try:
            yield
        finally:
            # Don't clear on exit — caller may want to call finish() after the
            # `with` block. finish() resets.
            pass

    def finish(self) -> List[dict]:
        """Pop and return the current trace. Clears thread-local state."""
        events = getattr(self._tls, "events", None) or []
        self._clear()
        return list(events)

    def is_active(self) -> bool:
        return getattr(self._tls, "events", None) is not None

    def add(self, event: dict) -> None:
        """Append one tool-call event. No-op if no trace is active."""
        events = getattr(self._tls, "events", None)
        if events is None:
            return
        events.append(event)

    def push_parent(self) -> Optional[List[dict]]:
        """Return the parent trace events list for child-thread inheritance."""
        return getattr(self._tls, "events", None)

    def attach(self, parent_events: Optional[List[dict]]) -> None:
        """Attach a parent's events list to this thread's TLS (for workers)."""
        if parent_events is not None:
            self._tls.events = parent_events
            self._tls.t0 = getattr(self._tls, "t0", time.time())
            self._tls.label = getattr(self._tls, "label", "worker")

    def detach(self) -> None:
        """Remove the attached parent list from this worker thread."""
        self._clear()

    # ── internals ────────────────────────────────────────────────

    def _set(self, events: List[dict], t0: float, label: str) -> None:
        self._tls.events = events
        self._tls.t0     = t0
        self._tls.label  = label

    def _clear(self) -> None:
        self._tls.events = None
        self._tls.t0     = None
        self._tls.label  = None


tracer = _Tracer()


# ═══════════════════════════════════════════════════════════════════════
# Decorator helpers
# ═══════════════════════════════════════════════════════════════════════

def traced(
    tool_name: str,
    *,
    summarize_input: Optional[Callable[..., str]] = None,
    summarize_output: Optional[Callable[[Any], str]] = None,
) -> Callable:
    """
    Wrap a function so every call is logged to the active trace (if any).

    tool_name:         display name shown in the report ("la_query", "enrich_ioc")
    summarize_input:   (args, kwargs) → short text describing the inputs
    summarize_output:  result → short text describing the outputs

    Default summaries: ok/error + dict key count for outputs; first arg for inputs.
    """
    def _decorator(fn: Callable) -> Callable:
        def _wrapper(*args, **kwargs):
            if not tracer.is_active():
                return fn(*args, **kwargs)

            t0 = time.time()
            in_text = ""
            try:
                in_text = (summarize_input(*args, **kwargs)
                           if summarize_input else _default_input_summary(args, kwargs))
            except Exception:
                in_text = "—"

            status = "ok"
            out_text = ""
            error_text = None
            result = None

            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                status = "exception"
                error_text = str(e)[:200]
                tracer.add({
                    "tool":        tool_name,
                    "status":      status,
                    "input":       in_text,
                    "output":      "",
                    "error":       error_text,
                    "duration_ms": int((time.time() - t0) * 1000),
                    "t":           time.strftime("%H:%M:%S"),
                })
                raise

            # Infer status/summary from the MCP envelope {ok: bool, data/error}
            if isinstance(result, dict):
                if result.get("ok") is False:
                    status     = "error"
                    error_text = str(result.get("error") or "")[:200]
                elif result.get("ok") is True:
                    status = "ok"
                try:
                    out_text = (summarize_output(result) if summarize_output
                                else _default_output_summary(result))
                except Exception:
                    out_text = "—"

            tracer.add({
                "tool":        tool_name,
                "status":      status,
                "input":       in_text,
                "output":      out_text,
                "error":       error_text,
                "duration_ms": int((time.time() - t0) * 1000),
                "t":           time.strftime("%H:%M:%S"),
            })
            return result

        _wrapper.__name__  = fn.__name__
        _wrapper.__doc__   = fn.__doc__
        _wrapper.__wrapped__ = fn  # type: ignore[attr-defined]
        return _wrapper

    return _decorator


# ─────────────────────────────────────────────────────────────────────
# Default summarizers
# ─────────────────────────────────────────────────────────────────────

def _default_input_summary(args: tuple, kwargs: dict) -> str:
    if args:
        v = args[0]
        if isinstance(v, str):
            return v[:160] + ("…" if len(v) > 160 else "")
        return type(v).__name__
    if kwargs:
        k = next(iter(kwargs))
        return f"{k}={str(kwargs[k])[:80]}"
    return "—"


def _default_output_summary(result: dict) -> str:
    if not result.get("ok"):
        return str(result.get("error") or "error")[:160]
    data = result.get("data") or {}
    # Log Analytics-ish response: tables[0].rows
    if isinstance(data, dict) and isinstance(data.get("tables"), list) and data["tables"]:
        rows = data["tables"][0].get("rows") or []
        return f"{len(rows)} row{'s' if len(rows) != 1 else ''}"
    # IOC enrichment response
    if isinstance(data, dict) and "verdict" in data:
        verdict = data.get("verdict")
        return f"verdict={verdict}"
    # Generic dict
    if isinstance(data, dict):
        return f"{len(data)} field{'s' if len(data) != 1 else ''}"
    if isinstance(data, list):
        return f"{len(data)} item{'s' if len(data) != 1 else ''}"
    return "ok"


# ─────────────────────────────────────────────────────────────────────
# KQL-specific summarizer — nicer than raw-string truncation
# ─────────────────────────────────────────────────────────────────────

_KQL_TABLE_RE = None

def summarize_kql(kql: str, *_a, **_kw) -> str:
    """
    For la_query(kql, timespan) calls. Produce a one-liner like:
        "DeviceProcessEvents | where DeviceName contains 'ds800' | take 100"
    Collapses whitespace and limits to ~140 chars.
    """
    import re
    global _KQL_TABLE_RE
    if _KQL_TABLE_RE is None:
        _KQL_TABLE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|")

    if not kql:
        return "—"
    s = " ".join(str(kql).split())
    # Peek at the table for convenience
    m = _KQL_TABLE_RE.match(str(kql))
    if m:
        table = m.group(1)
        # Show "Table | …" with rest truncated
        rest = s[len(table):].strip(" |")
        trunc = rest[:120] + ("…" if len(rest) > 120 else "")
        return f"{table} | {trunc}" if trunc else table
    return s[:140] + ("…" if len(s) > 140 else "")


# ─────────────────────────────────────────────────────────────────────
# ThreadPoolExecutor helper: propagate the active trace into workers
# ─────────────────────────────────────────────────────────────────────

def run_in_pool_with_trace(pool, fn, *args, **kwargs):
    """
    Submit `fn` to the ThreadPoolExecutor `pool` such that any tracer.add()
    inside fn lands in the current thread's trace.

    Usage (replaces pool.submit(fn, *a, **kw)):
        fut = run_in_pool_with_trace(pool, fn, arg1, arg2)
    """
    parent_events = tracer.push_parent()

    def _wrapper():
        if parent_events is not None:
            tracer.attach(parent_events)
        try:
            return fn(*args, **kwargs)
        finally:
            if parent_events is not None:
                tracer.detach()

    return pool.submit(_wrapper)
