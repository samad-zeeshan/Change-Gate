"""
Thin OpenTelemetry wrapper that no-ops when OTel is not installed or configured.

Callers always get a span handle, so instrumentation code never has to check first.
"""

from __future__ import annotations

import contextlib
import os
from typing import Iterator, Optional

_ENABLED = False
_tracer = None

try:  # pragma: no cover - exercised only when OTel is installed
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _OTEL_AVAILABLE = True
except Exception:  # noqa: BLE001
    _OTEL_AVAILABLE = False


_provider = None


def setup_telemetry(service_name: str) -> None:
    global _ENABLED, _tracer, _provider
    if not _OTEL_AVAILABLE:
        return
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        except Exception:  # noqa: BLE001
            pass
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(service_name)
    _provider = provider
    _ENABLED = True


def shutdown() -> None:
    global _provider
    if _provider is not None:  # pragma: no cover - requires the OTel SDK + endpoint
        try:
            _provider.shutdown()
        except Exception:  # noqa: BLE001
            pass
        finally:
            _provider = None


@contextlib.contextmanager
def span(name: str, **attributes) -> Iterator["_SpanHandle"]:
    # Hand back an inert handle when telemetry is off so call sites can use the
    # same `with span(...) as sp` shape whether or not OTel is wired up.
    handle = _SpanHandle()
    if _ENABLED and _tracer is not None:  # pragma: no cover
        with _tracer.start_as_current_span(name) as otel_span:
            for k, v in attributes.items():
                if v is not None:
                    otel_span.set_attribute(k, v)
            handle.bind(otel_span)
            try:
                yield handle
            finally:
                pass
    else:
        yield handle


class _SpanHandle:

    def __init__(self) -> None:
        self._span = None

    def bind(self, otel_span) -> None:  # pragma: no cover
        self._span = otel_span

    def set(self, key: str, value) -> None:
        if self._span is not None and value is not None:  # pragma: no cover
            self._span.set_attribute(key, value)


def current_trace_id() -> Optional[str]:
    if not (_ENABLED and _OTEL_AVAILABLE):  # pragma: no cover
        return None
    try:
        ctx = trace.get_current_span().get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x")
    except Exception:  # noqa: BLE001
        return None
    return None
