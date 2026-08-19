from __future__ import annotations

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.trace import Span, Tracer

from .config import Settings


def configure_tracing(settings: Settings, service_name: str) -> Tracer:
    endpoint = f"{str(settings.otel_exporter_otlp_endpoint).rstrip('/')}/v1/traces"
    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: service_name}))
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    return trace.get_tracer("exposure360.phase1", "0.1.0")


def trace_identifiers(span: Span | None = None) -> tuple[str | None, str | None]:
    active_span = span or trace.get_current_span()
    span_context = active_span.get_span_context()
    if not span_context.is_valid:
        return None, None
    return f"{span_context.trace_id:032x}", f"{span_context.span_id:016x}"
