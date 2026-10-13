"""
OpenTelemetry Tracer Middleware for AI Agent Runtime and Model Context Protocol (MCP).
Captures prompt context, tool names, tool arguments, call depth, and execution spans.
"""
from __future__ import annotations

import json
import time
import uuid
import datetime
from contextlib import contextmanager
from typing import Dict, Any, List, Optional, Generator

# Attempt OpenTelemetry imports with seamless fallback
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider, ReadableSpan
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, InMemorySpanExporter
    from opentelemetry.trace import Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False


class AgentTelemetryTracer:
    """
    OpenTelemetry-compliant instrumentation manager for AI Agent MCP tool executions.
    Records structured spans conforming to MCP telemetry standards.
    """

    def __init__(self, service_name: str = "agentic-soc-guard-mcp"):
        self.service_name = service_name
        self._captured_spans: List[Dict[str, Any]] = []

        if OTEL_AVAILABLE:
            self.provider = TracerProvider()
            self.memory_exporter = InMemorySpanExporter()
            self.provider.add_span_processor(SimpleSpanProcessor(self.memory_exporter))
            self.tracer = self.provider.get_tracer(service_name)
        else:
            self.provider = None
            self.memory_exporter = None
            self.tracer = None

    def clear(self) -> None:
        """Clear recorded spans from memory."""
        self._captured_spans.clear()
        if OTEL_AVAILABLE and self.memory_exporter:
            self.memory_exporter.clear()

    @contextmanager
    def trace_tool_call(
        self,
        tool_name: str,
        tool_arguments: Any,
        agent_id: str = "default_agent",
        prompt: Optional[str] = None,
        call_depth: int = 1,
        model: str = "mock-llm",
        extra_attributes: Optional[Dict[str, Any]] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Context manager to instrument an MCP tool execution.
        Captures start time, arguments, execution status, and emits standard span.
        """
        start_ns = time.time_ns()
        start_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        span_id = uuid.uuid4().hex[:16]
        trace_id = uuid.uuid4().hex[:32]

        # Normalize arguments
        if isinstance(tool_arguments, (dict, list)):
            args_serialized = json.dumps(tool_arguments)
        else:
            args_serialized = str(tool_arguments)

        # Standard MCP OpenTelemetry attributes
        attributes: Dict[str, Any] = {
            "agent.session_id": agent_id,
            "agent.prompt": prompt or "",
            "agent.tool.name": tool_name,
            "agent.tool.arguments": args_serialized,
            "agent.call_depth": call_depth,
            "agent.model": model,
            "mcp.protocol.version": "2024-11-05",
            "service.name": self.service_name,
        }
        if extra_attributes:
            for k, v in extra_attributes.items():
                attributes[k] = json.dumps(v) if isinstance(v, (dict, list)) else v

        span_record: Dict[str, Any] = {
            "name": f"mcp.tool.{tool_name}",
            "context": {
                "trace_id": trace_id,
                "span_id": span_id,
                "trace_state": "{}",
            },
            "parent_id": None,
            "start_time": start_iso,
            "end_time": None,
            "status": {"status_code": "OK"},
            "attributes": attributes,
        }

        otel_span = None
        if OTEL_AVAILABLE and self.tracer:
            otel_span = self.tracer.start_span(f"mcp.tool.{tool_name}")
            for k, v in attributes.items():
                otel_span.set_attribute(k, v)

        try:
            yield span_record
            span_record["status"]["status_code"] = "OK"
            if otel_span:
                otel_span.set_status(Status(StatusCode.OK))
        except Exception as exc:
            span_record["status"] = {
                "status_code": "ERROR",
                "description": str(exc),
            }
            if otel_span:
                otel_span.set_status(Status(StatusCode.ERROR, str(exc)))
                otel_span.record_exception(exc)
            raise
        finally:
            end_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            span_record["end_time"] = end_iso
            self._captured_spans.append(span_record)
            if otel_span:
                otel_span.end()

    def record_manual_span(
        self,
        tool_name: str,
        tool_arguments: Any,
        agent_id: str = "default_agent",
        prompt: Optional[str] = None,
        call_depth: int = 1,
        model: str = "mock-llm",
        status_code: str = "OK",
        error_message: Optional[str] = None,
        extra_attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Directly records a completed span dictionary into telemetry history."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        span_id = uuid.uuid4().hex[:16]
        trace_id = uuid.uuid4().hex[:32]

        if isinstance(tool_arguments, (dict, list)):
            args_serialized = json.dumps(tool_arguments)
        else:
            args_serialized = str(tool_arguments)

        attrs: Dict[str, Any] = {
            "agent.session_id": agent_id,
            "agent.prompt": prompt or "",
            "agent.tool.name": tool_name,
            "agent.tool.arguments": args_serialized,
            "agent.call_depth": call_depth,
            "agent.model": model,
            "mcp.protocol.version": "2024-11-05",
            "service.name": self.service_name,
        }
        if extra_attributes:
            attrs.update(extra_attributes)

        status_obj = {"status_code": status_code}
        if error_message:
            status_obj["description"] = error_message

        span_record = {
            "name": f"mcp.tool.{tool_name}",
            "context": {
                "trace_id": trace_id,
                "span_id": span_id,
                "trace_state": "{}",
            },
            "parent_id": None,
            "start_time": now_iso,
            "end_time": now_iso,
            "status": status_obj,
            "attributes": attrs,
        }
        self._captured_spans.append(span_record)
        return span_record

    def get_captured_spans(self) -> List[Dict[str, Any]]:
        """Returns all captured spans recorded in memory."""
        return list(self._captured_spans)

    def save_spans_to_file(self, filepath: str) -> None:
        """Serializes captured spans to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self._captured_spans, f, indent=2)

    @staticmethod
    def load_spans_from_file(filepath: str) -> List[Dict[str, Any]]:
        """Loads span records from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)


# Singleton tracer instance
global_tracer = AgentTelemetryTracer()
