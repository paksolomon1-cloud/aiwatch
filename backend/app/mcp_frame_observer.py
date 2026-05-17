from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from app.mcp_normalizer import normalize_tools_call_frame, normalize_tools_list_frame
from app.schemas import AgentEvent

DEFAULT_MAX_PENDING_REQUEST_METHODS = 1024
JsonRpcRequestIdKey = tuple[str, Any]


@dataclass(frozen=True)
class ObservedMcpFrame:
    method: str | None
    events: list[AgentEvent] = field(default_factory=list)


def request_id_key(value: Any) -> JsonRpcRequestIdKey | None:
    if value is None:
        return None
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        return ("float", value)
    return (type(value).__name__, repr(value))


class McpFrameObserver:
    def __init__(
        self,
        *,
        server_id: str,
        session_id: str,
        agent_id: str,
        max_pending_request_methods: int = DEFAULT_MAX_PENDING_REQUEST_METHODS,
    ) -> None:
        self._server_id = server_id
        self._session_id = session_id
        self._agent_id = agent_id
        self._max_pending_request_methods = max_pending_request_methods
        self._request_methods: OrderedDict[JsonRpcRequestIdKey, str] = OrderedDict()
        self._request_methods_lock = threading.Lock()

    @property
    def pending_request_count(self) -> int:
        with self._request_methods_lock:
            return len(self._request_methods)

    def observe_client_frame(self, frame: dict[str, Any]) -> ObservedMcpFrame:
        method = _frame_method(frame)
        request_key = request_id_key(frame.get("id"))
        if method is not None and request_key is not None:
            self._remember_request_method(request_key, method)

        return ObservedMcpFrame(
            method=method,
            events=normalize_tools_call_frame(
                frame=frame,
                server_id=self._server_id,
                session_id=self._session_id,
                agent_id=self._agent_id,
            ),
        )

    def observe_server_frame(self, frame: dict[str, Any]) -> ObservedMcpFrame:
        request_method = self._pop_request_method(request_id_key(frame.get("id")))
        return ObservedMcpFrame(
            method=request_method,
            events=normalize_tools_list_frame(
                frame=frame,
                server_id=self._server_id,
                session_id=self._session_id,
                agent_id=self._agent_id,
                request_method=request_method,
            ),
        )

    def _remember_request_method(self, request_key: JsonRpcRequestIdKey, method: str) -> None:
        with self._request_methods_lock:
            self._request_methods[request_key] = method
            self._request_methods.move_to_end(request_key)
            while len(self._request_methods) > self._max_pending_request_methods:
                self._request_methods.popitem(last=False)

    def _pop_request_method(self, request_key: JsonRpcRequestIdKey | None) -> str | None:
        if request_key is None:
            return None
        with self._request_methods_lock:
            return self._request_methods.pop(request_key, None)


def _frame_method(frame: dict[str, Any]) -> str | None:
    method = frame.get("method")
    return method if isinstance(method, str) else None
