"""LLM API client for interpretation-only semantic agents."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from vulsor.config import AgentLLMConfig


@dataclass(frozen=True)
class LLMResult:
    """Result returned by the semantic LLM client."""

    status: str
    content: str | None
    parsed_json: dict[str, Any] | None
    error: str | None
    usage: dict[str, int]


class SemanticLLMClient:
    """Small OpenAI-compatible chat completions client.

    The client is deliberately transport-only. Agent boundaries, prompts, and
    fact filtering stay outside this module.
    """

    def __init__(self, config: AgentLLMConfig) -> None:
        self.config = config

    def complete_json(
        self,
        *,
        system_prompt: str,
        user_payload: dict[str, Any],
    ) -> LLMResult:
        if self.config.provider not in {"openrouter", "openai_compatible"}:
            return LLMResult(
                status="error",
                content=None,
                parsed_json=None,
                error=f"unsupported LLM provider: {self.config.provider}",
                usage={},
            )

        api_key = os.environ.get(self.config.api_key_env)
        if not api_key:
            return LLMResult(
                status="disabled",
                content=None,
                parsed_json=None,
                error=f"missing environment variable: {self.config.api_key_env}",
                usage={},
            )

        body = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_output_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": json.dumps(user_payload, ensure_ascii=True),
                },
            ],
        }
        request = urllib.request.Request(
            self.config.base_url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                **self.config.extra_headers,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.timeout_seconds,
            ) as response:
                raw = response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError) as exc:
            return LLMResult(
                status="error",
                content=None,
                parsed_json=None,
                error=str(exc),
                usage={},
            )

        try:
            payload = json.loads(raw)
            content = payload["choices"][0]["message"]["content"]
            usage = _usage(payload.get("usage"))
            if not isinstance(content, str):
                raise TypeError("response content is not a string")
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            return LLMResult(
                status="error",
                content=raw,
                parsed_json=None,
                error=f"unexpected LLM response shape: {exc}",
                usage={},
            )

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            return LLMResult(
                status="error",
                content=content,
                parsed_json=None,
                error=f"LLM response was not JSON: {exc}",
                usage=usage,
            )

        return LLMResult(
            status="ok",
            content=content,
            parsed_json=parsed,
            error=None,
            usage=usage,
        )


def _usage(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}

    return {
        key: int(value[key])
        for key in ("prompt_tokens", "completion_tokens", "total_tokens")
        if isinstance(value.get(key), int)
    }
