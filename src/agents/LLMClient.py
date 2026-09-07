from __future__ import annotations

import getpass
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LLMMessage:
    role: str
    content: str


class OpenRouterClient:
    def __init__(self, provider_config: dict[str, Any]) -> None:
        self.base_url = provider_config.get("base_url", "https://openrouter.ai/api/v1")
        self.api_key = self._resolve_api_key(provider_config.get("api_key", {}))
        headers = provider_config.get("default_headers", {}) or {}
        self.default_headers = {
            "HTTP-Referer": headers.get("http_referer") or "http://localhost",
            "X-Title": headers.get("x_title") or "VulB",
        }

    def chat_completion(
        self,
        messages: list[LLMMessage],
        model: str,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        timeout_seconds: int = 120,
        response_format: Any = None,
        reasoning: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "messages": [message.__dict__ for message in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if isinstance(response_format, dict):
            payload["response_format"] = response_format
            if response_format.get("type") == "json_schema":
                payload["provider"] = {"require_parameters": True}
        elif response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        if reasoning and reasoning.get("enabled"):
            payload["reasoning"] = {"effort": reasoning.get("effort", "medium")}

        request = urllib.request.Request(
            url=f"{self.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                **self.default_headers,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(format_openrouter_http_error(exc.code, detail)) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"OpenRouter request failed: {exc.reason}") from exc

    def _resolve_api_key(self, api_key_config: dict[str, Any]) -> str:
        env_name = api_key_config.get("env_fallback", "OPENROUTER_API_KEY")
        api_key = os.environ.get(env_name)
        if api_key:
            return normalize_api_key(api_key)
        if api_key_config.get("source") == "keyboard":
            prompt = api_key_config.get("prompt", f"Enter {env_name}: ")
            return normalize_api_key(getpass.getpass(prompt))
        raise RuntimeError(f"Missing API key. Set {env_name}.")


def normalize_api_key(api_key: str) -> str:
    normalized = api_key.strip().strip("\"'")
    if normalized.lower().startswith("bearer "):
        normalized = normalized.split(None, 1)[1].strip()
    return normalized


def mask_api_key(api_key: str) -> str:
    normalized = normalize_api_key(api_key)
    if len(normalized) <= 12:
        return "***"
    return f"{normalized[:8]}...{normalized[-4:]}"


def format_openrouter_http_error(status_code: int, detail: str) -> str:
    message = extract_error_message(detail).rstrip(".")
    if status_code == 401:
        return (
            "OpenRouter authentication failed (HTTP 401): "
            f"{message or 'unauthorized'}. Check OPENROUTER_API_KEY, paste a valid OpenRouter key, "
            "or choose no at Use LLM API to run dry-run mode."
        )
    return f"OpenRouter request failed: HTTP {status_code}: {message or detail}"


def extract_error_message(detail: str) -> str:
    try:
        payload = json.loads(detail)
    except json.JSONDecodeError:
        return detail.strip()
    error = payload.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str):
            return message
    return detail.strip()


class DryRunClient:
    def chat_completion(self, messages: list[LLMMessage], **_: Any) -> dict[str, Any]:
        user_prompt = messages[-1].content if messages else ""
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "dry_run": True,
                                "prompt_preview": user_prompt[:2000],
                            }
                        )
                    }
                }
            ]
        }
