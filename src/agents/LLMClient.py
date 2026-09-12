from __future__ import annotations

import getpass
import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LLMMessage:
    role: str
    content: str


class OpenAICompatibleClient:
    def __init__(self, provider_config: dict[str, Any], cache_dir: Path | None = None) -> None:
        self.provider_name = provider_config.get("name", "openai-compatible")
        self.base_url = provider_config.get("base_url", "https://api.deepseek.com")
        self.api_key_env_name = provider_config.get("api_key", {}).get("env_fallback", "DEEPSEEK_API_KEY")
        self.api_key = self._resolve_api_key(provider_config.get("api_key", {}))
        cache_config = provider_config.get("cache", {}) or {}
        self.cache_enabled = bool(cache_config.get("enabled", True))
        configured_cache_dir = cache_config.get("dir")
        self.cache_dir = Path(configured_cache_dir) if configured_cache_dir else cache_dir
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
            if response_format.get("type") == "json_schema":
                json_schema = response_format.get("json_schema", {})
                root_schema = json_schema.get("schema", {}) if isinstance(json_schema, dict) else {}
                # Many OpenAI-compatible providers only support json_object mode.
                # Do not force that mode for a top-level array (Stage 3); client-side
                # schema validation will enforce the raw array contract instead.
                if not (isinstance(root_schema, dict) and root_schema.get("type") == "array"):
                    payload["response_format"] = {"type": "json_object"}
            else:
                payload["response_format"] = response_format
        elif response_format == "json":
            payload["response_format"] = {"type": "json_object"}
        if reasoning:
            if reasoning.get("enabled"):
                payload["thinking"] = {"type": "enabled"}
                payload["reasoning_effort"] = reasoning.get("effort", "medium")
            else:
                payload["thinking"] = {"type": "disabled"}

        cached = self._read_cached_response(payload)
        if cached is not None:
            return cached

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
                raw = json.loads(response.read().decode("utf-8"))
                self._write_cached_response(payload, raw)
                return raw
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(format_provider_http_error(self.provider_name, self.api_key_env_name, exc.code, detail)) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"{self.provider_name} request failed: {exc.reason}") from exc

    def _cache_key(self, payload: dict[str, Any]) -> str:
        cache_payload = {
            "provider": self.provider_name,
            "base_url": self.base_url.rstrip("/"),
            "endpoint": "/chat/completions",
            "payload": payload,
        }
        encoded = json.dumps(cache_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _cache_path(self, payload: dict[str, Any]) -> Path | None:
        if not self.cache_enabled or self.cache_dir is None:
            return None
        return self.cache_dir / f"{self._cache_key(payload)}.json"

    def _read_cached_response(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        path = self._cache_path(payload)
        if path is None or not path.exists():
            return None
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        raw = envelope.get("response")
        if not isinstance(raw, dict) or not is_cacheable_response(raw):
            return None
        cached_raw = dict(raw)
        cached_raw["cached"] = True
        return cached_raw

    def _write_cached_response(self, payload: dict[str, Any], response: dict[str, Any]) -> None:
        path = self._cache_path(payload)
        if path is None or not is_cacheable_response(response):
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            envelope = {
                "provider": self.provider_name,
                "model": payload.get("model"),
                "response": response,
            }
            path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError:
            return

    def _resolve_api_key(self, api_key_config: dict[str, Any]) -> str:
        env_name = api_key_config.get("env_fallback", "DEEPSEEK_API_KEY")
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


def format_provider_http_error(provider_name: str, api_key_env_name: str, status_code: int, detail: str) -> str:
    message = extract_error_message(detail).rstrip(".")
    if status_code == 401:
        provider_display = provider_name.replace("-", " ").title()
        return (
            f"{provider_display} authentication failed (HTTP 401): "
            f"{message or 'unauthorized'}. Check {api_key_env_name}, paste a valid API key, "
            "or choose no at Use LLM API to run dry-run mode."
        )
    return f"{provider_name} request failed: HTTP {status_code}: {message or detail}"


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


def zero_token_usage() -> dict[str, int]:
    return {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "input_tokens": 0,
        "output_tokens": 0,
    }


def is_cacheable_response(response: dict[str, Any]) -> bool:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return False
    choice = choices[0]
    if choice.get("finish_reason") == "length":
        return False
    message = choice.get("message")
    if not isinstance(message, dict):
        return False
    content = message.get("content")
    return isinstance(content, str) and bool(content.strip())


class DryRunClient:
    def chat_completion(self, messages: list[LLMMessage], **kwargs: Any) -> dict[str, Any]:
        user_prompt = messages[-1].content if messages else ""
        content = dry_run_content(kwargs.get("response_format"))
        if isinstance(content, dict):
            content["dry_run"] = True
            content["prompt_preview"] = user_prompt[:2000]
        return {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(content)
                    }
                }
            ]
        }


def dry_run_content(response_format: Any) -> Any:
    if not isinstance(response_format, dict):
        return {}
    if response_format.get("type") != "json_schema":
        return {}
    json_schema = response_format.get("json_schema")
    if not isinstance(json_schema, dict):
        return {}
    schema = json_schema.get("schema")
    default_value = default_json_value(schema)
    return default_value if isinstance(default_value, (dict, list)) else {}


def default_json_value(schema: Any) -> Any:
    if not isinstance(schema, dict):
        return None
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        values = schema["enum"]
        return values[0] if isinstance(values, list) and values else None
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = schema_type[0] if schema_type else None
    if schema_type == "object":
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return {}
        return {key: default_json_value(value) for key, value in properties.items()}
    if schema_type == "array":
        return []
    if schema_type == "string":
        return ""
    if schema_type == "number":
        return 0
    if schema_type == "boolean":
        return False
    if schema_type == "null":
        return None
    any_of = schema.get("anyOf")
    if isinstance(any_of, list) and any_of:
        return default_json_value(any_of[0])
    return None
