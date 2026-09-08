from __future__ import annotations

import json
from pathlib import Path

import pytest

import agents.repo_context.primevul_file_source as primevul_file_source
from agents.repo_context.primevul_file_source import (
    FileSourceResolutionError,
    PrimeVulFileSourceResolver,
    github_raw_url,
)


def fail_http(_: str) -> bytes:
    raise AssertionError("local source resolution must not use HTTP")


def test_resolve_prefers_existing_local_file(tmp_path: Path) -> None:
    source = tmp_path / "file_contents" / "demo" / "1.c"
    source.parent.mkdir(parents=True)
    source.write_text("int target(void) {}\n", encoding="utf-8")
    resolver = PrimeVulFileSourceResolver(tmp_path / "cache", http_get=fail_http)

    result = resolver.resolve(
        locator={"local_file_path": "file_contents/demo/1.c"},
        repository_url="https://github.com/acme/demo",
        fix_revision="a" * 40,
        dataset_root=tmp_path,
    )

    assert result.source_path == source
    assert result.revision is None
    assert len(result.source_sha256) == 64


def test_github_raw_url_uses_parent_revision_and_repository_path() -> None:
    revision = "b" * 40
    assert github_raw_url("https://github.com/acme/demo", revision, "src/demo.c") == (
        f"https://raw.githubusercontent.com/acme/demo/{revision}/src/demo.c"
    )


def test_commit_page_request_uses_html_accept_header(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, str | None] = {}

    class Response:
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return b"<html>"

    def fake_urlopen(request: object, timeout: int) -> Response:
        captured["accept"] = request.get_header("Accept")  # type: ignore[attr-defined]
        return Response()

    monkeypatch.setattr(primevul_file_source, "urlopen", fake_urlopen)

    assert primevul_file_source._http_get("https://github.com/acme/demo/commit/" + "a" * 40) == b"<html>"
    assert captured["accept"] == "text/html"


def test_resolve_rejects_non_unique_parent(tmp_path: Path) -> None:
    def fake_http(url: str) -> bytes:
        assert url.endswith("/commits/" + "a" * 40)
        return json.dumps({"parents": [{"sha": "b" * 40}, {"sha": "c" * 40}]}).encode()

    resolver = PrimeVulFileSourceResolver(tmp_path / "cache", http_get=fake_http)

    with pytest.raises(FileSourceResolutionError, match="exactly one parent"):
        resolver.resolve(
            locator={"project_file_path": "src/demo.c", "file_hash": "source-hash"},
            repository_url="https://github.com/acme/demo",
            fix_revision="a" * 40,
            dataset_root=tmp_path,
        )


def test_resolve_falls_back_to_commit_page_when_api_is_rate_limited(tmp_path: Path) -> None:
    parent = "b" * 40

    def fake_http(url: str) -> bytes:
        if "/commits/" in url:
            raise RuntimeError("HTTP 403 rate limit exceeded")
        if "/commit/" in url:
            return f'<a href="/acme/demo/commit/{parent}">parent</a>'.encode()
        assert url.endswith(f"/{parent}/src/demo.c")
        return b"int target(void) {}\n"

    resolver = PrimeVulFileSourceResolver(tmp_path / "cache", http_get=fake_http)

    result = resolver.resolve(
        locator={"project_file_path": "src/demo.c", "file_hash": "source-hash"},
        repository_url="https://github.com/acme/demo",
        fix_revision="a" * 40,
        dataset_root=tmp_path,
    )

    assert result.revision == parent
    assert result.source_path.read_bytes() == b"int target(void) {}\n"


def test_resolve_reuses_cached_download_without_http(tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_http(url: str) -> bytes:
        calls.append(url)
        if "/commits/" in url:
            return json.dumps({"parents": [{"sha": "b" * 40}]}).encode()
        return b"int target(void) {}\n"

    locator = {"project_file_path": "src/demo.c", "file_hash": "source-hash"}
    resolver = PrimeVulFileSourceResolver(tmp_path / "cache", http_get=fake_http)
    first = resolver.resolve(
        locator=locator,
        repository_url="https://github.com/acme/demo.git",
        fix_revision="a" * 40,
        dataset_root=tmp_path,
    )
    second = resolver.resolve(
        locator=locator,
        repository_url="https://github.com/acme/demo.git",
        fix_revision="a" * 40,
        dataset_root=tmp_path,
    )

    assert first.source_path == second.source_path
    assert first.source_path.read_bytes() == b"int target(void) {}\n"
    assert len(calls) == 2


def test_resolve_rejects_local_path_outside_dataset(tmp_path: Path) -> None:
    resolver = PrimeVulFileSourceResolver(tmp_path / "cache", http_get=fail_http)

    with pytest.raises(FileSourceResolutionError, match="unsafe local_file_path"):
        resolver.resolve(
            locator={"local_file_path": "../outside.c"},
            repository_url="https://github.com/acme/demo",
            fix_revision="a" * 40,
            dataset_root=tmp_path,
        )
