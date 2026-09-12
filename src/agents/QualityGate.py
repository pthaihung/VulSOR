from __future__ import annotations

import json
import re
from typing import Any

from .tools.LineLocatorTool import LineLocatorTool
from .SemanticContract import (
    COLLECTIONS,
    evidence_fragments,
    parse_location,
    validate_claim_output,
    validate_operation_references,
)


class QualityGateError(ValueError):
    pass


def repair_semantic_claim_output(
    output: Any, agent_key: str, source_code: str
) -> list[dict[str, Any]]:
    """Deterministically recover item-level representation/grounding defects.

    This function never invents semantic claims. It may only canonicalize source
    anchors/evidence to exact source text or remove an individual ungroundable item.
    The goal is to prevent one malformed item from turning an otherwise useful
    semantic view into a whole-sample AnalysisFailure.
    """
    events: list[dict[str, Any]] = []
    if not isinstance(output, dict) or agent_key not in COLLECTIONS:
        return events
    collection_name = COLLECTIONS[agent_key]
    records = output.get(collection_name)
    if not isinstance(records, list):
        return events
    source_lines = source_code.splitlines()

    repaired_records: list[Any] = []
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            repaired_records.append(item)
            continue

        if agent_key == "operation_agent":
            expression = item.get("expression")
            locations = item.get("locations")
            if not isinstance(expression, str) or not expression.strip() or not isinstance(locations, list):
                repaired_records.append(item)
                continue
            repaired = _repair_operation_locations(expression, locations, source_lines)
            if repaired is None:
                events.append({"action": "drop_ungrounded_item", "index": index, "expression": expression})
                continue
            if repaired != locations:
                item["locations"] = repaired
                events.append({"action": "repair_operation_locations", "index": index, "locations": repaired})
            repaired_records.append(item)
            continue

        evidence = item.get("evidence")
        fragments = evidence_fragments(evidence)
        if not fragments:
            repaired_records.append(item)
            continue
        canonical_lines: list[str] = []
        failed = False
        used_lines: set[int] = set()
        for claimed_line, fragment in fragments:
            resolved = _resolve_evidence_fragment(claimed_line, fragment, source_lines, used_lines)
            if resolved is None:
                failed = True
                break
            used_lines.add(resolved)
            canonical_lines.append(f"L{resolved}: {source_lines[resolved - 1].strip()}")
        if failed:
            events.append({"action": "drop_ungrounded_item", "index": index, "collection": collection_name})
            continue
        canonical = "\n".join(canonical_lines)
        if canonical != evidence:
            item["evidence"] = canonical
            events.append({"action": "repair_evidence", "index": index, "collection": collection_name})
        repaired_records.append(item)

    output[collection_name] = repaired_records
    return events


def _resolve_evidence_fragment(
    claimed_line: int | None,
    fragment: str,
    source_lines: list[str],
    used_lines: set[int] | None = None,
) -> int | None:
    used_lines = used_lines or set()
    if claimed_line is not None and 1 <= claimed_line <= len(source_lines):
        if _evidence_line_matches_source(fragment, source_lines[claimed_line - 1]):
            return claimed_line
    matches = [
        i + 1 for i, line in enumerate(source_lines)
        if _evidence_line_matches_source(fragment, line)
    ]
    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    if claimed_line is not None:
        ranked = sorted((abs(line - claimed_line), line) for line in matches if line not in used_lines)
        if ranked:
            # A nearby exact physical-source match is deterministic enough for a
            # line-anchor correction. For distant ambiguous matches, refuse repair.
            best_distance, best_line = ranked[0]
            tied = [line for distance, line in ranked if distance == best_distance]
            if len(tied) == 1 and best_distance <= 6:
                return best_line
    return None


def _operation_anchor_token(expression: str) -> str | None:
    call = re.match(r"\s*([A-Za-z_]\w*)\s*\(", expression)
    if call:
        return call.group(1)
    ids = re.findall(r"[A-Za-z_]\w*", expression)
    return ids[0] if ids else None


def _operation_source_candidates(expression: str, source_lines: list[str]) -> list[int]:
    token = _operation_anchor_token(expression)
    is_call = re.match(r"\s*[A-Za-z_]\w*\s*\(", expression) is not None
    compact_expr = re.sub(r"\s+", "", expression).lower()
    candidates: list[int] = []
    for line_no, line in enumerate(source_lines, start=1):
        compact_line = re.sub(r"\s+", "", line).lower()
        # For ordinary access expressions, source-wide recovery must anchor on the
        # physical line containing the expression itself.  This avoids adjacent
        # lines inheriting a match merely because their logical-statement window
        # contains the true occurrence.
        if "..." not in expression and not is_call:
            if compact_expr in compact_line:
                candidates.append(line_no)
            continue
        if token and token not in line:
            continue
        window = _operation_statement_window(source_lines, line_no)
        if _operation_expression_matches_source(expression, line, window):
            candidates.append(line_no)
    return sorted(set(candidates))


def _repair_operation_locations(
    expression: str, locations: list[Any], source_lines: list[str]
) -> list[str] | None:
    claimed: list[int] = []
    all_local = True
    for location in locations:
        line_no = parse_location(location)
        if line_no is None or not (1 <= line_no <= len(source_lines)):
            all_local = False
            continue
        claimed.append(line_no)
        window = _operation_statement_window(source_lines, line_no)
        if not _operation_expression_matches_source(expression, source_lines[line_no - 1], window):
            all_local = False
    if locations and all_local and len(claimed) == len(locations):
        return [f"L{line}" for line in sorted(dict.fromkeys(claimed))]

    candidates = _operation_source_candidates(expression, source_lines)
    if not candidates:
        return None
    if not claimed:
        # Without a usable line anchor, only a unique source occurrence can be
        # repaired safely. Multiple matches may belong to different path/state
        # contexts and must not be merged merely to satisfy grounding.
        return [f"L{candidates[0]}"] if len(candidates) == 1 else None

    assigned: list[int] = []
    remaining = set(candidates)
    for target in claimed:
        if not remaining:
            break
        best = min(remaining, key=lambda line: (abs(line - target), line))
        # Local line drift is common; a unique whole-function occurrence is also
        # safe to canonicalize even when the reported line is far away.
        if abs(best - target) <= 12 or len(candidates) == 1:
            assigned.append(best)
            remaining.remove(best)
        else:
            return None
    if len(assigned) != len(claimed):
        return None
    return [f"L{line}" for line in sorted(dict.fromkeys(assigned))]


def validate_semantic_claim_output(output: dict[str, Any], agent_key: str, max_line: int) -> list[str]:
    """Validate the operation or operation-linked semantic fact contract."""
    return validate_claim_output(output, agent_key, max_line)


def validate_semantic_operation_references(semantic_model: dict[str, Any]) -> list[str]:
    """Validate explicit links after the four semantic outputs are assembled."""
    return validate_operation_references(semantic_model)


def validate_semantic_claim_grounding(
    output: Any, agent_key: str, source_code: str
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """Validate compact v4 source grounding without adding fields to model output.

    Validation must never crash on malformed model JSON. Structural mistakes are
    reported by the schema/contract validator; grounding simply returns a useful
    error for an invalid top-level/collection shape.
    """
    errors: list[str] = []
    metadata: dict[str, dict[str, Any]] = {}
    if not isinstance(output, dict):
        return ["semantic grounding output must be an object"], metadata
    collection_name = COLLECTIONS[agent_key]
    collection = output.get(collection_name, [])
    if not isinstance(collection, list):
        return [f"$.{collection_name} must be an array for grounding"], metadata
    source_lines = source_code.splitlines()

    for index, claim in enumerate(collection):
        if not isinstance(claim, dict):
            continue
        ref = f"{agent_key}.{collection_name}[{index}]"

        if agent_key == "operation_agent":
            expression = claim.get("expression")
            locations = claim.get("locations", [])
            matches: list[dict[str, Any]] = []
            if isinstance(expression, str) and expression.strip():
                for location in locations if isinstance(locations, list) else []:
                    line_no = parse_location(location)
                    matched = False
                    if line_no is not None and 1 <= line_no <= len(source_lines):
                        # A selected Operation may be nested inside a multiline source
                        # statement.  For example, the claimed location can be the first
                        # physical line of EXIFMultipleValues(...), while the nested
                        # ReadPropertyUnsignedLong(...) expression appears on the next line.
                        # Ground against the logical statement containing the claimed line
                        # rather than requiring the representative expression on that exact
                        # physical line.
                        source_statement = _operation_statement_window(
                            source_lines, line_no
                        )
                        matched = _operation_expression_matches_source(
                            expression, source_lines[line_no - 1], source_statement
                        )
                    matches.append(
                        {
                            "location": location,
                            "matched": matched,
                            "expression": expression,
                        }
                    )
                    if not matched:
                        errors.append(
                            f"{ref} expression has no source match near {location}: {expression!r}"
                        )
            metadata[ref] = {
                "expression_matches": matches,
                "status": "pass" if matches and all(item["matched"] for item in matches) else "retry",
            }
            continue

        fragments = evidence_fragments(claim.get("evidence", ""))
        matches = []
        for evidence_line, fragment in fragments:
            if not fragment:
                continue
            matched_lines: list[int] = []
            if evidence_line is not None and 1 <= evidence_line <= len(source_lines):
                source_line = source_lines[evidence_line - 1]
                if _evidence_line_matches_source(fragment, source_line):
                    matched_lines = [evidence_line]
            # A model can quote the exact physical source text but attach a nearby
            # line number, especially around `else`/brace boundaries or multiline
            # statements.  If the anchored line does not match, accept a fallback
            # only when the canonical fragment has exactly one source-line match in
            # the whole function. This preserves grounding without allowing a free
            # nearby-text substitute.
            if not matched_lines:
                unique_matches = [
                    i + 1 for i, candidate in enumerate(source_lines)
                    if _evidence_line_matches_source(fragment, candidate)
                ]
                if len(unique_matches) == 1:
                    matched_lines = unique_matches
            matches.append(
                {
                    "evidence_line": evidence_line,
                    "fragment": fragment,
                    "matched_lines": matched_lines,
                }
            )
            if not matched_lines:
                errors.append(
                    f"{ref} evidence fragment has no grounded source-line match: {fragment!r}"
                )
        metadata[ref] = {
            "evidence_matches": matches,
            "status": "pass" if matches and all(item["matched_lines"] for item in matches) else "retry",
        }
    return errors, metadata



def _operation_statement_window(
    source_lines: list[str], line_no: int, max_span: int = 12
) -> str:
    """Return a compact logical-statement window containing ``line_no``.

    The goal is source grounding, not parsing C. We walk only a small bounded
    region and stop at obvious statement/block boundaries. This is enough for
    multiline calls/macros while preventing an expression from being grounded to
    an unrelated nearby statement.
    """
    if line_no < 1 or line_no > len(source_lines):
        return ""

    index = line_no - 1
    start = index
    backward = 0
    while start > 0 and backward < max_span // 2:
        previous = source_lines[start - 1].strip()
        if (
            previous.endswith(";")
            or previous.endswith("{")
            or previous.endswith("}")
            or previous.startswith("case ")
            or previous.startswith("default:")
        ):
            break
        start -= 1
        backward += 1

    end = index
    forward = 0
    while end + 1 < len(source_lines) and forward < max_span:
        current = source_lines[end].strip()
        if ";" in current:
            break
        if end > index and (current.endswith("{") or current.endswith("}")):
            break
        end += 1
        forward += 1
        if ";" in source_lines[end]:
            break

    return " ".join(source_lines[start : end + 1])


def _operation_expression_matches_source(
    expression: str, source_line: str, source_window: str
) -> bool:
    """Ground a concise/representative Operation expression to its source location.

    ``expression`` may abbreviate irrelevant call arguments with ``...`` and may
    represent a multiline operation.  The numbered location must still point at a
    physical line that participates in the operation; nearby text is used only to
    complete that multiline construct, never as a free substitute for the anchored
    line.
    """
    expr = expression.strip()
    line = source_line.strip()
    window = source_window.strip()
    if not expr or not line or not window:
        return False

    compact_expr = re.sub(r"\s+", "", expr).lower()
    compact_line = re.sub(r"\s+", "", line).lower()
    compact_window = re.sub(r"\s+", "", window).lower()

    if compact_expr in compact_line:
        return True

    # Multiline/nested operation: the claimed physical line may be the beginning
    # of the same logical statement while the representative expression appears
    # on a continuation line.
    if compact_expr in compact_window:
        return True

    # Ellipsis is allowed only as an abbreviation of irrelevant call arguments.
    if "..." in compact_expr:
        pieces = [re.escape(part) for part in compact_expr.split("...") if part]
        if pieces and re.search(".*?".join(pieces), compact_window, re.DOTALL):
            # The anchored physical line must itself participate in the expression.
            expr_ids = re.findall(r"[A-Za-z_]\w*", expr)
            line_ids = set(re.findall(r"[A-Za-z_]\w*", line))
            call_match = re.match(r"\s*([A-Za-z_]\w*)\s*\(", expr)
            if call_match and call_match.group(1) in line_ids:
                return True
            noncallee = [
                identifier for identifier in expr_ids
                if not call_match or identifier != call_match.group(1)
            ]
            if any(identifier in line_ids for identifier in noncallee):
                return True

    expr_ids = re.findall(r"[A-Za-z_]\w*", expr)
    line_ids = set(re.findall(r"[A-Za-z_]\w*", line))
    window_ids = set(re.findall(r"[A-Za-z_]\w*", window))
    if not expr_ids or not line_ids:
        return False

    call_match = re.match(r"\s*([A-Za-z_]\w*)\s*\(", expr)
    if call_match:
        callee = call_match.group(1)
        if callee not in window_ids:
            return False

        # Exact/compact matching above already accepts faithful multiline calls.
        # This fallback is only for representative expressions that omit harmless
        # syntax such as casts/formatting.  Do not accept a call merely because the
        # callee appears on the anchored line: that allowed a GetNodeAttr call for
        # one attribute to ground incorrectly to a nearby GetNodeAttr call for a
        # different attribute.  Require every non-callee identifier carried by the
        # representative expression to occur in the same logical statement.
        c_keywords = {
            "const", "volatile", "signed", "unsigned", "char", "short", "int",
            "long", "float", "double", "void", "struct", "union", "enum",
            "sizeof", "return", "if", "else", "for", "while", "do", "switch",
            "case", "default", "break", "continue", "static", "extern", "register",
            "auto", "restrict", "true", "false", "null",
        }
        other_ids = [
            identifier for identifier in expr_ids
            if identifier != callee and identifier.lower() not in c_keywords
        ]
        if any(identifier not in window_ids for identifier in other_ids):
            return False

        # The claimed physical line must participate in this logical operation.
        return callee in line_ids or any(identifier in line_ids for identifier in other_ids)

    c_keywords = {
        "const", "volatile", "signed", "unsigned", "char", "short", "int",
        "long", "float", "double", "void", "struct", "union", "enum",
        "sizeof", "return", "if", "else", "for", "while", "do", "switch",
        "case", "default", "break", "continue", "static", "extern", "register",
        "auto", "restrict", "true", "false", "null",
    }
    anchors = [identifier for identifier in expr_ids if identifier.lower() not in c_keywords]
    return any(anchor in line_ids for anchor in anchors)

def _evidence_line_matches_source(fragment: str, source_line: str) -> bool:
    """Compare an evidence quote with its anchored source line.

    C macro bodies are a special case: each physical source line commonly ends in
    a continuation backslash.  Models often omit only that final backslash while
    reproducing the actual C statement exactly.  Treating this as a grounding
    failure caused repeated, costly retries on valid evidence.  We therefore
    canonicalize *only* the physical-line continuation marker plus whitespace/case;
    all other source tokens still have to match exactly.
    """
    return _canonical_evidence_line(fragment) == _canonical_evidence_line(source_line)


def _canonical_evidence_line(text: str) -> str:
    stripped = text.strip()
    # Ignore only a final preprocessor/macro physical-line continuation marker.
    # Backslashes inside literals (e.g. '\\0') are preserved.
    if stripped.endswith("\\"):
        stripped = stripped[:-1].rstrip()
    # Evidence frequently quotes the control statement while omitting a source-line
    # boundary brace, e.g. `else` for `} else {` or `if (x)` for `if (x) {`.
    # Strip only brace tokens at the physical line boundaries; never braces inside
    # expressions/initializers.
    stripped = re.sub(r"^\s*}\s*", "", stripped)
    stripped = re.sub(r"\s*{\s*$", "", stripped)
    return re.sub(r"\s+", "", stripped).lower()


def validate_output_schema(output: Any, schema: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(schema, dict):
        if not isinstance(output, dict):
            return [f"{path} must be an object"]
        for key, child_schema in schema.items():
            if key not in output:
                errors.append(f"{path}.{key} is missing")
                continue
            errors.extend(validate_output_schema(output[key], child_schema, f"{path}.{key}"))
        return errors

    if isinstance(schema, list):
        if not isinstance(output, list):
            return [f"{path} must be an array"]
        if schema:
            for index, item in enumerate(output):
                errors.extend(validate_output_schema(item, schema[0], f"{path}[{index}]"))
        return errors

    if isinstance(schema, str):
        if not _matches_schema_scalar(output, schema):
            errors.append(f"{path} must match: {schema}")
    return errors


def validate_line_numbers(output: dict[str, Any], max_line: int) -> list[str]:
    errors: list[str] = []
    for owner_path, owner in _semantic_outputs(output):
        for collection_name in ("operations", "records"):
            for index, item in enumerate(owner.get(collection_name, [])):
                item_path = f"{owner_path}.{collection_name}[{index}]"
                line = item.get("line")
                if line is None:
                    continue
                if not isinstance(line, int):
                    errors.append(f"{item_path}.line must be an integer")
                    continue
                if line < 1 or line > max_line:
                    errors.append(f"{item_path}.line={line} is outside 1..{max_line}")
    return errors


def _semantic_outputs(output: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    if any(key in output for key in ("operations", "records")):
        return [("$", output)]
    nested = []
    for key in ("operation_agent", "state_agent", "value_agent", "execution_agent"):
        value = output.get(key)
        if isinstance(value, dict):
            nested.append((f"$.{key}", value))
    return nested


def validate_source_grounding(output: dict[str, Any], locator: LineLocatorTool) -> list[str]:
    errors: list[str] = []
    for owner_path, owner in _semantic_outputs(output):
        for collection_name in ("operations", "records"):
            for index, item in enumerate(owner.get(collection_name, [])):
                candidates = _grounding_candidates(item)
                if not candidates:
                    continue
                grounding = resolve_soft_grounding(item, candidates, locator)
                if grounding:
                    item["grounding"] = grounding
                if grounding and grounding.get("status") in {"pass", "warning"}:
                    continue
                if grounding and grounding.get("status") == "retry":
                    errors.append(
                        f"{owner_path}.{collection_name}[{index}] grounding is too weak: "
                        f"claimed_line={grounding.get('claimed_line')}, "
                        f"resolved_line={grounding.get('resolved_line')}, "
                        f"match_type={grounding.get('match_type')}, reason={grounding.get('reason')}"
                    )
                    continue
                errors.append(
                    f"{owner_path}.{collection_name}[{index}] has no source match for any grounding text: "
                    + ", ".join(candidates[:3])
                )
    return errors


def resolve_soft_grounding(
    item: dict[str, Any],
    candidates: list[str],
    locator: LineLocatorTool,
    near_window: int = 2,
) -> dict[str, Any] | None:
    claimed_line = item.get("line")
    matches = []
    for candidate in candidates:
        for match in locator.locate(candidate):
            matches.append(
                {
                    **match,
                    "candidate": candidate,
                    "rank": _match_rank(str(match.get("match_type", "")), float(match.get("score", 0.0) or 0.0)),
                }
            )
    if not matches:
        return None

    best = _best_grounding_match(matches, claimed_line)
    resolved_line = int(best["line"])
    line_delta = _line_delta(claimed_line, resolved_line)
    match_type = str(best.get("match_type", "unknown"))
    score = float(best.get("score", 0.0) or 0.0)

    if line_delta is None:
        status = "warning"
        confidence = "medium" if score >= 0.75 else "low"
        reason = "source evidence was found, but the LLM did not provide a usable line anchor"
    elif line_delta == 0 and match_type in {"exact", "normalized_exact"}:
        status = "pass"
        confidence = "high"
        reason = "evidence matches the claimed line"
    elif line_delta <= near_window and score >= 0.5:
        status = "pass"
        confidence = "high" if match_type in {"exact", "normalized_exact"} else "medium"
        reason = f"evidence resolves within +/-{near_window} lines of the claimed line"
    elif match_type in {"exact", "normalized_exact"}:
        status = "warning"
        confidence = "medium"
        reason = "evidence exists in source, but far from the claimed line"
    elif score >= 0.75:
        status = "warning"
        confidence = "low"
        reason = "weak evidence match exists, but far from the claimed line"
    else:
        status = "retry"
        confidence = "low"
        reason = "evidence only has a weak match far from the claimed line"

    return {
        "claimed_line": claimed_line if isinstance(claimed_line, int) else None,
        "resolved_line": resolved_line,
        "line_delta": line_delta,
        "match_type": match_type,
        "confidence": confidence,
        "status": status,
        "reason": reason,
        "evidence": best.get("candidate", ""),
        "source_line": best.get("text", ""),
    }


def _best_grounding_match(matches: list[dict[str, Any]], claimed_line: Any) -> dict[str, Any]:
    if isinstance(claimed_line, int):
        return sorted(
            matches,
            key=lambda match: (
                abs(int(match["line"]) - claimed_line),
                -float(match.get("rank", 0.0) or 0.0),
                int(match["line"]),
            ),
        )[0]
    return sorted(
        matches,
        key=lambda match: (
            -float(match.get("rank", 0.0) or 0.0),
            int(match["line"]),
        ),
    )[0]


def _line_delta(claimed_line: Any, resolved_line: int) -> int | None:
    if not isinstance(claimed_line, int):
        return None
    return abs(resolved_line - claimed_line)


def _match_rank(match_type: str, score: float) -> float:
    base = {
        "exact": 3.0,
        "normalized_exact": 2.8,
        "identifier": 2.0,
        "token": 1.0,
    }.get(match_type, 0.5)
    return base + score


def _grounding_candidates(item: dict[str, Any]) -> list[str]:
    candidates = []
    for key in ("expression", "evidence"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            candidates.extend(_source_like_fragments(value))
    return candidates


def _source_like_fragments(value: str) -> list[str]:
    value = value.strip()
    fragments = [value]
    quoted = []
    for match in re.finditer(r"`([^`]+)`|\"([^\"]+)\"", value):
        fragment = match.group(1) or match.group(2)
        if fragment:
            quoted.append(fragment.strip())
    fragments.extend(fragment for fragment in quoted if fragment)

    shows_match = re.search(r"\bshows?\s+(.+)$", value, flags=re.IGNORECASE)
    if shows_match:
        fragments.extend(_split_prose_joined_code(shows_match.group(1).strip()))

    line_prefix_match = re.search(r"^line\s+\d+\s*:?\s*(.+)$", value, flags=re.IGNORECASE)
    if line_prefix_match:
        fragments.extend(_split_prose_joined_code(line_prefix_match.group(1).strip()))

    return _dedupe_fragments(fragments)


def _split_prose_joined_code(value: str) -> list[str]:
    fragments = [value]
    for separator in (r";", r"\bfollowed by\b", r"\bthen\b", r"\bon line\s+\d+\b"):
        next_fragments = []
        for fragment in fragments:
            next_fragments.extend(re.split(separator, fragment, flags=re.IGNORECASE))
        fragments = next_fragments
    return [fragment.strip(" ,.;") for fragment in fragments if fragment.strip(" ,.;")]


def _dedupe_fragments(fragments: list[str]) -> list[str]:
    deduped = []
    seen = set()
    for fragment in fragments:
        normalized = fragment.strip("`\"' ")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def build_retry_user_prompt(
    original_user_prompt: str,
    invalid_output: Any,
    errors: list[str],
    schema: Any,
) -> str:
    previous_output = _compact_retry_value(invalid_output)
    return "\n".join(
        [
            "The previous answer failed validation.",
            "Fix the answer and return exactly one valid JSON object.",
            "Do not add Markdown, code fences, or prose outside JSON.",
            "",
            "validation_errors:",
            json.dumps(errors, ensure_ascii=False, indent=2),
            "",
            "required_schema:",
            json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
            "",
            "previous_output:",
            previous_output,
            "",
            "original_task:",
            original_user_prompt,
        ]
    )


def _compact_retry_value(value: Any, limit: int = 12000) -> str:
    if isinstance(value, dict) and isinstance(value.get("unparseable_output"), str):
        summary = dict(value)
        summary["unparseable_output"] = _truncate_text(value["unparseable_output"], limit)
        value = summary
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return _truncate_text(text, limit)


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _matches_schema_scalar(output: Any, schema: str) -> bool:
    variants = [part.strip() for part in schema.split("|")]
    for variant in variants:
        if variant == "string" and isinstance(output, str):
            return True
        if variant == "number" and isinstance(output, (int, float)) and not isinstance(output, bool):
            return True
        if variant == "boolean" and isinstance(output, bool):
            return True
        if output == _parse_literal(variant):
            return True
    return False


def _parse_literal(value: str) -> Any:
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value
