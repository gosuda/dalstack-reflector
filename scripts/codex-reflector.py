#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import functools
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypedDict, cast

DEBUG = os.environ.get("CODEX_REFLECTOR_DEBUG", "0") == "1"
_SYNTHETIC_PREFIX = "synthetic::"


def debug(msg: str) -> None:
    if DEBUG:
        print(f"[codex-reflector] {msg}", file=sys.stderr)


_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|credential|auth)\s*[=:]\s*\S+"),
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END"),
    re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*\S+"),
]


def _redact(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


FAIL_AT_ADVISORY = 0.7
PASS_BELOW = 0.3
BLOCK_AT = 0.9
CHUNK_MAX_BYTES = 28000

_MATERIAL_DEFECT_AT = 0.5

_JUDGE_DEFAULT_MODEL = "jev-1.14.0"
_JUDGE_TIMEOUT_SECS = 10.0
_JUDGE_MAX_ATTEMPTS = 3
_JUDGE_BACKOFF_CAP_SECS = 5.0
_JUDGE_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_JUDGE_MAX_IN_FLIGHT = 8
_JUDGE_REVIEW_DEADLINE_SECS = 90.0
_JUDGE_RANDOM = random.random

_ROUTE_SUBJECTS = {
    "write": "code change",
    "plan": "implementation plan",
    "stop": "work done in this session",
}

_UI_EXTENSIONS = (
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".jsx",
    ".tsx",
    ".vue",
    ".svelte",
    ".astro",
)

_LEVEL_NAMES = ("material defect", "concrete concern", "no concern")

_DROPPED_WITHOUT_CODE = ("correctness", "complexity", "concurrency", "performance")


class _DimensionSpec(TypedDict):
    id: str
    title: str
    criteria: tuple[str, str, str]


class _ScreenSpec(TypedDict):
    id: str
    instructions: str
    true: str
    false: str


_DIMENSIONS: tuple[_DimensionSpec, ...] = (
    {
        "id": "correctness",
        "title": "correctness",
        "criteria": (
            (
                "It contains a defect that produces a wrong result, a crash, data loss, "
                "or a security hole on a realistic input."
            ),
            (
                "It works on the main path but mishandles a specific edge case, error "
                "path, or boundary value."
            ),
            "No incorrect behavior is visible in it.",
        ),
    },
    {
        "id": "spec_completion",
        "title": "completeness against its stated job, including the request in "
        "`request` when that field is present",
        "criteria": (
            (
                "A required part is missing, stubbed, or left as a placeholder, so it "
                "does not do its stated job."
            ),
            (
                "The main job is done but a named sub-part, caller, test, or document is "
                "left unfinished."
            ),
            "Nothing it starts is left unfinished.",
        ),
    },
    {
        "id": "complexity",
        "title": "complexity",
        "criteria": (
            (
                "It adds structure that is hard to follow: deep nesting, a long function "
                "with many branches, or an abstraction layer with a single use."
            ),
            (
                "It is more involved than the task needs in one specific place, such as "
                "an extra parameter, flag, or indirection."
            ),
            "It is as simple as the task allows.",
        ),
    },
    {
        "id": "slop",
        "title": "filler and leftovers",
        "criteria": (
            (
                "It contains filler that must not ship: dead or commented-out code, "
                "duplicated blocks, generic names such as helper or data, or comments "
                "that restate the code."
            ),
            (
                "It contains one or two small leftovers, such as an unused import, a "
                "stale comment, or a vague name."
            ),
            "It contains no filler, leftovers, or vague names.",
        ),
    },
    {
        "id": "concurrency",
        "title": "concurrency safety",
        "criteria": (
            (
                "It introduces a data race, a deadlock, a lost update, or unbounded "
                "concurrent work."
            ),
            (
                "It shares state or orders asynchronous steps in a way that is fragile "
                "but not shown to fail."
            ),
            "No concurrency problem is visible in it, or it has no concurrent behavior.",
        ),
    },
    {
        "id": "performance",
        "title": "performance",
        "criteria": (
            (
                "It adds work that grows badly with input size or blocks a hot path, "
                "such as a nested loop over the same data, a query inside a loop, or "
                "blocking I/O in an event loop."
            ),
            (
                "It does avoidable repeated work, allocation, or copying in one specific "
                "place."
            ),
            "No avoidable cost is visible in it.",
        ),
    },
    {
        "id": "design",
        "title": "design",
        "criteria": (
            (
                "It puts a responsibility in the wrong place, breaks an existing "
                "interface contract, or couples parts that change for different reasons."
            ),
            (
                "It works within the structure but leaks an internal detail, duplicates "
                "an existing mechanism, or names something misleadingly."
            ),
            "It fits the surrounding structure and its interfaces are clear.",
        ),
    },
)

_UI_DIMENSIONS: tuple[_DimensionSpec, ...] = (
    {
        "id": "layout",
        "title": "layout",
        "criteria": (
            (
                "It breaks layout for common screen sizes or content lengths: fixed "
                "pixel sizes that overflow, overlapping elements, or content clipped "
                "without scrolling."
            ),
            (
                "It uses hardcoded spacing or sizes where relative units or tokens fit, "
                "or it misaligns one element."
            ),
            "No layout problem is visible in it.",
        ),
    },
    {
        "id": "animation",
        "title": "animation",
        "criteria": (
            (
                "It animates in a way that harms use: it animates layout properties such "
                "as width, height, top, or left, ignores reduced-motion preferences, or "
                "blocks interaction until it ends."
            ),
            (
                "It uses an inconsistent duration or easing, or it animates every "
                "property at once."
            ),
            "No animation problem is visible in it, or it adds no animation.",
        ),
    },
    {
        "id": "accessibility",
        "title": "accessibility",
        "criteria": (
            (
                "It makes a control unusable for keyboard or screen-reader users: no "
                "accessible name, no focus handling, or a click handler on a "
                "non-interactive element."
            ),
            (
                "It misses one accessibility detail, such as alt text, a label "
                "association, or visible focus styling."
            ),
            "No accessibility problem is visible in it.",
        ),
    },
)

_SCREENS: tuple[_ScreenSpec, ...] = (
    {
        "id": "is_executable_code",
        "instructions": "Is the content in `subject` executable source code?",
        "true": "It is program source code, a script, a query, or a test.",
        "false": "It is prose, documentation, configuration, or data.",
    },
    {
        "id": "touches_shared_state",
        "instructions": "Does the code in `subject` read or write state that more "
        "than one thread, task, process, or request can reach at the same time?",
        "true": "It reads or writes such shared state.",
        "false": "It uses only local or single-owner state.",
    },
    {
        "id": "has_placeholder",
        "instructions": "Does the content in `subject` contain a stub, a TODO or "
        "FIXME marker, a not-implemented error, or placeholder text standing in "
        "for real work?",
        "true": "It contains at least one of those.",
        "false": "It contains none of those.",
    },
)


def _chunk_text(text: str, limit: int = CHUNK_MAX_BYTES) -> list[str]:
    if limit < 4:
        raise ValueError(f"chunk limit must be at least 4, got {limit}")
    data = text.encode("utf-8", "surrogatepass")
    chunks: list[str] = []
    pos = 0
    while len(data) - pos > limit:
        end = pos + limit
        while data[end] & 0xC0 == 0x80:
            end -= 1
        newline = data.rfind(b"\n", pos, end)
        if newline - pos >= 0 and 2 * (newline - pos) >= end - pos:
            end = newline + 1
        chunks.append(data[pos:end].decode("utf-8", "surrogatepass"))
        pos = end
    chunks.append(data[pos:].decode("utf-8", "surrogatepass"))
    return chunks


class _ScreenQuestion(TypedDict):
    type: Literal["noul"]
    instructions: str
    criteria: dict[str, str]


class _ScoreQuestion(TypedDict):
    type: Literal["score"]
    instructions: str
    criteria: list[str]


class _JudgedChunk(TypedDict):
    answers: dict[str, Answer]
    model: str


class _SkippedChunk(TypedDict):
    cause: str


if TYPE_CHECKING:
    from typing import Self

    Question = _ScreenQuestion | _ScoreQuestion
    _ChunkResult = _JudgedChunk | _SkippedChunk


def build_questions(
    route: str, file_path: str = "", completeness_judged: bool = True
) -> dict[str, Question]:
    subject = _ROUTE_SUBJECTS[route]
    if route == "write":
        screens = _SCREENS
        dimensions = (
            _DIMENSIONS + _UI_DIMENSIONS
            if Path(file_path).suffix.lower() in _UI_EXTENSIONS
            else _DIMENSIONS
        )
    else:
        screens = ()
        dimensions = _DIMENSIONS
    if not completeness_judged:
        dimensions = tuple(d for d in dimensions if d["id"] != "spec_completion")
    questions: dict[str, Question] = {}
    for screen in screens:
        questions[screen["id"]] = _ScreenQuestion(
            type="noul",
            instructions=screen["instructions"],
            criteria={"true": screen["true"], "false": screen["false"]},
        )
    for dimension in dimensions:
        questions[dimension["id"]] = _ScoreQuestion(
            type="score",
            instructions=f"Rate the {subject} in `subject` on {dimension['title']}.",
            criteria=[*dimension["criteria"]],
        )
    return questions


def _scored_dimensions(
    route: str, answers: dict[str, Answer]
) -> tuple[list[_DimensionSpec], dict[str, float]]:
    dimensions = [d for d in _DIMENSIONS + _UI_DIMENSIONS if d["id"] in answers]
    if route == "write":
        executable = answers["is_executable_code"]
        if executable["type"] == "noul" and executable["noul"] < 0.5:
            dimensions = [d for d in dimensions if d["id"] not in _DROPPED_WITHOUT_CODE]
        shared = answers["touches_shared_state"]
        if shared["type"] == "noul" and shared["noul"] < 0.5:
            dimensions = [d for d in dimensions if d["id"] != "concurrency"]
    defects: dict[str, float] = {}
    for dimension in dimensions:
        answer = answers[dimension["id"]]
        if answer["type"] == "score":
            defects[dimension["id"]] = answer["probabilities"]["0"]
    if route == "write":
        placeholder = answers["has_placeholder"]
        if placeholder["type"] == "noul" and "spec_completion" in defects:
            defects["spec_completion"] = max(
                defects["spec_completion"], placeholder["noul"]
            )
    return dimensions, defects


def derive_verdict(route: str, answers: dict[str, Answer]) -> str:
    dimensions, defects = _scored_dimensions(route, answers)
    worst = max(defects.values())
    if worst >= (BLOCK_AT if route == "stop" else FAIL_AT_ADVISORY):
        return "FAIL"
    if worst >= PASS_BELOW:
        return "UNCERTAIN"
    for dimension in dimensions:
        answer = answers[dimension["id"]]
        if answer["type"] != "score":
            continue
        levels = answer["probabilities"]
        if levels["2"] <= levels["0"] or levels["2"] <= levels["1"]:
            return "UNCERTAIN"
    return "PASS"


def combine_verdicts(
    verdicts: list[str | None],
) -> str | None:
    judged = [verdict for verdict in verdicts if verdict is not None]
    if "FAIL" in judged:
        return "FAIL"
    if len(judged) < len(verdicts):
        return None
    return "PASS" if all(verdict == "PASS" for verdict in judged) else "UNCERTAIN"


def _dimension_line(
    dimension: _DimensionSpec, answers: dict[str, Answer], defect: float
) -> str | None:
    answer = answers[dimension["id"]]
    if answer["type"] != "score":
        return None
    levels = answer["probabilities"]
    likely = 0
    if levels["1"] > levels["0"]:
        likely = 1
    if levels["2"] > levels[str(likely)]:
        likely = 2
    if defect < PASS_BELOW and likely not in (0, 1):
        return None
    if defect >= _MATERIAL_DEFECT_AT:
        shown = 0
    elif defect >= PASS_BELOW:
        shown = min(likely, 1)
    else:
        shown = likely
    return (
        f"- {dimension['id']}: {_LEVEL_NAMES[shown]} "
        f"(P(defect)={defect:.2f}) {dimension['criteria'][shown]}"
    )


def _worst_line(
    dimension: _DimensionSpec,
    scored: list[tuple[int, dict[str, Answer], dict[str, float]]],
) -> tuple[float, str, int] | None:
    worst: tuple[float, str, int] | None = None
    for index, answers, defects in scored:
        defect = defects.get(dimension["id"])
        if defect is None:
            continue
        line = _dimension_line(dimension, answers, defect)
        if line is not None and (worst is None or defect > worst[0]):
            worst = (defect, line, index)
    return worst


def _judged_chunk(result: _ChunkResult) -> _JudgedChunk | None:
    if "answers" in result:
        return cast("_JudgedChunk", result)
    return None


def _chunk_cause(result: _ChunkResult) -> str | None:
    if "cause" in result:
        return cast("_SkippedChunk", result)["cause"]
    return None


def _dimension_lines(route: str, results: list[_ChunkResult]) -> list[str]:
    parts = len(results)
    scored: list[tuple[int, dict[str, Answer], dict[str, float]]] = []
    for index, result in enumerate(results):
        chunk = _judged_chunk(result)
        if chunk is not None:
            answers = chunk["answers"]
            scored.append((index, answers, _scored_dimensions(route, answers)[1]))
    ranked: list[tuple[float, str]] = []
    for dimension in _DIMENSIONS + _UI_DIMENSIONS:
        worst = _worst_line(dimension, scored)
        if worst is None:
            continue
        suffix = f" (part {worst[2] + 1} of {parts})" if parts > 1 else ""
        ranked.append((worst[0], worst[1] + suffix))
    ranked.sort(key=lambda entry: -entry[0])
    if ranked:
        return [line for _, line in ranked]
    highest = max(
        (defect for _, _, defects in scored for defect in defects.values()),
        default=0.0,
    )
    return [f"No dimension shows a material defect (highest P(defect)={highest:.2f})."]


def _added_lines(
    results: list[_ChunkResult], completeness_judged: bool
) -> list[str]:
    parts = len(results)
    lines: list[str] = []
    if not completeness_judged and parts > 1:
        lines.append(
            f"Completeness was not judged: the subject was split into {parts} parts."
        )
    elif not completeness_judged:
        lines.append(
            "Completeness was not judged: the request does not fit in one part with the subject."
        )
    causes = [cause for cause in map(_chunk_cause, results) if cause is not None]
    if causes:
        lines.append(f"Parts not judged: {len(causes)} of {parts} ({causes[0]}).")
    return lines


def _model_line(results: list[_ChunkResult]) -> str:
    models: list[str] = []
    for result in results:
        chunk = _judged_chunk(result)
        if chunk is not None and chunk["model"] not in models:
            models.append(chunk["model"])
    return f"Judged by {', '.join(models)}."


def render_scorecard(
    route: str,
    results: list[_ChunkResult],
    completeness_judged: bool,
) -> str:
    lines = _dimension_lines(route, results) + _added_lines(results, completeness_judged)
    lines.append(_model_line(results))
    return "\n".join(lines)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _judge_opener(url: str, review: _Review) -> urllib.request.OpenerDirector:
    tracked = (_ReviewHTTPHandler(review), _ReviewHTTPSHandler(review))
    if _is_loopback_host(urllib.parse.urlsplit(url).hostname):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect, *tracked
        )
    return urllib.request.build_opener(_NoRedirect, *tracked)


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _judge_url() -> str:
    base = os.environ.get("TYPESAFE_BASE_URL", "").strip() or "https://api.typesafe.ai"
    parts = urllib.parse.urlsplit(base)
    loopback_http = parts.scheme == "http" and _is_loopback_host(parts.hostname)
    if parts.scheme != "https" and not loopback_http:
        raise ValueError(f"TYPESAFE_BASE_URL must be https or a loopback http host: {base}")
    return base.rstrip("/") + "/v1/systemone"


def _judge_model() -> str:
    override = os.environ.get("TYPESAFE_DEFAULT_MODEL", "").strip()
    return override or _JUDGE_DEFAULT_MODEL


def _judge_request(
    url: str,
    key: str,
    state: dict[str, str],
    questions: dict[str, Question],
) -> urllib.request.Request:
    body = json.dumps({"model": _judge_model(), "state": state, "questions": questions}).encode("utf-8")
    return urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )


def _retry_after(headers) -> float | None:
    raw = headers.get("Retry-After") if headers is not None else None
    if not raw:
        return None
    try:
        after = float(raw)
    except ValueError:
        return None
    return after if 0 <= after < _JUDGE_BACKOFF_CAP_SECS else None


def _retry_wait(attempt: int, headers, left: float) -> float:
    wait = _retry_after(headers)
    if wait is None:
        nominal = min(0.5 * (2 ** attempt), _JUDGE_BACKOFF_CAP_SECS)
        wait = nominal * (0.5 + 0.5 * _JUDGE_RANDOM())
    return max(0.0, min(wait, left))


class _NoulAnswer(TypedDict):
    type: Literal["noul"]
    noul: float


class _ScoreAnswer(TypedDict):
    type: Literal["score"]
    probabilities: dict[str, float]


if TYPE_CHECKING:
    Answer = _NoulAnswer | _ScoreAnswer


class _JudgeAnswerError(Exception):
    pass


def _is_answer_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return 0 <= value <= 1


def _answer_value(answer: object, wire_type: str) -> Answer:
    if not isinstance(answer, dict) or answer.get("type") != wire_type:
        raise _JudgeAnswerError(f"answer is not a {wire_type} answer")
    if wire_type == "noul":
        if not _is_answer_number(answer.get("noul")):
            raise _JudgeAnswerError("noul answer is not a number")
        return _NoulAnswer(type="noul", noul=answer["noul"])
    probabilities = answer.get("probabilities")
    if not isinstance(probabilities, dict):
        raise _JudgeAnswerError("score answer lacks a probabilities object")
    if not all(_is_answer_number(probabilities.get(level)) for level in ("0", "1", "2")):
        raise _JudgeAnswerError("score answer is not three numbers")
    return _ScoreAnswer(type="score", probabilities=probabilities)


def _judge_answers(
    body: bytes, questions: dict[str, Question]
) -> tuple[dict[str, Answer], str]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as err:
        raise _JudgeAnswerError("response is not JSON") from err
    if not isinstance(payload, dict):
        raise _JudgeAnswerError("response is not an object")
    raw = payload.get("answers")
    model = payload.get("model")
    if not isinstance(raw, dict) or not isinstance(model, str) or not model:
        raise _JudgeAnswerError("response lacks answers or model")
    answers: dict[str, Answer] = {}
    for question_id, question in questions.items():
        if question_id not in raw:
            raise _JudgeAnswerError(f"response lacks answer for {question_id}")
        answers[question_id] = _answer_value(raw[question_id], question["type"])
    return answers, model


def _shut_socket(sock: socket.socket) -> None:
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError as err:
        debug(f"judge socket shutdown failed: {err}")


class _Review:
    def __init__(self) -> None:
        self.clock: Callable[[], float] = time.monotonic
        self.deadline = self.clock() + _JUDGE_REVIEW_DEADLINE_SECS
        self.lock = threading.Lock()
        self.refused: str | None = None
        self.expired = False
        self.sockets: set[socket.socket] = set()

    def _past(self) -> bool:
        return self.expired or self.clock() >= self.deadline

    def left(self) -> float:
        return max(0.0, self.deadline - self.clock())

    def timed_out(self) -> bool:
        with self.lock:
            return self._past()

    def admit(self) -> str | None:
        with self.lock:
            if self.refused is not None:
                return self.refused
            if self._past():
                return "judge request timed out"
            return None

    def refuse(self, cause: str) -> None:
        with self.lock:
            if self.refused is None:
                self.refused = cause

    def track(self, sock: socket.socket) -> None:
        with self.lock:
            self.sockets.add(sock)
            if self.expired:
                _shut_socket(sock)

    def expire(self) -> None:
        with self.lock:
            self.expired = True
            for sock in self.sockets:
                _shut_socket(sock)


class _ReviewHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, timeout: float, review: _Review) -> None:
        super().__init__(host, timeout=timeout)
        self.review = review

    def connect(self) -> None:
        super().connect()
        self.review.track(self.sock)


class _ReviewHTTPSConnection(_ReviewHTTPConnection, http.client.HTTPSConnection):
    pass


class _ReviewHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, review: _Review) -> None:
        super().__init__()
        self.review = review

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            functools.partial(_ReviewHTTPConnection, review=self.review), req
        )


class _ReviewHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, review: _Review) -> None:
        super().__init__()
        self.review = review

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            functools.partial(_ReviewHTTPSConnection, review=self.review), req
        )


class _RetryableJudgeError(Exception):
    def __init__(self, cause: str, headers=None) -> None:
        super().__init__(cause)
        self.cause = cause
        self.headers = headers


def _judge_body(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    timeout: float,
) -> bytes:
    with opener.open(request, timeout=timeout) as response:
        body = response.read(_JUDGE_MAX_RESPONSE_BYTES + 1)
        if len(body) <= _JUDGE_MAX_RESPONSE_BYTES and response.length:
            raise http.client.IncompleteRead(body, response.length)
    if len(body) > _JUDGE_MAX_RESPONSE_BYTES:
        raise _JudgeAnswerError("response exceeds the size limit")
    return body


def _network_cause(err: OSError | http.client.HTTPException) -> str:
    reason = err.reason if isinstance(err, urllib.error.URLError) else err
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "judge request timed out"
    return f"judge request failed: {type(reason).__name__}"


def _attempt_failure(
    err: OSError | http.client.HTTPException | ValueError | _JudgeAnswerError,
    review: _Review,
) -> tuple[None, str]:
    if isinstance(err, _JudgeAnswerError):
        return None, "judge answer was malformed"
    if isinstance(err, urllib.error.HTTPError):
        cause = f"judge request failed: HTTP {err.code}"
        if err.code in (401, 403):
            review.refuse(cause)
        if err.code not in (408, 429) and err.code < 500:
            return None, cause
        raise _RetryableJudgeError(cause, err.headers) from err
    if isinstance(err, ValueError):
        return None, "judge request failed: ValueError"
    raise _RetryableJudgeError(_network_cause(err)) from err


def _judge_attempt(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    questions: dict[str, Question],
    review: _Review,
) -> tuple[dict[str, Answer] | None, str]:
    timeout = min(_JUDGE_TIMEOUT_SECS, review.left())
    try:
        body = _judge_body(opener, request, timeout)
    except (OSError, http.client.HTTPException, ValueError, _JudgeAnswerError) as err:
        if review.timed_out():
            return None, "judge request timed out"
        return _attempt_failure(err, review)
    if review.timed_out():
        return None, "judge request timed out"
    try:
        return _judge_answers(body, questions)
    except _JudgeAnswerError:
        return None, "judge answer was malformed"


def _judge_attempts(
    opener: urllib.request.OpenerDirector,
    request: urllib.request.Request,
    questions: dict[str, Question],
    review: _Review,
) -> tuple[dict[str, Answer] | None, str]:
    cause = ""
    for attempt in range(_JUDGE_MAX_ATTEMPTS):
        refusal = review.admit()
        if refusal is not None:
            return None, refusal
        try:
            return _judge_attempt(opener, request, questions, review)
        except _RetryableJudgeError as err:
            cause = err.cause
            wait = _retry_wait(attempt, err.headers, review.left())
        if attempt + 1 < _JUDGE_MAX_ATTEMPTS:
            time.sleep(wait)
    return None, cause


def invoke_judge(
    state: dict[str, str],
    questions: dict[str, Question],
    review: _Review | None = None,
) -> tuple[dict[str, Answer] | None, str]:
    key = os.environ.get("TYPESAFE_API_KEY", "")
    if not key:
        return None, "TYPESAFE_API_KEY is not set"
    try:
        url = _judge_url()
    except ValueError as err:
        debug(f"judge url refused: {err}")
        return None, f"judge request failed: {type(err).__name__}"
    request = _judge_request(url, key, state, questions)
    review = review or _Review()
    return _judge_attempts(_judge_opener(url, review), request, questions, review)


def _chunk_states(state: dict[str, str]) -> tuple[list[dict[str, str]], bool]:
    size = sum(
        len(state[key].encode("utf-8", "surrogatepass"))
        for key in ("subject", "request")
        if key in state
    )
    completeness_judged = size <= CHUNK_MAX_BYTES
    base = {
        key: value
        for key, value in state.items()
        if completeness_judged or key != "request"
    }
    chunks = _chunk_text(state["subject"])
    if len(chunks) == 1:
        return [base], completeness_judged
    states = [
        {**base, "subject": chunk, "part": f"{index} of {len(chunks)}"}
        for index, chunk in enumerate(chunks, 1)
    ]
    return states, completeness_judged


def _judge_chunks(
    states: list[dict[str, str]], questions: dict[str, Question]
) -> list[_ChunkResult]:
    review = _Review()
    timer = threading.Timer(review.left(), review.expire)
    timer.daemon = True
    timer.start()
    try:
        workers = min(_JUDGE_MAX_IN_FLIGHT, len(states))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            replies = list(
                pool.map(lambda state: invoke_judge(state, questions, review), states)
            )
    finally:
        timer.cancel()
    results: list[_ChunkResult] = []
    for answers, model_or_cause in replies:
        if answers is None:
            results.append(_SkippedChunk(cause=model_or_cause))
        else:
            results.append(_JudgedChunk(answers=answers, model=model_or_cause))
    return results


def _chunk_verdict(route: str, result: _ChunkResult) -> str | None:
    chunk = _judged_chunk(result)
    return None if chunk is None else derive_verdict(route, chunk["answers"])


def judge_review(
    route: str, state: dict[str, str], file_path: str = ""
) -> tuple[str | None, str]:
    states, completeness_judged = _chunk_states(state)
    questions = build_questions(route, file_path, completeness_judged)
    results = _judge_chunks(states, questions)
    verdict = combine_verdicts([_chunk_verdict(route, result) for result in results])
    if verdict is None:
        cause = next(cause for cause in map(_chunk_cause, results) if cause is not None)
        return None, f"codex-reflector: review skipped: {cause}"
    return verdict, render_scorecard(route, results, completeness_judged)


_TOOL_ROUTES: dict[str, str] = {
    "Write": "code_change",
    "Edit": "code_change",
    "MultiEdit": "code_change",
    "Patch": "code_change",
    "NotebookEdit": "code_change",
    "ExitPlanMode": "plan_review",
}

_NEVER_REVIEWED_TOOLS: frozenset[str] = frozenset(
    {
        "Read",
        "Glob",
        "Grep",
        "Bash",
        "Task",
        "TaskCreate",
        "TaskGet",
        "TaskList",
        "TaskUpdate",
        "TaskOutput",
        "TaskStop",
        "WebFetch",
        "WebSearch",
        "AskUserQuestion",
        "Skill",
        "EnterPlanMode",
    }
)

_MCP_EDIT_MARKERS: tuple[str, ...] = ("__edit_file",)


def _is_fast_apply(tool_name: str) -> bool:
    return tool_name.startswith("mcp__") and "__edit_file" in tool_name


def _is_safe_edit_path(path_str: str, cwd: str) -> bool:
    if not path_str or not cwd:
        return False
    try:
        cwd_resolved = Path(cwd).resolve()
        resolved = (cwd_resolved / path_str).resolve()
    except (OSError, ValueError):
        return False
    plans_dir = Path.home() / ".claude" / "plans"
    try:
        resolved.relative_to(cwd_resolved)
        return True
    except ValueError as err:
        debug(f"edit path outside cwd: {err}")
    try:
        resolved.relative_to(plans_dir)
        return True
    except ValueError:
        return False


def classify(tool_name: str) -> str | None:
    cat = _TOOL_ROUTES.get(tool_name)
    if cat is None:
        if tool_name in _NEVER_REVIEWED_TOOLS:
            return None
        if tool_name.startswith("mcp__"):
            if any(m in tool_name for m in _MCP_EDIT_MARKERS):
                return "code_change"
            debug(f"unknown MCP tool skipped: {tool_name}")
            return None
        debug(f"unknown tool skipped: {tool_name}")
        return None
    return cat


_GLOBAL_PLANS_DIR = Path.home() / ".claude" / "plans"

_PLAN_SAVED_TEXT_RE = re.compile(r"saved to:\s*(/[^\n\"]+\.md)")


def _is_synthetic_path(path: str) -> bool:
    return path.startswith(_SYNTHETIC_PREFIX)


def _validate_plan_path(path_str: str) -> str | None:
    if _is_synthetic_path(path_str):
        return None
    try:
        resolved = Path(path_str).resolve()
        plans_resolved = _GLOBAL_PLANS_DIR.resolve()
    except (OSError, ValueError):
        return None
    if resolved.suffix != ".md":
        debug(f"plan path not .md: {resolved}")
        return None
    if not str(resolved).startswith(str(plans_resolved) + os.sep):
        debug(f"plan path outside ~/.claude/plans/: {resolved}")
        return None
    return str(resolved)


def _extract_plan_path(tool_response: dict[str, object] | str | None) -> str | None:
    if not tool_response:
        return None

    if isinstance(tool_response, dict):
        fp = tool_response.get("filePath")
        if isinstance(fp, str) and fp:
            validated = _validate_plan_path(fp)
            if validated:
                debug(f"plan path from tool_response.filePath: {validated}")
                return validated
        for key in ("content", "result", "text"):
            val = tool_response.get(key)
            if isinstance(val, str):
                m = _PLAN_SAVED_TEXT_RE.search(val)
                if m:
                    validated = _validate_plan_path(m.group(1).strip())
                    if validated:
                        debug(f"plan path from tool_response.{key}: {validated}")
                        return validated
        return None

    if isinstance(tool_response, str):
        m = _PLAN_SAVED_TEXT_RE.search(tool_response)
        if m:
            validated = _validate_plan_path(m.group(1).strip())
            if validated:
                debug(f"plan path from tool_response string: {validated}")
                return validated

    return None


def _find_plan_for_session(hook_data: dict[str, object]) -> tuple[str, str] | None:
    tool_response = hook_data.get("tool_response")
    if not isinstance(tool_response, (dict, str)):
        tool_response = None
    tool_input = hook_data.get("tool_input", {})

    plan_path = _extract_plan_path(tool_response)

    plan_content = ""
    if isinstance(tool_response, dict):
        plan_content = tool_response.get("plan", "")
    if not plan_content and isinstance(tool_input, dict):
        plan_content = tool_input.get("plan", "")

    if plan_path:
        if plan_content:
            debug("plan from tool_response path + hook content (zero I/O)")
            return (plan_path, plan_content)
        if _is_synthetic_path(plan_path):
            raise ValueError(f"synthetic path reached I/O boundary: {plan_path}")
        try:
            content = Path(plan_path).read_text(errors="replace")
            debug("plan from tool_response path + disk read")
            return (plan_path, content)
        except OSError as exc:
            debug(f"cannot read plan at {plan_path}: {exc}")

    if plan_content:
        session_id = hook_data.get("session_id", "unknown")
        synthetic = f"{_SYNTHETIC_PREFIX}plan:session:{session_id}"
        debug(f"plan from hook content with synthetic path: {synthetic}")
        return (synthetic, plan_content)

    debug("falling back to global mtime plan discovery")
    return _find_latest_plan_global()


def _find_latest_plan_global() -> tuple[str, str] | None:
    if not _GLOBAL_PLANS_DIR.is_dir():
        debug("no ~/.claude/plans/ directory")
        return None
    candidates = list(_GLOBAL_PLANS_DIR.glob("*.md"))
    if not candidates:
        debug("no plan files found in ~/.claude/plans/")
        return None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    debug(f"found plan (global mtime): {latest}")
    try:
        content = latest.read_text(errors="replace")
        return (str(latest), content)
    except OSError as exc:
        debug(f"cannot read plan: {exc}")
        return None


_VERDICT_PREFIX: dict[str, str] = {
    "FAIL": "\u26a0\ufe0f FAIL",
    "PASS": "\u2713 PASS",
    "UNCERTAIN": "? UNCERTAIN",
}


def _fast_apply_text(
    tool_name: str, tool_input: dict[str, object], file_path: str, cwd: str
) -> str | None:
    if not _is_fast_apply(tool_name):
        return None
    code_edit = tool_input.get("code_edit", "")
    instruction = tool_input.get("instruction", "")
    if not code_edit or not instruction or not _is_safe_edit_path(file_path, cwd):
        return None
    try:
        applied = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as err:
        debug(f"fast-apply read failed: {err}")
        return None
    return (
        f"Instruction: {instruction}\n\n--- sketch ---\n{code_edit}\n\n--- applied ---\n{applied}"
    )


def _change_text(tool_name: str, tool_input: dict[str, object], cwd: str) -> tuple[str, str]:
    file_path = tool_input.get("file_path", tool_input.get("path", "unknown"))
    if not isinstance(file_path, str):
        file_path = "unknown"
    fast_text = _fast_apply_text(tool_name, tool_input, file_path, cwd)
    if fast_text is not None:
        return file_path, fast_text
    content = tool_input.get("content", "")
    if not isinstance(content, str):
        content = ""
    if content:
        return file_path, content
    old = tool_input.get("old_string", "")
    new = tool_input.get("new_string", "")
    if old or new:
        return file_path, f"--- old ---\n{old}\n--- new ---\n{new}"
    return file_path, json.dumps(tool_input, indent=2)


def _code_change_state(
    tool_name: str, tool_input: dict[str, object], cwd: str
) -> tuple[str, dict[str, str]]:
    file_path, change_text = _change_text(tool_name, tool_input, cwd)
    state = {"file": _redact(file_path), "subject": _redact(change_text)}
    instruction = tool_input.get("instruction", "")
    if isinstance(instruction, str) and instruction:
        state["request"] = _redact(instruction)
    return file_path, state


def respond_code_review(
    tool_name: str,
    tool_input: dict[str, object],
    cwd: str = "",
    event_name: str = "PostToolUse",
) -> dict[str, object]:
    file_path, state = _code_change_state(tool_name, tool_input, cwd)
    verdict, body = judge_review("write", state, file_path)
    if verdict is None:
        return {"systemMessage": body}
    prefix = _VERDICT_PREFIX[verdict]
    result: dict[str, object] = {"systemMessage": f"Reflector Review {prefix} [{file_path}]:\n{body}"}
    if verdict in ("FAIL", "UNCERTAIN"):
        result["hookSpecificOutput"] = {
            "hookEventName": event_name,
            "additionalContext": f"Reflector Review {prefix} [{file_path}]:\n{body}",
        }
    return result


def respond_plan_review(
    plan_path: str, plan_content: str, event_name: str = "PostToolUse"
) -> dict[str, object]:
    state = {"subject": _redact(plan_content)}
    verdict, body = judge_review("plan", state)
    if verdict is None:
        return {"systemMessage": body}
    prefix = _VERDICT_PREFIX[verdict]
    result: dict[str, object] = {"systemMessage": f"Reflector Plan Review {prefix} [{plan_path}]:\n{body}"}
    if verdict in ("FAIL", "UNCERTAIN"):
        result["hookSpecificOutput"] = {
            "hookEventName": event_name,
            "additionalContext": f"Reflector Plan Review {prefix} [{plan_path}]:\n{body}",
        }
    return result


def _read_transcript(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        debug(f"cannot read transcript: {err}")
        return ""


def respond_stop(hook_data: dict[str, object]) -> dict[str, object] | None:
    if hook_data.get("stop_hook_active"):
        debug("stop_hook_active=true, approving stop")
        return None

    last_msg = hook_data.get("last_assistant_message", "")
    if not isinstance(last_msg, str):
        last_msg = ""
    if last_msg:
        transcript = last_msg
        debug(f"using last_assistant_message ({len(last_msg)} chars)")
    else:
        transcript_path = hook_data.get("transcript_path", "")
        if not isinstance(transcript_path, str):
            transcript_path = ""
        transcript = _read_transcript(transcript_path)
    if not transcript:
        debug("no transcript available, approving stop")
        return None

    state = {"subject": _redact(transcript)}
    verdict, body = judge_review("stop", state)
    if verdict is None:
        return {"systemMessage": body}
    if verdict == "FAIL":
        return {
            "decision": "block",
            "reason": f"Reflector Stop Review FAIL:\n{body}",
            "_exit": 2,
        }
    return {
        "systemMessage": f"Reflector Stop Review {_VERDICT_PREFIX[verdict]}:\n{body}",
    }


_CURSOR_EVENT_MAP = {
    "postToolUse": "PostToolUse",
    "stop": "Stop",
}


def _normalize_cursor_input(hook_data: dict[str, object]) -> dict[str, object]:
    event = hook_data.get("hook_event_name")
    if isinstance(event, str) and event in _CURSOR_EVENT_MAP:
        hook_data["hook_event_name"] = _CURSOR_EVENT_MAP[event]

    if "conversation_id" in hook_data and "session_id" not in hook_data:
        hook_data["session_id"] = hook_data["conversation_id"]

    if "workspace_roots" in hook_data and not hook_data.get("cwd"):
        roots = hook_data.get("workspace_roots")
        if isinstance(roots, list) and roots:
            hook_data["cwd"] = roots[0]

    if "tool_output" in hook_data and "tool_response" not in hook_data:
        output = hook_data["tool_output"]
        try:
            hook_data["tool_response"] = (
                json.loads(output)
                if isinstance(output, (str, bytes, bytearray))
                else output
            )
        except (json.JSONDecodeError, TypeError):
            hook_data["tool_response"] = output

    if "loop_count" in hook_data and "stop_hook_active" not in hook_data:
        loop_count = hook_data.get("loop_count", 0)
        if isinstance(loop_count, (str, bytes, int, float)):
            try:
                hook_data["stop_hook_active"] = int(loop_count) > 0
            except ValueError:
                hook_data["stop_hook_active"] = False
        else:
            hook_data["stop_hook_active"] = False

    return hook_data


def _restore_env(name: str, value: str | None) -> None:
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value


_ORACLE_QUESTION_KEYS = frozenset({"type", "instructions", "criteria"})


def _noul_criteria_violation(question_id: str, criteria: object) -> str | None:
    if criteria is None:
        return None
    if not isinstance(criteria, dict) or set(criteria) - {"true", "false"}:
        return f"{question_id} noul criteria is not keyed by true and false"
    if not all(isinstance(value, str) for value in criteria.values()):
        return f"{question_id} noul criteria values are not strings"
    return None


def _score_criteria_violation(question_id: str, criteria: object) -> str | None:
    if (
        isinstance(criteria, list)
        and len(criteria) >= 2
        and all(isinstance(level, str) for level in criteria)
    ):
        return None
    return f"{question_id} score criteria is not a list of at least two strings"


def _question_violation(question_id: str, question: object) -> str | None:
    if not isinstance(question, dict):
        return f"{question_id} is not an object"
    if set(question) - _ORACLE_QUESTION_KEYS:
        return f"{question_id} has keys outside {sorted(_ORACLE_QUESTION_KEYS)}"
    criteria = question.get("criteria")
    if question.get("type") == "noul":
        return _noul_criteria_violation(question_id, criteria)
    if question.get("type") == "score":
        return _score_criteria_violation(question_id, criteria)
    return f"{question_id} type is neither noul nor score"


def _schema_violation(body: bytes) -> str | None:
    try:
        request = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "request is not JSON"
    if not isinstance(request, dict):
        return "request is not an object"
    if not isinstance(request.get("model"), str) or not request.get("model"):
        return "model is not a non-empty string"
    if not isinstance(request.get("state"), dict):
        return "state is not an object"
    questions = request.get("questions")
    if not isinstance(questions, dict) or not questions:
        return "questions is not an object with at least one entry"
    for question_id, question in questions.items():
        violation = _question_violation(question_id, question)
        if violation is not None:
            return violation
    return None


class _JudgeRequestRecord(TypedDict):
    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    index: int
    cancelled: threading.Event


def _recorded_judge_server(judge: _RecordedJudgeServer):
    import http.server

    class JudgeRecorder(http.server.BaseHTTPRequestHandler):
        def _record_request(self) -> _JudgeRequestRecord:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            with judge.lock:
                record: _JudgeRequestRecord = {
                    "method": self.command,
                    "path": self.path,
                    "headers": {
                        name.lower(): value for name, value in self.headers.items()
                    },
                    "body": body,
                    "index": len(judge.records),
                    "cancelled": judge.cancelled,
                }
                judge.records.append(record)
            return record

        def _send_reply(
            self,
            status: int,
            payload: bytes,
            extra_headers: dict[str, str],
            declared: int | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Content-Length", str(len(payload) if declared is None else declared)
            )
            for name, value in extra_headers.items():
                self.send_header(name, str(value))
            self.end_headers()
            self.wfile.write(payload)

        def _trickle(self, reply: _TrickleReply) -> None:
            self.wfile.write(reply[: reply.at])
            for byte in reply[reply.at : reply.at + _TRICKLED_BYTES]:
                if judge.cancelled.wait(0.2):
                    return
                self.wfile.write(bytes([byte]))

        def do_POST(self) -> None:
            judge.enter()
            try:
                self._answer(self._record_request())
            except (BrokenPipeError, ConnectionResetError) as err:
                debug(f"judge test client dropped the reply: {err}")
            finally:
                judge.leave()

        def _answer(self, record: _JudgeRequestRecord) -> None:
            violation = _schema_violation(record["body"])
            if violation is not None:
                self._send_reply(
                    422, json.dumps({"error": violation}).encode("utf-8"), {}
                )
                return
            status, payload, extra_headers = judge.responder(record)
            if isinstance(payload, _TrickleReply):
                self._trickle(payload)
                return
            declared = None
            if isinstance(payload, _ShortReply):
                declared = payload.declared
                payload = payload.payload
            self._send_reply(status, payload, extra_headers, declared)

        def log_message(self, format, *args) -> None:
            debug(f"judge test server: {self.command} {self.path}")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), JudgeRecorder)
    server.daemon_threads = False
    server.block_on_close = True
    return server


class _RecordedJudgeServer:
    def __init__(
        self,
        responder: Callable[
            [_JudgeRequestRecord], tuple[int, bytes | _ShortReply, dict[str, str]]
        ],
    ) -> None:
        self.responder = responder
        self.records: list[_JudgeRequestRecord] = []
        self.lock = threading.Lock()
        self.cancelled = threading.Event()
        self.in_flight = 0
        self.max_in_flight = 0
        self.base_url = ""
        self.httpd = None

    def enter(self) -> None:
        with self.lock:
            self.in_flight += 1
            self.max_in_flight = max(self.max_in_flight, self.in_flight)

    def leave(self) -> None:
        with self.lock:
            self.in_flight -= 1

    def __enter__(self) -> Self:
        self.httpd = _recorded_judge_server(self)
        self.base_url = f"http://127.0.0.1:{self.httpd.server_port}"
        self.serving_thread = threading.Thread(target=self.httpd.serve_forever)
        self.serving_thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        if self.httpd is not None:
            self.cancelled.set()
            self.httpd.shutdown()
            self.httpd.server_close()
            self.serving_thread.join()
        return False


class _ShortReply:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.declared = len(payload) + 16


_TRICKLED_BYTES = 25


class _ShutdownRecorder(socket.socket):
    subclass_shutdowns = 0

    def shutdown(self, how: int) -> None:
        self.subclass_shutdowns += 1
        super().shutdown(how)


class _TrickleReply(bytes):
    at: int = 0


def _trickle_reply(head: bytes, tail: bytes) -> _TrickleReply:
    reply = _TrickleReply(head + tail)
    reply.at = len(head)
    return reply


if TYPE_CHECKING:
    _JudgeReply = tuple[
        int,
        bytes | _ShortReply | Callable[[_JudgeRequestRecord], bytes],
        dict[str, str],
    ]


def _answers_reply(overrides: dict[str, float | dict[str, float]], model: str) -> Callable[[_JudgeRequestRecord], bytes]:
    def reply(record: _JudgeRequestRecord) -> bytes:
        return _systemone_answer_body(record, overrides, model)

    return reply


def _scripted_replies(
    script: list[_JudgeReply],
) -> Callable[[_JudgeRequestRecord], tuple[int, bytes | _ShortReply, dict[str, str]]]:
    def responder(
        record: _JudgeRequestRecord,
    ) -> tuple[int, bytes | _ShortReply, dict[str, str]]:
        status, payload_source, extra_headers = script[
            min(record["index"], len(script) - 1)
        ]
        if isinstance(payload_source, _ShortReply):
            return status, payload_source, extra_headers
        if not isinstance(payload_source, bytes):
            return status, payload_source(record), extra_headers
        return status, payload_source, extra_headers

    return responder


def _hanging_reply(record: _JudgeRequestRecord) -> bytes:
    record["cancelled"].wait(1.0)
    return b"{}"


def _silent_reply(record: _JudgeRequestRecord) -> bytes:
    record["cancelled"].wait()
    return b"{}"


def _raw_answer(record: _JudgeRequestRecord) -> bytes:
    body = _systemone_answer_body(record, {}, "jev-test")
    head = (
        "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    return head.encode("ascii") + body


def _trickled_body(record: _JudgeRequestRecord) -> bytes:
    head, blank, body = _raw_answer(record).partition(b"\r\n\r\n")
    return _trickle_reply(head + blank, body)


def _trickled_head(record: _JudgeRequestRecord) -> bytes:
    return _trickle_reply(b"", _raw_answer(record))


def _held_answers(seconds: float) -> Callable[[_JudgeRequestRecord], bytes]:
    def reply(record: _JudgeRequestRecord) -> bytes:
        record["cancelled"].wait(seconds)
        return _systemone_answer_body(record, {}, "jev-test")

    return reply


def _record_state(record: _JudgeRequestRecord) -> dict[str, str]:
    return json.loads(record["body"])["state"]


def _record_part(record: _JudgeRequestRecord) -> int:
    return int(_record_state(record).get("part", "1 of 1").split(" of ")[0])


def _joined_subject(records: list[_JudgeRequestRecord]) -> str:
    ordered = sorted(records, key=_record_part)
    return "".join(_record_state(record)["subject"] for record in ordered)


def _part_replies(
    by_part: dict[int, _JudgeReply], default: _JudgeReply
) -> Callable[[_JudgeRequestRecord], tuple[int, bytes | _ShortReply, dict[str, str]]]:
    def responder(
        record: _JudgeRequestRecord,
    ) -> tuple[int, bytes | _ShortReply, dict[str, str]]:
        status, payload_source, extra_headers = by_part.get(
            _record_part(record), default
        )
        if isinstance(payload_source, (bytes, _ShortReply)):
            return status, payload_source, extra_headers
        return status, payload_source(record), extra_headers

    return responder


def _judged(answers: dict[str, Answer], model: str = "jev-test") -> _JudgedChunk:
    return _JudgedChunk(answers=answers, model=model)


def _reply_missing_dimension(record: _JudgeRequestRecord) -> bytes:
    payload = json.loads(_systemone_answer_body(record, {}, "jev-1.14.0"))
    del payload["answers"]["slop"]
    return json.dumps(payload).encode("utf-8")


class _ScoreProgram(TypedDict):
    overrides: dict[str, float | dict[str, float]]
    model: str


def _programmed_reply(
    score_program: _ScoreProgram,
) -> Callable[[_JudgeRequestRecord], bytes]:
    def reply(record: _JudgeRequestRecord) -> bytes:
        return _systemone_answer_body(
            record, score_program["overrides"], score_program["model"]
        )

    return reply


class _ScoreAnswerFixture(TypedDict):
    type: Literal["score"]
    score: float
    confidence: float
    legend: dict[str, str]
    probabilities: dict[str, float]


def _answer_fixture(value: float | dict[str, float]) -> _NoulAnswer | _ScoreAnswerFixture:
    if isinstance(value, dict):
        probabilities = {str(level): float(value[str(level)]) for level in range(3)}
        return {
            "type": "score",
            "score": probabilities["0"],
            "confidence": 0.95,
            "legend": {"0": "material defect", "1": "concrete concern", "2": "no concern"},
            "probabilities": probabilities,
        }
    return {"type": "noul", "noul": float(value)}


def _default_answer_value(question_id: str, wire_type: str) -> float | dict[str, float]:
    if wire_type == "noul":
        return 0.0 if question_id == "has_placeholder" else 1.0
    return {"0": 0.0, "1": 0.05, "2": 0.95}


def _systemone_answer_body(
    record: _JudgeRequestRecord,
    overrides: dict[str, float | dict[str, float]],
    model: str,
) -> bytes:
    request = json.loads(record["body"])
    answers: dict[str, object] = {}
    for question_id, question in request["questions"].items():
        value = overrides.get(question_id)
        if value is None:
            value = _default_answer_value(question_id, question["type"])
        answers[question_id] = _answer_fixture(value)
    return json.dumps(
        {
            "model": model,
            "answers": answers,
            "usage": {"input_tokens": 100, "output_tokens": 20},
        }
    ).encode("utf-8")


def _score_answers(
    route: str,
    overrides: dict[str, float | dict[str, float]] | None = None,
    file_path: str = "",
) -> dict[str, Answer]:
    overrides = overrides or {}
    answers: dict[str, Answer] = {}
    for question_id, question in build_questions(route, file_path).items():
        value = overrides.get(question_id)
        if value is None:
            value = _default_answer_value(question_id, question["type"])
        answers[question_id] = _answer_fixture(value)
    return answers


def _dispatch_hook_payload(payload: dict[str, object]) -> tuple[int, str, str]:
    import io

    main_io = (sys.stdin, sys.stdout, sys.stderr)
    main_argv = sys.argv
    sys.argv = [main_argv[0]]
    sys.stdin = io.StringIO(json.dumps(payload))
    stdout, stderr = io.StringIO(), io.StringIO()
    sys.stdout, sys.stderr = stdout, stderr
    exit_code = 0
    try:
        main()
    except SystemExit as err:
        exit_code = err.code if isinstance(err.code, int) else 1
    finally:
        sys.argv = main_argv
        sys.stdin, sys.stdout, sys.stderr = main_io
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _parsed_hook_output(out: str) -> dict[str, object]:
    return json.loads(out) if out else {}


def _write_change_hook(
    content: str, instruction: str | None = None
) -> dict[str, object]:
    tool_input: dict[str, object] = {"file_path": "src/patch.py", "content": content}
    if instruction is not None:
        tool_input["instruction"] = instruction
    return {
        "hook_event_name": "PostToolUse",
        "cwd": os.getcwd(),
        "tool_name": "Write",
        "tool_input": tool_input,
    }


def _plan_approval_hook() -> dict[str, object]:
    return {
        "hook_event_name": "PostToolUse",
        "cwd": os.getcwd(),
        "tool_name": "ExitPlanMode",
        "tool_response": {"plan": "# Plan\n\nAdd the retry loop."},
    }


def _session_stop_hook() -> dict[str, object]:
    return {
        "hook_event_name": "Stop",
        "cwd": os.getcwd(),
        "last_assistant_message": "Added the retry loop and covered it with tests.",
    }


def _selftest_plan_paths(check: Callable[[str, object], None]) -> None:
    print("\n=== Plan Path Extraction ===")
    home = str(Path.home())
    valid_path = f"{home}/.claude/plans/test-slug.md"
    plan_cases: list[tuple[dict[str, object] | str | None, str | None, str]] = [
        (
            {"filePath": valid_path, "plan": "content", "isAgent": False},
            valid_path,
            "dict with filePath",
        ),
        ({"plan": "content only"}, None, "dict without filePath"),
        (
            f"Your plan has been saved to: {valid_path}\nYou can refer back.",
            valid_path,
            "string with saved-to pattern",
        ),
        ("No plan path in this string", None, "string without pattern"),
        (None, None, "None input"),
        ("", None, "empty string"),
        ({}, None, "empty dict"),
        (
            {"filePath": "/etc/passwd"},
            None,
            "path outside ~/.claude/plans/ (confinement)",
        ),
        (
            {"filePath": f"{home}/.claude/plans/../../../etc/passwd"},
            None,
            "path traversal attempt (confinement)",
        ),
        (
            {"filePath": f"{home}/.claude/plans/test.txt"},
            None,
            "non-.md extension (confinement)",
        ),
        (
            {"content": f"saved to: {valid_path}"},
            valid_path,
            "dict with content key containing pattern",
        ),
        (
            f"saved to: {home}/.claude/plans/slug-agent-a35ec22.md",
            f"{home}/.claude/plans/slug-agent-a35ec22.md",
            "agent-suffixed plan path",
        ),
    ]
    for tool_response, expected, desc in plan_cases:
        check(f"_extract_plan_path {desc}", _extract_plan_path(tool_response) == expected)


def _selftest_synthetic_paths(check: Callable[[str, object], None]) -> None:
    print("\n=== Synthetic Path Guards ===")
    check(
        "synthetic path detected",
        _is_synthetic_path(f"{_SYNTHETIC_PREFIX}plan:session:abc"),
    )
    check(
        "real path not synthetic",
        _is_synthetic_path("/home/user/.claude/plans/foo.md") is False,
    )
    check(
        "validate rejects synthetic",
        _validate_plan_path(f"{_SYNTHETIC_PREFIX}plan:session:abc") is None,
    )


def _selftest_fast_apply(check: Callable[[str, object], None]) -> None:
    print("\n=== Fast Apply Marker ===")
    fast_apply_cases = [
        ("mcp__edit__edit_file", True),
        ("mcp__filesystem-with-morph__edit_file", True),
        ("mcp__morphllm__edit_file", True),
        ("Edit", False),
        ("Write", False),
    ]
    for tool_name, expected in fast_apply_cases:
        check(f"_is_fast_apply({tool_name!r})", _is_fast_apply(tool_name) == expected)


def _selftest_classify(check: Callable[[str, object], None]) -> None:
    print("\n=== MCP Classify Routing ===")
    mcp_classify_cases = [
        ("mcp__morph__edit_file", "code_change"),
        ("mcp__morphllm__edit_file", "code_change"),
        ("mcp__morph__fastcompact", None),
        ("mcp__morph__flashcompact", None),
        ("mcp__morph__warpgrep", None),
        ("fastcompact", None),
        ("flashcompact", None),
    ]
    for tool_name, expected_cat in mcp_classify_cases:
        check(
            f"classify({tool_name!r}) category",
            classify(tool_name) == expected_cat,
        )


def _selftest_cursor(check: Callable[[str, object], None]) -> None:
    print("\n=== Cursor Input Normalization ===")
    cursor_post = _normalize_cursor_input(
        {
            "hook_event_name": "postToolUse",
            "conversation_id": "conv-123",
            "workspace_roots": ["/tmp/project"],
            "tool_output": '{"filePath": "README.md"}',
        }
    )
    cursor_stop_first = _normalize_cursor_input(
        {"hook_event_name": "stop", "conversation_id": "conv-123", "loop_count": 0}
    )
    cursor_stop_loop = _normalize_cursor_input(
        {"hook_event_name": "stop", "conversation_id": "conv-123", "loop_count": 2}
    )
    claude_passthrough_input = {
        "hook_event_name": "Stop",
        "session_id": "sid-123",
        "stop_hook_active": True,
    }
    claude_passthrough = _normalize_cursor_input(dict(claude_passthrough_input))
    normalizer_cases = [
        (
            "cursor postToolUse event maps to Claude event",
            cursor_post.get("hook_event_name"),
            "PostToolUse",
        ),
        (
            "cursor conversation_id maps to session_id",
            cursor_post.get("session_id"),
            "conv-123",
        ),
        ("cursor workspace root maps to cwd", cursor_post.get("cwd"), "/tmp/project"),
        (
            "cursor JSON tool_output maps to tool_response",
            cursor_post.get("tool_response"),
            {"filePath": "README.md"},
        ),
        (
            "cursor first stop allows review",
            cursor_stop_first.get("stop_hook_active"),
            False,
        ),
        (
            "cursor looped stop prevents recursion",
            cursor_stop_loop.get("stop_hook_active"),
            True,
        ),
        (
            "Claude payload passes through unchanged",
            claude_passthrough,
            claude_passthrough_input,
        ),
    ]
    for desc, got, expected in normalizer_cases:
        check(desc, got == expected)


def _selftest_stateless_stop(check: Callable[[str, object], None]) -> None:
    print("\n=== Stateless Stop ===")
    check("loop guard returns None", respond_stop({"stop_hook_active": True}) is None)
    check(
        "empty transcript returns None",
        respond_stop({"stop_hook_active": False}) is None,
    )


def _selftest_questions(check: Callable[[str, object], None]) -> None:
    print("\n=== Judge Questions ===")
    dimension_ids = {
        "correctness",
        "spec_completion",
        "complexity",
        "slop",
        "concurrency",
        "performance",
        "design",
    }
    screen_ids = {"is_executable_code", "touches_shared_state", "has_placeholder"}
    check(
        "write asks the screens and the seven dimensions",
        set(build_questions("write")) == screen_ids | dimension_ids,
    )
    check(
        "UI extension adds layout, animation, accessibility",
        set(build_questions("write", "page.tsx"))
        == screen_ids | dimension_ids | {"layout", "animation", "accessibility"},
    )
    check(
        "plain file adds no UI dimensions",
        set(build_questions("write", "src/util.py")) == screen_ids | dimension_ids,
    )
    check(
        "plan asks the seven dimensions",
        set(build_questions("plan")) == dimension_ids,
    )
    check(
        "stop asks the seven dimensions",
        set(build_questions("stop")) == dimension_ids,
    )
    unjudged = build_questions("write", "page.tsx", False)
    judged = build_questions("write", "page.tsx")
    del judged["spec_completion"]
    check("completeness not judged drops only spec_completion", unjudged == judged)
    every_question: dict[str, Question] = {}
    for questions in (
        build_questions("write", "page.tsx"),
        build_questions("plan"),
        build_questions("stop"),
    ):
        every_question.update(questions)
    check(
        "questions ride the System One wire shape",
        all(
            set(question) == {"type", "instructions", "criteria"}
            for question in every_question.values()
        ),
    )
    check(
        "every score question carries three criteria",
        all(
            len(question["criteria"]) == 3
            for question in every_question.values()
            if question["type"] == "score"
        ),
    )
    check(
        "every screen question offers true and false criteria",
        all(
            set(question["criteria"]) == {"true", "false"}
            for question in every_question.values()
            if question["type"] == "noul"
        ),
    )


def _selftest_question_wording(check: Callable[[str, object], None]) -> None:
    print("\n=== Judge Question Wording ===")
    write_questions = build_questions("write")
    check(
        "dimension instruction template is frozen",
        write_questions["correctness"]["instructions"]
        == "Rate the code change in `subject` on correctness.",
    )
    check(
        "spec_completion instruction names the request field",
        write_questions["spec_completion"]["instructions"]
        == (
            "Rate the code change in `subject` on completeness against its stated job, "
            "including the request in `request` when that field is present."
        ),
    )
    placeholder = write_questions["has_placeholder"]
    assert placeholder["type"] == "noul"
    check("placeholder screen rides the noul wire type", placeholder["type"] == "noul")
    check(
        "placeholder screen wording is frozen",
        (
            placeholder["instructions"],
            placeholder["criteria"]["true"],
            placeholder["criteria"]["false"],
        )
        == (
            (
                "Does the content in `subject` contain a stub, a TODO or FIXME marker, "
                "a not-implemented error, or placeholder text standing in for real work?"
            ),
            "It contains at least one of those.",
            "It contains none of those.",
        ),
    )


def _selftest_chunk_text(check: Callable[[str, object], None]) -> None:
    print("\n=== Chunk Text ===")
    at_limit = "a" * CHUNK_MAX_BYTES
    check("text at the limit is one chunk", _chunk_text(at_limit) == [at_limit])
    check(
        "one byte over with no newline cuts at the limit",
        _chunk_text(at_limit + "a") == [at_limit, "a"],
    )
    check(
        "newline exactly at half the prefix is the cut",
        _chunk_text("abcd\nfghij", 8) == ["abcd\n", "fghij"],
    )
    check(
        "newline just before half the prefix is not the cut",
        _chunk_text("abc\nefghij", 8) == ["abc\nefgh", "ij"],
    )
    check(
        "remainder that holds a newline is not cut",
        _chunk_text("abcdefghi\nj", 8) == ["abcdefgh", "i\nj"],
    )
    check("empty string is one empty chunk", _chunk_text("") == [""])
    lone = json.loads('"\\ud83d"')
    for name, text, expected in (
        ("three-byte character", "abcdefg\u20acx", ["abcdefg", "\u20acx"]),
        ("four-byte character", "abcdef\U0001f600x", ["abcdef", "\U0001f600x"]),
        ("lone surrogate", "abcdefg" + lone + "x", ["abcdefg", lone + "x"]),
    ):
        chunks = _chunk_text(text, 8)
        check(
            f"{name} at the cut stays whole and round-trips",
            (chunks, "".join(chunks)) == (expected, text),
        )
    big = "".join(
        f"row {index} \u20ac\U0001f600{lone}" + ("\n" if index % 5 else "")
        for index in range(150000)
    )
    big_chunks = _chunk_text(big)
    check(
        "multi-megabyte text joins back equal within the limit",
        (
            "".join(big_chunks) == big,
            len(big.encode("utf-8", "surrogatepass")) > 2_000_000,
            all(
                len(chunk.encode("utf-8", "surrogatepass")) <= CHUNK_MAX_BYTES
                for chunk in big_chunks
            ),
        )
        == (True, True, True),
    )
    try:
        _chunk_text("abc", 3)
        refused = False
    except ValueError:
        refused = True
    check("limit under 4 fails", refused)


def _selftest_combine(check: Callable[[str, object], None]) -> None:
    print("\n=== Combine Verdicts ===")
    cases: tuple[tuple[list[str | None], str | None, str], ...] = (
        (["PASS", "FAIL", None], "FAIL", "FAIL with a failed chunk is FAIL"),
        (["PASS", None], None, "PASS with a failed chunk skips the review"),
        (["PASS", "PASS"], "PASS", "all PASS is PASS"),
        (["PASS", "UNCERTAIN"], "UNCERTAIN", "PASS with UNCERTAIN is UNCERTAIN"),
        (["UNCERTAIN"], "UNCERTAIN", "one element is its own verdict"),
    )
    for verdicts, expected, name in cases:
        check(f"combine_verdicts: {name}", combine_verdicts(verdicts) == expected)


def _selftest_verdict_rule(check: Callable[[str, object], None]) -> None:
    print("\n=== Verdict Rule ===")
    at_advisory = {"0": 0.7, "1": 0.2, "2": 0.1}
    below_advisory = {"0": 0.69, "1": 0.2, "2": 0.11}
    check(
        "write FAIL at 0.7 exactly",
        derive_verdict("write", _score_answers("write", {"correctness": at_advisory})) == "FAIL",
    )
    check(
        "plan FAIL at 0.7 exactly",
        derive_verdict("plan", _score_answers("plan", {"correctness": at_advisory})) == "FAIL",
    )
    check(
        "write UNCERTAIN just below 0.7",
        derive_verdict("write", _score_answers("write", {"correctness": below_advisory}))
        == "UNCERTAIN",
    )
    check(
        "write UNCERTAIN at 0.3 exactly",
        derive_verdict("write", _score_answers("write", {"correctness": {"0": 0.3, "1": 0.3, "2": 0.4}}))
        == "UNCERTAIN",
    )
    check(
        "write PASS just below 0.3",
        derive_verdict("write", _score_answers("write", {"correctness": {"0": 0.29, "1": 0.0, "2": 0.71}}))
        == "PASS",
    )
    check(
        "stop FAIL at 0.9 exactly",
        derive_verdict("stop", _score_answers("stop", {"correctness": {"0": 0.9, "1": 0.05, "2": 0.05}}))
        == "FAIL",
    )
    check(
        "stop not FAIL just below 0.9",
        derive_verdict("stop", _score_answers("stop", {"correctness": {"0": 0.89, "1": 0.05, "2": 0.06}}))
        == "UNCERTAIN",
    )


def _selftest_amendment_rule(check: Callable[[str, object], None]) -> None:
    print("\n=== Level-2 Dominance ===")
    level1_heavy = {"0": 0.05, "1": 0.93, "2": 0.02}
    level1_tie = {"0": 0.05, "1": 0.475, "2": 0.475}
    check(
        "level-1 heavy dimension is UNCERTAIN",
        derive_verdict("write", _score_answers("write", {"slop": level1_heavy})) == "UNCERTAIN",
    )
    check(
        "tie between level 1 and level 2 is UNCERTAIN",
        derive_verdict("write", _score_answers("write", {"slop": level1_tie})) == "UNCERTAIN",
    )
    screen_dropped = _score_answers(
        "write", {"performance": level1_heavy, "is_executable_code": 0.4}
    )
    check(
        "screen-dropped dimension cannot veto PASS",
        derive_verdict("write", screen_dropped) == "PASS",
    )


def _selftest_screens(check: Callable[[str, object], None]) -> None:
    print("\n=== Screens ===")
    hot = {"0": 0.95, "1": 0.03, "2": 0.02}
    for dim in ("correctness", "complexity", "concurrency", "performance"):
        dropped = _score_answers("write", {dim: hot, "is_executable_code": 0.4})
        check(f"is_executable_code below 0.5 drops {dim}", derive_verdict("write", dropped) == "PASS")
    shared_off = _score_answers(
        "write", {"concurrency": hot, "touches_shared_state": 0.4}
    )
    check(
        "touches_shared_state below 0.5 drops concurrency",
        derive_verdict("write", shared_off) == "PASS",
    )
    placeholder = _score_answers("write", {"has_placeholder": 0.9})
    check(
        "has_placeholder raises spec_completion to FAIL",
        derive_verdict("write", placeholder) == "FAIL",
    )
    ui_kept = _score_answers(
        "write", {"layout": hot, "is_executable_code": 0.4}, file_path="page.tsx"
    )
    check(
        "UI dimensions survive the executable screen",
        derive_verdict("write", ui_kept) == "FAIL",
    )


def _selftest_scorecard(check: Callable[[str, object], None]) -> None:
    print("\n=== Scorecard ===")
    ranked = _score_answers(
        "plan",
        {"slop": {"0": 0.8, "1": 0.15, "2": 0.05}, "design": {"0": 0.35, "1": 0.2, "2": 0.45}},
    )
    expected_ranked = [
        (
            "- slop: material defect (P(defect)=0.80) It contains filler that must not "
            "ship: dead or commented-out code, duplicated blocks, generic names such as "
            "helper or data, or comments that restate the code."
        ),
        (
            "- design: concrete concern (P(defect)=0.35) It works within the structure "
            "but leaks an internal detail, duplicates an existing mechanism, or names "
            "something misleadingly."
        ),
        "Judged by jev-test.",
    ]
    check(
        "lines sort by defect with the model line last",
        render_scorecard("plan", [_judged(ranked)], True).split("\n") == expected_ranked,
    )
    concern = _score_answers("plan", {"correctness": {"0": 0.1, "1": 0.85, "2": 0.05}})
    expected_concern = [
        (
            "- correctness: concrete concern (P(defect)=0.10) It works on the main path "
            "but mishandles a specific edge case, error path, or boundary value."
        ),
        "Judged by jev-test.",
    ]
    check(
        "level-1 line shows even below the defect threshold",
        render_scorecard("plan", [_judged(concern)], True).split("\n") == expected_concern,
    )
    clean = render_scorecard("plan", [_judged(_score_answers("plan"))], True).split("\n")
    check(
        "clean review falls back to the no-defect line",
        clean
        == [
            "No dimension shows a material defect (highest P(defect)=0.00).",
            "Judged by jev-test.",
        ],
    )
    hot = {"0": 0.95, "1": 0.03, "2": 0.02}
    raised = render_scorecard(
        "write", [_judged(_score_answers("write", {"has_placeholder": 0.9}))], True
    ).split("\n")
    check(
        "raised spec_completion leads the write scorecard",
        (
            raised[0],
            raised[-1],
        )
        == (
            (
                "- spec_completion: material defect (P(defect)=0.90) A required part is "
                "missing, stubbed, or left as a placeholder, so it does not do its "
                "stated job."
            ),
            "Judged by jev-test.",
        ),
    )
    dropped_card = render_scorecard(
        "write",
        [_judged(_score_answers("write", {"correctness": hot, "is_executable_code": 0.4}))],
        True,
    )
    check(
        "dropped dimension never reaches the scorecard",
        "correctness" not in dropped_card,
    )


def _selftest_chunk_scorecard(check: Callable[[str, object], None]) -> None:
    print("\n=== Chunk Scorecard ===")
    slop_line = (
        "- slop: material defect (P(defect)=0.80) It contains filler that must not "
        "ship: dead or commented-out code, duplicated blocks, generic names such as "
        "helper or data, or comments that restate the code."
    )
    design_line = (
        "- design: concrete concern (P(defect)=0.35) It works within the structure "
        "but leaks an internal detail, duplicates an existing mechanism, or names "
        "something misleadingly."
    )
    slop_hot = {"0": 0.8, "1": 0.15, "2": 0.05}
    slop_warm = {"0": 0.4, "1": 0.3, "2": 0.3}
    design_warm = {"0": 0.35, "1": 0.2, "2": 0.45}
    clean = _score_answers("plan")
    worse_second = render_scorecard(
        "plan",
        [
            _judged(_score_answers("plan", {"slop": slop_warm})),
            _judged(_score_answers("plan", {"slop": slop_hot})),
        ],
        False,
    ).split("\n")
    check(
        "two chunks: the line comes from the worse chunk with its part suffix",
        worse_second[0] == slop_line + " (part 2 of 2)",
    )
    tie = render_scorecard(
        "plan",
        [
            _judged(_score_answers("plan", {"slop": slop_hot})),
            _judged(_score_answers("plan", {"slop": slop_hot})),
        ],
        False,
    ).split("\n")
    check("a tie keeps the earlier chunk", tie[0] == slop_line + " (part 1 of 2)")
    one_sided = render_scorecard(
        "plan",
        [_judged(clean), _judged(_score_answers("plan", {"design": design_warm}))],
        False,
    ).split("\n")
    check(
        "a dimension with a line in one chunk only keeps that line",
        one_sided[0] == design_line + " (part 2 of 2)",
    )
    added = render_scorecard(
        "plan",
        [
            _judged(_score_answers("plan", {"slop": slop_hot}), "jev-b"),
            _SkippedChunk(cause="judge request failed: HTTP 500"),
            _judged(clean, "jev-a"),
            _judged(clean, "jev-b"),
        ],
        False,
    ).split("\n")
    check(
        "both added lines appear in the stated order before the model line",
        added[1:]
        == [
            "Completeness was not judged: the subject was split into 4 parts.",
            "Parts not judged: 1 of 4 (judge request failed: HTTP 500).",
            "Judged by jev-b, jev-a.",
        ],
    )
    check(
        "two models are named once each in chunk order",
        added[-1] == "Judged by jev-b, jev-a.",
    )
    lowest = render_scorecard(
        "plan",
        [
            _judged(clean),
            _SkippedChunk(cause="judge request failed: HTTP 400"),
            _SkippedChunk(cause="judge request failed: HTTP 404"),
        ],
        False,
    ).split("\n")
    check(
        "parts line names the cause of the lowest-numbered failed chunk",
        lowest[-2] == "Parts not judged: 2 of 3 (judge request failed: HTTP 400).",
    )
    fallback = render_scorecard(
        "plan",
        [_judged(clean), _judged(_score_answers("plan", {"correctness": {"0": 0.2, "1": 0.0, "2": 0.8}}))],
        False,
    ).split("\n")
    check(
        "fallback line takes the highest defect over all judged chunks",
        fallback[0] == "No dimension shows a material defect (highest P(defect)=0.20).",
    )
    check(
        "one chunk is unchanged",
        render_scorecard(
            "plan",
            [_judged(_score_answers("plan", {"slop": slop_hot, "design": design_warm}))],
            True,
        ).split("\n")
        == [slop_line, design_line, "Judged by jev-test."],
    )
    check(
        "one chunk without completeness names the request",
        render_scorecard("plan", [_judged(clean)], False).split("\n")[-2]
        == "Completeness was not judged: the request does not fit in one part with the subject.",
    )
    unasked = _score_answers("write", {"has_placeholder": 0.9})
    del unasked["spec_completion"]
    check(
        "write answers without spec_completion derive a verdict and a scorecard",
        (
            derive_verdict("write", unasked),
            render_scorecard("write", [_judged(unasked)], False).split("\n")[-1],
        )
        == ("PASS", "Judged by jev-test."),
    )


def _post_to_judge(base_url: str, body: bytes) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        base_url + "/v1/systemone",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=_JUDGE_TIMEOUT_SECS) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def _selftest_transport_wire(check: Callable[[str, object], None]) -> None:
    print("\n=== Judge Transport Wire ===")
    key = "test-key-1234"
    questions = build_questions("plan")
    state = {"subject": "Add a retry with backoff to the upload loop."}
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_model = os.environ.get("TYPESAFE_DEFAULT_MODEL")
    os.environ["TYPESAFE_API_KEY"] = key
    os.environ.pop("TYPESAFE_DEFAULT_MODEL", None)
    try:
        ok_reply = _scripted_replies([(200, _answers_reply({}, "jev-1.14.0"), {})])
        with _RecordedJudgeServer(ok_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, model = invoke_judge(state, questions)
            record = judge.records[0]
            body = json.loads(record["body"])
            assert answers is not None
            correctness = answers["correctness"]
            assert correctness["type"] == "score"
            check(
                "loopback http base is allowed and answers come back",
                (answers is not None, model) == (True, "jev-1.14.0"),
            )
            check(
                "answers keep the response wire shape",
                (
                    correctness["type"],
                    sorted(correctness["probabilities"]),
                )
                == ("score", ["0", "1", "2"]),
            )
            check(
                "judge posts json to /v1/systemone",
                (
                    record["method"],
                    record["path"],
                    record["headers"].get("content-type"),
                    record["headers"].get("accept"),
                )
                == ("POST", "/v1/systemone", "application/json", "application/json"),
            )
            check(
                "bearer header carries the key",
                record["headers"].get("authorization") == f"Bearer {key}",
            )
            check(
                "body carries model, state, questions",
                sorted(body) == ["model", "questions", "state"],
            )
            check("default model is jev-1.14.0", body["model"] == "jev-1.14.0")
            write_answers, _ = invoke_judge(state, build_questions("write"))
            assert write_answers is not None
            wire = json.loads(judge.records[1]["body"])
            screen_wire = {
                question_id: wire["questions"][question_id]["type"]
                for question_id in (
                    "is_executable_code",
                    "touches_shared_state",
                    "has_placeholder",
                )
            }
            check(
                "screens ride the noul wire type",
                (
                    screen_wire,
                    write_answers["has_placeholder"]["type"],
                )
                == (
                    {
                        "is_executable_code": "noul",
                        "touches_shared_state": "noul",
                        "has_placeholder": "noul",
                    },
                    "noul",
                ),
            )
        with _RecordedJudgeServer(ok_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            rejections = (
                (
                    "questions as a list",
                    {
                        "model": "jev-1.14.0",
                        "state": {},
                        "questions": [{"id": "correctness", "type": "score"}],
                    },
                ),
                (
                    "score question with type score3",
                    {
                        "model": "jev-1.14.0",
                        "state": {},
                        "questions": {
                            "correctness": {
                                "type": "score3",
                                "instructions": "Rate the code change in `subject`.",
                                "criteria": ["too few", "levels"],
                            }
                        },
                    },
                ),
            )
            for name, body in rejections:
                status, payload = _post_to_judge(
                    judge.base_url, json.dumps(body).encode("utf-8")
                )
                check(
                    f"oracle rejects {name} with 422",
                    (status, "error" in payload) == (422, True),
                )
        os.environ["TYPESAFE_DEFAULT_MODEL"] = "jev-test-override"
        with _RecordedJudgeServer(ok_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            invoke_judge(state, questions)
            override_body = json.loads(judge.records[0]["body"])
            check(
                "TYPESAFE_DEFAULT_MODEL overrides the model",
                override_body["model"] == "jev-test-override",
            )
        os.environ["TYPESAFE_DEFAULT_MODEL"] = ""
        with _RecordedJudgeServer(ok_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            invoke_judge(state, questions)
            empty_body = json.loads(judge.records[0]["body"])
            check(
                "empty override falls back to the default model",
                empty_body["model"] == "jev-1.14.0",
            )
        os.environ["TYPESAFE_BASE_URL"] = "http://example.com"
        answers, cause = invoke_judge(state, questions)
        check(
            "non-loopback http base is refused before any request",
            (answers, cause) == (None, "judge request failed: ValueError"),
        )
        os.environ.pop("TYPESAFE_API_KEY", None)
        answers, cause = invoke_judge(state, questions)
        check(
            "missing key names the cause",
            (answers, cause) == (None, "TYPESAFE_API_KEY is not set"),
        )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("TYPESAFE_DEFAULT_MODEL", prev_model)


def _selftest_transport_failures(check: Callable[[str, object], None]) -> None:
    print("\n=== Judge Transport Failures ===")
    global _JUDGE_TIMEOUT_SECS, _JUDGE_BACKOFF_CAP_SECS
    questions = build_questions("plan")
    state = {"subject": "Add a retry with backoff to the upload loop."}
    prev_timeout, prev_cap = _JUDGE_TIMEOUT_SECS, _JUDGE_BACKOFF_CAP_SECS
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    _JUDGE_TIMEOUT_SECS = 0.25
    _JUDGE_BACKOFF_CAP_SECS = 0.01
    try:
        throttle = _scripted_replies(
            [(429, b"{}", {"Retry-After": "0"}), (200, _answers_reply({}, "jev-1.14.0"), {})]
        )
        with _RecordedJudgeServer(throttle) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, model = invoke_judge(state, questions)
            check(
                "429 is retried once and succeeds",
                (answers is not None, len(judge.records), model)
                == (True, 2, "jev-1.14.0"),
            )
        reject = _scripted_replies([(401, b"{}", {})])
        with _RecordedJudgeServer(reject) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "401 is not retried and names the status",
                (answers, cause, len(judge.records))
                == (None, "judge request failed: HTTP 401", 1),
            )
        with _RecordedJudgeServer(_scripted_replies([(200, _hanging_reply, {})])) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "silent server ends in judge request timed out",
                (answers, cause) == (None, "judge request timed out"),
            )
        with _RecordedJudgeServer(
            _scripted_replies([(200, _answers_reply({}, "jev-1.14.0"), {})])
        ) as target:
            redirect = _scripted_replies(
                [(302, b"", {"Location": target.base_url + "/v1/systemone"})]
            )
            with _RecordedJudgeServer(redirect) as source:
                os.environ["TYPESAFE_BASE_URL"] = source.base_url
                answers, cause = invoke_judge(state, questions)
                check(
                    "redirect is refused without retry",
                    (answers, cause, len(source.records))
                    == (None, "judge request failed: HTTP 302", 1),
                )
                check("redirect target records no request", target.records == [])
        with _RecordedJudgeServer(_scripted_replies([(200, b"this is not json", {})])) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "non-JSON body is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(_scripted_replies([(200, _reply_missing_dimension, {})])) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "missing requested question id is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(
            _scripted_replies(
                [(200, _ShortReply(b'{"model": "jev-1.14.0", "answers": {'), {})]
            )
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "truncated reply ends in a cause, not an exception",
                (answers, cause, len(judge.records))
                == (None, "judge request failed: IncompleteRead", 3),
            )
        with _RecordedJudgeServer(
            _scripted_replies([(200, b"[" * 100000, {})])
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "deeply nested reply is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(
            _scripted_replies(
                [
                    (
                        200,
                        (
                            b'{"model": "jev-1.14.0", "answers": {"correctness": '
                            b'{"type": "score", "probabilities": '
                            b'{"0": NaN, "1": 0.2, "2": 0.7}}}}'
                        ),
                        {},
                    )
                ]
            )
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "NaN probability is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(
            _scripted_replies([(200, b"x" * (_JUDGE_MAX_RESPONSE_BYTES + 1), {})])
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "oversized reply is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(_scripted_replies([(200, b'{"answers": {}}', {})])) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "reply without model is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(_scripted_replies([(200, b'{"model": "jev-1.14.0"}', {})])) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "reply without answers is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )

        def _non_numeric_noul_reply(record: _JudgeRequestRecord) -> bytes:
            payload = json.loads(_systemone_answer_body(record, {}, "jev-test"))
            payload["answers"]["has_placeholder"] = {"type": "noul", "noul": "high"}
            return json.dumps(payload).encode("utf-8")

        with _RecordedJudgeServer(
            _scripted_replies([(200, _non_numeric_noul_reply, {})])
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, build_questions("write"))
            check(
                "non-numeric noul is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )

        def _missing_level_reply(record: _JudgeRequestRecord) -> bytes:
            payload = json.loads(_systemone_answer_body(record, {}, "jev-test"))
            del payload["answers"]["correctness"]["probabilities"]["1"]
            return json.dumps(payload).encode("utf-8")

        with _RecordedJudgeServer(
            _scripted_replies([(200, _missing_level_reply, {})])
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, questions)
            check(
                "probabilities missing level 1 is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
        with _RecordedJudgeServer(
            _scripted_replies(
                [
                    (
                        200,
                        _answers_reply(
                            {"is_executable_code": {"0": 0.2, "1": 0.3, "2": 0.5}},
                            "jev-test",
                        ),
                        {},
                    )
                ]
            )
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(state, build_questions("write"))
            check(
                "score answer for a noul question is malformed",
                (answers, cause) == (None, "judge answer was malformed"),
            )
    finally:
        _JUDGE_TIMEOUT_SECS = prev_timeout
        _JUDGE_BACKOFF_CAP_SECS = prev_cap
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)


def _selftest_dispatch(check: Callable[[str, object], None]) -> None:
    print("\n=== Verdict Route Dispatch ===")
    score_program: _ScoreProgram = {"overrides": {}, "model": "jev-test"}
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_enabled = os.environ.get("CODEX_REFLECTOR_ENABLED")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    os.environ.pop("CODEX_REFLECTOR_ENABLED", None)
    try:
        judge_reply = _scripted_replies([(200, _programmed_reply(score_program), {})])
        with _RecordedJudgeServer(judge_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            score_program["overrides"] = {"correctness": {"0": 0.95, "1": 0.03, "2": 0.02}}
            code, out, err = _dispatch_hook_payload(
                _write_change_hook("def add(a, b):\n    return a + b\n")
            )
            payload = _parsed_hook_output(out)
            extra = payload.get("hookSpecificOutput", {})
            if not isinstance(extra, dict):
                extra = {}
            message = payload.get("systemMessage", "")
            if not isinstance(message, str):
                message = ""
            check(
                "write FAIL emits systemMessage and additionalContext",
                (
                    code,
                    message.startswith("Reflector Review") and "FAIL" in message,
                    extra.get("hookEventName"),
                    extra.get("additionalContext", "").startswith("Reflector Review")
                    and "Judged by" in extra.get("additionalContext", ""),
                )
                == (0, True, "PostToolUse", True),
            )
            score_program["overrides"] = {"slop": {"0": 0.05, "1": 0.93, "2": 0.02}}
            code, out, err = _dispatch_hook_payload(
                _write_change_hook("def add(a, b):\n    return a + b\n")
            )
            payload = _parsed_hook_output(out)
            message = payload.get("systemMessage", "")
            if not isinstance(message, str):
                message = ""
            context = payload.get("hookSpecificOutput", {})
            if not isinstance(context, dict):
                context = {}
            check(
                "level-1 heavy write review is UNCERTAIN with additionalContext",
                (
                    code,
                    "UNCERTAIN" in message,
                    "additionalContext" in context,
                )
                == (0, True, True),
            )
            score_program["overrides"] = {"correctness": {"0": 0.95, "1": 0.03, "2": 0.02}}
            mark = len(judge.records)
            code, out, err = _dispatch_hook_payload(_plan_approval_hook())
            payload = _parsed_hook_output(out)
            message = payload.get("systemMessage", "")
            if not isinstance(message, str):
                message = ""
            context = payload.get("hookSpecificOutput", {})
            if not isinstance(context, dict):
                context = {}
            plan_state = (
                json.loads(judge.records[mark]["body"])["state"]
                if len(judge.records) > mark
                else {}
            )
            check(
                "plan FAIL is advisory and judges the plan text as the only state",
                (
                    code,
                    message.startswith("Reflector Plan Review") and "FAIL" in message,
                    str(context.get("additionalContext", "")).startswith("Reflector Plan Review"),
                    plan_state,
                )
                == (0, True, True, {"subject": "# Plan\n\nAdd the retry loop."}),
            )
            score_program["overrides"] = {"correctness": {"0": 0.95, "1": 0.03, "2": 0.02}}
            code, out, err = _dispatch_hook_payload(_session_stop_hook())
            check(
                "stop at 0.9 or more exits 2 with the scorecard on stderr",
                (code, err.startswith("Reflector Stop Review FAIL") and "Judged by" in err, out)
                == (2, True, ""),
            )
            score_program["overrides"] = {"correctness": {"0": 1.53, "1": 0.0, "2": 0.0}}
            code, out, err = _dispatch_hook_payload(_session_stop_hook())
            check(
                "probability above one skips the stop review",
                (code, _parsed_hook_output(out))
                == (
                    0,
                    {
                        "systemMessage": "codex-reflector: review skipped: judge answer was malformed"
                    },
                ),
            )
            score_program["overrides"] = {}
            code, out, err = _dispatch_hook_payload(_session_stop_hook())
            payload = _parsed_hook_output(out)
            message = payload.get("systemMessage", "")
            if not isinstance(message, str):
                message = ""
            check(
                "stop below 0.9 settles with a systemMessage",
                (code, message.startswith("Reflector Stop Review") and "Judged by" in message)
                == (0, True),
            )
            score_program["overrides"] = {"slop": {"0": 0.05, "1": 0.93, "2": 0.02}}
            code, out, err = _dispatch_hook_payload(_session_stop_hook())
            payload = _parsed_hook_output(out)
            check(
                "level-1 heavy stop does not block",
                (code, "decision" in payload, "systemMessage" in payload)
                == (0, False, True),
            )
            score_program["overrides"] = {}
            head_marker = "TRANSCRIPT-HEAD-MARKER"
            tail_marker = "TRANSCRIPT-TAIL-MARKER"
            filler_line = "x\n"
            filler_lines = 600 * 1024 // len(filler_line)
            transcript_bytes = (
                f"{head_marker}\n"
                f"{filler_line * filler_lines}"
                f"{tail_marker}\n"
            ).encode()
            fd, transcript_path = tempfile.mkstemp(suffix=".jsonl")
            try:
                with os.fdopen(fd, "wb") as transcript_file:
                    transcript_file.write(transcript_bytes)
                stop_hook = _session_stop_hook()
                del stop_hook["last_assistant_message"]
                stop_hook["transcript_path"] = transcript_path
                mark = len(judge.records)
                _dispatch_hook_payload(stop_hook)
                joined = _joined_subject(judge.records[mark:])
                check(
                    "stop subject is the whole transcript, joined in part order",
                    (
                        joined == _redact(transcript_bytes.decode()),
                        joined.startswith(head_marker),
                    )
                    == (True, True),
                )
                check(
                    "stop without a last assistant message reads a transcript over 500,000 bytes in full",
                    (len(transcript_bytes) > 500_000, head_marker in joined, tail_marker in joined)
                    == (True, True, True),
                )
            finally:
                os.unlink(transcript_path)
            token = "sk-" + "c" * 24
            mark = len(judge.records)
            _dispatch_hook_payload(
                _write_change_hook("x = 1\n", instruction=f"Ship it with {token}")
            )
            instructed = (
                json.loads(judge.records[mark]["body"])["state"]
                if len(judge.records) > mark
                else {}
            )
            mark = len(judge.records)
            _dispatch_hook_payload(_write_change_hook("x = 1\n"))
            plain = (
                json.loads(judge.records[mark]["body"])["state"]
                if len(judge.records) > mark
                else {}
            )
            check(
                "instruction rides the request field redacted",
                (sorted(instructed), instructed.get("request"))
                == (["file", "request", "subject"], "Ship it with [REDACTED]"),
            )
            check(
                "no instruction means no request field",
                sorted(plain) == ["file", "subject"],
            )
            os.environ.pop("TYPESAFE_API_KEY", None)
            skip_notice = {
                "systemMessage": "codex-reflector: review skipped: TYPESAFE_API_KEY is not set"
            }
            for name, hook in (
                ("write", _write_change_hook("x = 1")),
                ("plan", _plan_approval_hook()),
                ("stop", _session_stop_hook()),
            ):
                code, out, err = _dispatch_hook_payload(hook)
                check(
                    f"missing key emits the skip notice on {name}",
                    (code, _parsed_hook_output(out)) == (0, skip_notice),
                )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("CODEX_REFLECTOR_ENABLED", prev_enabled)


def _selftest_chunk_dispatch(check: Callable[[str, object], None]) -> None:
    print("\n=== Chunk Dispatch ===")
    hot = {"0": 0.95, "1": 0.03, "2": 0.02}
    ok: _JudgeReply = (200, _answers_reply({}, "jev-test"), {})
    defect: _JudgeReply = (200, _answers_reply({"correctness": hot}, "jev-test"), {})
    replies: dict[int, _JudgeReply] = {}
    content = "value = 1\n" * 7000
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_enabled = os.environ.get("CODEX_REFLECTOR_ENABLED")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    os.environ.pop("CODEX_REFLECTOR_ENABLED", None)
    try:
        with _RecordedJudgeServer(_part_replies(replies, ok)) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            mark = len(judge.records)
            code, out, err = _dispatch_hook_payload(
                _write_change_hook(content, instruction="Ship it")
            )
            sent = judge.records[mark:]
            states = [_record_state(record) for record in sent]
            message = str(_parsed_hook_output(out).get("systemMessage", ""))
            check(
                "oversized write makes one request per chunk",
                (len(sent), len(_chunk_text(content))) == (3, 3),
            )
            check(
                "recorded subjects join to the redacted subject",
                _joined_subject(sent) == _redact(content),
            )
            check(
                "each chunk request carries its part",
                sorted(state.get("part", "") for state in states)
                == ["1 of 3", "2 of 3", "3 of 3"],
            )
            check(
                "split subject sends no request field and no spec_completion question",
                (
                    any("request" in state for state in states),
                    any(
                        "spec_completion" in json.loads(record["body"])["questions"]
                        for record in sent
                    ),
                )
                == (False, False),
            )
            check(
                "split write scorecard holds the split line",
                (
                    code,
                    "Completeness was not judged: the subject was split into 3 parts."
                    in message.split("\n"),
                )
                == (0, True),
            )
            mark = len(judge.records)
            code, out, err = _dispatch_hook_payload(
                _write_change_hook("a = 1\n" * 4000, instruction="Do it " * 1000)
            )
            sent = judge.records[mark:]
            message = str(_parsed_hook_output(out).get("systemMessage", ""))
            check(
                "subject that fits beside an oversized request makes one request without request",
                (len(sent), sorted(_record_state(sent[0])) if sent else [])
                == (1, ["file", "subject"]),
            )
            check(
                "subject that fits beside an oversized request gives the one-chunk completeness line",
                "Completeness was not judged: the request does not fit in one part with the subject."
                in message.split("\n"),
            )
            replies[3] = defect
            code, out, err = _dispatch_hook_payload(_write_change_hook(content))
            message = str(_parsed_hook_output(out).get("systemMessage", ""))
            check(
                "a defect only in the last chunk gives FAIL",
                (code, "FAIL" in message, "(part 3 of 3)" in message) == (0, True, True),
            )
            replies.clear()
            replies[2] = defect
            stop_hook = _session_stop_hook()
            stop_hook["last_assistant_message"] = "Done the work.\n" * 5000
            code, out, err = _dispatch_hook_payload(stop_hook)
            check(
                "stop with a block-level defect in a middle chunk exits 2",
                (code, "(part 2 of 3)" in err, out) == (2, True, ""),
            )
            replies.clear()
            replies[2] = (400, b"{}", {})
            replies[3] = (404, b"{}", {})
            code, out, err = _dispatch_hook_payload(_write_change_hook(content))
            check(
                "no FAIL with failed chunks 2 and 3 skips with the cause of chunk 2",
                (code, _parsed_hook_output(out))
                == (
                    0,
                    {
                        "systemMessage": "codex-reflector: review skipped: judge request failed: HTTP 400"
                    },
                ),
            )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("CODEX_REFLECTOR_ENABLED", prev_enabled)


def _selftest_chunk_transport(check: Callable[[str, object], None]) -> None:
    print("\n=== Chunk Transport ===")
    global _JUDGE_BACKOFF_CAP_SECS, _JUDGE_RANDOM, _JUDGE_REVIEW_DEADLINE_SECS
    prev_cap, prev_random = _JUDGE_BACKOFF_CAP_SECS, _JUDGE_RANDOM
    prev_deadline = _JUDGE_REVIEW_DEADLINE_SECS
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    hot = {"0": 0.95, "1": 0.03, "2": 0.02}
    ok: _JudgeReply = (200, _answers_reply({}, "jev-test"), {})
    two_parts = "line\n" * 8000
    twenty_parts = "row\n" * (CHUNK_MAX_BYTES * 5)

    def low_draw() -> float:
        return 0.0

    try:
        samples = [
            (
                min(0.5 * (2 ** attempt), _JUDGE_BACKOFF_CAP_SECS),
                _retry_wait(attempt, None, 60.0),
            )
            for attempt in range(_JUDGE_MAX_ATTEMPTS)
            for _ in range(200)
        ]
        check(
            "each computed wait lies between half the nominal wait and the nominal wait",
            all(0.5 * nominal <= wait <= nominal for nominal, wait in samples),
        )
        _JUDGE_RANDOM = low_draw
        check(
            "the replaced random source at its low end gives half the nominal wait",
            _retry_wait(1, None, 60.0) == 0.5,
        )
        check(
            "a Retry-After wait is not changed",
            _retry_wait(2, {"Retry-After": "0.3"}, 60.0) == 0.3,
        )
        check("a wait is at most the time left", _retry_wait(2, None, 0.05) == 0.05)
        _JUDGE_BACKOFF_CAP_SECS = 0.01
        fail_then_500 = _part_replies(
            {
                1: (200, _answers_reply({"correctness": hot}, "jev-test"), {}),
                2: (500, b"{}", {}),
            },
            ok,
        )
        with _RecordedJudgeServer(fail_then_500) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            verdict, body = judge_review("plan", {"subject": two_parts})
            second = [record for record in judge.records if _record_part(record) == 2]
            check(
                "FAIL in chunk 1 stands over HTTP 500 on every attempt of chunk 2",
                (
                    verdict,
                    len(second),
                    "Parts not judged: 1 of 2 (judge request failed: HTTP 500)."
                    in body.split("\n"),
                )
                == ("FAIL", _JUDGE_MAX_ATTEMPTS, True),
            )
        refuse_first = _part_replies(
            {1: (401, b"{}", {})}, (200, _held_answers(0.5), {})
        )
        with _RecordedJudgeServer(refuse_first) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            verdict, notice = judge_review("plan", {"subject": twenty_parts})
            late = [record for record in judge.records if _record_part(record) >= 9]
            check(
                "HTTP 401 on chunk 1 of 20 stops chunks 9 to 20 "
                "(the 500 ms hold on other chunks is a timing margin)",
                (verdict, notice, late)
                == (
                    None,
                    "codex-reflector: review skipped: judge request failed: HTTP 401",
                    [],
                ),
            )
        with _RecordedJudgeServer(
            _part_replies({}, (200, _held_answers(0.2), {}))
        ) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            verdict, _ = judge_review("plan", {"subject": twenty_parts})
            check(
                "stub never sees more than 8 requests in flight for 20 chunks",
                (verdict, len(judge.records), 1 < judge.max_in_flight <= 8)
                == ("PASS", 20, True),
            )
        _JUDGE_REVIEW_DEADLINE_SECS = 1.0
        with _RecordedJudgeServer(_part_replies({}, (200, _silent_reply, {}))) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            started = time.monotonic()
            verdict, notice = judge_review("plan", {"subject": "Add the retry loop."})
            elapsed = time.monotonic() - started
            check(
                "1 s deadline ends a silent review with judge request timed out in under 4 s",
                (verdict, notice, elapsed < 4.0)
                == (None, "codex-reflector: review skipped: judge request timed out", True),
            )
    finally:
        _JUDGE_BACKOFF_CAP_SECS, _JUDGE_RANDOM = prev_cap, prev_random
        _JUDGE_REVIEW_DEADLINE_SECS = prev_deadline
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)


def _selftest_review_bounds(check: Callable[[str, object], None]) -> None:
    print("\n=== Review Deadline ===")
    global _JUDGE_REVIEW_DEADLINE_SECS
    prev_deadline = _JUDGE_REVIEW_DEADLINE_SECS
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    timed_out = "codex-reflector: review skipped: judge request timed out"
    skew = [0.0]

    def skewed_clock() -> float:
        return time.monotonic() + skew[0]

    def late_answer(record: _JudgeRequestRecord) -> bytes:
        skew[0] = 3600.0
        return _systemone_answer_body(record, {}, "jev-test")

    try:
        review = _Review()
        review.clock = skewed_clock
        with _RecordedJudgeServer(_scripted_replies([(200, late_answer, {})])) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            answers, cause = invoke_judge(
                {"subject": "Add the retry loop."}, build_questions("plan"), review
            )
            check(
                "a valid answer completed after the deadline is discarded without retry",
                (answers, cause, len(judge.records))
                == (None, "judge request timed out", 1),
            )
        _JUDGE_REVIEW_DEADLINE_SECS = 1.0
        trickles = (
            ("a body sent one byte per 0.2 s", _trickled_body),
            ("a status line and headers sent one byte per 0.2 s", _trickled_head),
        )
        for name, reply in trickles:
            with _RecordedJudgeServer(_scripted_replies([(200, reply, {})])) as judge:
                os.environ["TYPESAFE_BASE_URL"] = judge.base_url
                started = time.monotonic()
                verdict, notice = judge_review("plan", {"subject": "Add the retry loop."})
                elapsed = time.monotonic() - started
                check(
                    f"{name} ends at the 1 s deadline in under 3 s",
                    (verdict, notice, elapsed < 3.0) == (None, timed_out, True),
                )
        forty_parts = "row\n" * (CHUNK_MAX_BYTES * 10)
        with _RecordedJudgeServer(_part_replies({}, (200, _silent_reply, {}))) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            started = time.monotonic()
            verdict, notice = judge_review("plan", {"subject": forty_parts})
            elapsed = time.monotonic() - started
            check(
                "40 queued chunks share one 1 s deadline against a silent server "
                "and end in under 4 s (five waves of 8 would take 5 s)",
                (len(_chunk_text(forty_parts)), verdict, notice, elapsed < 4.0)
                == (40, None, timed_out, True),
            )
    finally:
        _JUDGE_REVIEW_DEADLINE_SECS = prev_deadline
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)


def _selftest_review_refusal(check: Callable[[str, object], None]) -> None:
    print("\n=== Review Refusal ===")
    review = _Review()
    review.refuse("a")
    review.refuse("b")
    check(
        "the first refusal cause is kept and admit returns it",
        (review.refused, review.admit()) == ("a", "a"),
    )
    left, right = socket.socketpair()
    right.settimeout(2.0)
    recorder = _ShutdownRecorder(left.family, left.type, left.proto, fileno=left.detach())
    try:
        _shut_socket(recorder)
        check(
            "expiry shuts the raw socket and skips a subclass shutdown, which on ssl.SSLSocket drops the TLS layer first",
            (recorder.subclass_shutdowns, right.recv(1)) == (0, b""),
        )
    finally:
        recorder.close()
        right.close()
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    refuse_first = _part_replies(
        {1: (403, b"{}", {})}, (200, _held_answers(0.5), {})
    )
    try:
        with _RecordedJudgeServer(refuse_first) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            states, completeness_judged = _chunk_states(
                {"subject": "row\n" * (CHUNK_MAX_BYTES * 5)}
            )
            results = _judge_chunks(
                states, build_questions("plan", "", completeness_judged)
            )
            started = {_record_part(record) for record in judge.records}
            unstarted = [
                _chunk_cause(result)
                for part, result in enumerate(results, 1)
                if part not in started
            ]
            check(
                "HTTP 403 on chunk 1 of 20 starts no chunk after 8, and each chunk "
                "that did not start has the 403 cause "
                "(the 500 ms hold on other chunks is a timing margin)",
                (
                    1 in started,
                    max(started, default=0) <= 8,
                    unstarted == ["judge request failed: HTTP 403"] * (20 - len(started)),
                )
                == (True, True, True),
            )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)


def _request_shape(sent: list[_JudgeRequestRecord]) -> tuple[int, bool, bool]:
    if not sent:
        return 0, False, False
    body = json.loads(sent[0]["body"])
    return len(sent), "request" in body["state"], "spec_completion" in body["questions"]


def _huge_probability_reply(record: _JudgeRequestRecord) -> bytes:
    payload = json.loads(_systemone_answer_body(record, {}, "jev-test"))
    payload["answers"]["correctness"]["probabilities"]["0"] = 10**400
    return json.dumps(payload).encode("utf-8")


def _fast_apply_subject(judge: _RecordedJudgeServer, applied_text: str) -> str:
    with tempfile.TemporaryDirectory() as root:
        applied = Path(root) / "big.py"
        applied.write_text(applied_text, encoding="utf-8")
        mark = len(judge.records)
        _dispatch_hook_payload(
            {
                "hook_event_name": "PostToolUse",
                "cwd": root,
                "tool_name": "mcp__morph__edit_file",
                "tool_input": {
                    "file_path": str(applied),
                    "code_edit": "b = 2",
                    "instruction": "Set b",
                },
            }
        )
        return _joined_subject(judge.records[mark:])


def _selftest_chunk_routes(check: Callable[[str, object], None]) -> None:
    print("\n=== Chunk Routes ===")
    hot = {"0": 0.95, "1": 0.03, "2": 0.02}
    ok: _JudgeReply = (200, _answers_reply({}, "jev-test"), {})
    replies: dict[int, _JudgeReply] = {1: (200, _huge_probability_reply, {})}
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_enabled = os.environ.get("CODEX_REFLECTOR_ENABLED")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    os.environ.pop("CODEX_REFLECTOR_ENABLED", None)
    try:
        with _RecordedJudgeServer(_part_replies(replies, ok)) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            code, out, _ = _dispatch_hook_payload(_write_change_hook("value = 1\n"))
            check(
                "a 401-digit integer probability skips the review with one notice "
                "and no traceback",
                (code, _parsed_hook_output(out))
                == (
                    0,
                    {
                        "systemMessage": "codex-reflector: review skipped: judge answer was malformed"
                    },
                ),
            )
            replies.clear()
            marker = "FAST-APPLY-TAIL-MARKER"
            applied_text = "a" * 50_000 + marker + "b" * (10_000 - len(marker))
            check(
                "Fast Apply sends a 60,000-character file whole, "
                "with the marker after character 50,000",
                marker in _fast_apply_subject(judge, applied_text),
            )
            subject = "\u00e9" * 13_000
            request = "\u00fc" * 1_000
            mark = len(judge.records)
            _dispatch_hook_payload(_write_change_hook(subject, instruction=request))
            check(
                "subject plus request at exactly 28,000 UTF-8 bytes (14,000 characters) "
                "makes one call with request and spec_completion",
                _request_shape(judge.records[mark:]) == (1, True, True),
            )
            mark = len(judge.records)
            _dispatch_hook_payload(_write_change_hook(subject, instruction=request + "x"))
            check(
                "one byte more makes one call without request and without spec_completion",
                _request_shape(judge.records[mark:]) == (1, False, False),
            )
            mark = len(judge.records)
            _dispatch_hook_payload(_write_change_hook("a" * (CHUNK_MAX_BYTES + 1)))
            check(
                "a write subject one byte over the limit makes two calls",
                len(judge.records[mark:]) == 2,
            )
            secret_path = "src/password=hunter2/patch.py"
            mark = len(judge.records)
            _dispatch_hook_payload(
                {
                    "hook_event_name": "PostToolUse",
                    "cwd": os.getcwd(),
                    "tool_name": "Write",
                    "tool_input": {"file_path": secret_path, "content": "value = 1\n" * 7000},
                }
            )
            files = [_record_state(record).get("file") for record in judge.records[mark:]]
            check(
                "every part of a split write holds the same whole redacted file value",
                (len(files), set(files), _redact(secret_path) == secret_path)
                == (3, {_redact(secret_path)}, False),
            )
            plan = "# Plan\n\npassword = hunter2\n" + "- step\n" * 9000
            mark = len(judge.records)
            _dispatch_hook_payload(
                {
                    "hook_event_name": "PostToolUse",
                    "cwd": os.getcwd(),
                    "tool_name": "ExitPlanMode",
                    "tool_response": {"plan": plan},
                }
            )
            sent = judge.records[mark:]
            check(
                "a plan over the limit goes out in parts that join to the redacted plan",
                (len(sent) > 1, _joined_subject(sent) == _redact(plan), _redact(plan) == plan)
                == (True, True, False),
            )
            replies[1] = (
                200,
                _answers_reply({"is_executable_code": 0.1, "correctness": hot}, "jev-test"),
                {},
            )
            replies[2] = (
                200,
                _answers_reply({"is_executable_code": 0.9, "correctness": hot}, "jev-test"),
                {},
            )
            verdict, body = judge_review(
                "write", {"file": "src/patch.py", "subject": "line\n" * 8000}, "src/patch.py"
            )
            correctness = [
                line for line in body.split("\n") if line.startswith("- correctness:")
            ]
            check(
                "mixed code screens: chunk 1 drops correctness, chunk 2 keeps it",
                (verdict, [line.endswith("(part 2 of 2)") for line in correctness])
                == ("FAIL", [True]),
            )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("CODEX_REFLECTOR_ENABLED", prev_enabled)


def _selftest_secrets(check: Callable[[str, object], None]) -> None:
    print("\n=== Secrets ===")
    token = "sk-" + "a" * 24
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_enabled = os.environ.get("CODEX_REFLECTOR_ENABLED")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    os.environ.pop("CODEX_REFLECTOR_ENABLED", None)
    try:
        ok_reply = _scripted_replies([(200, _answers_reply({}, "jev-test"), {})])
        with _RecordedJudgeServer(ok_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            code, _, _ = _dispatch_hook_payload(
                _write_change_hook(f'API_KEY = "{token}"\n')
            )
            sent = judge.records[0]["body"]
            check(
                "token is redacted before it reaches the judge",
                (code, token.encode() in sent, b"[REDACTED]" in sent)
                == (0, False, True),
            )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("CODEX_REFLECTOR_ENABLED", prev_enabled)


def _selftest_transport_bad_key(check: Callable[[str, object], None]) -> None:
    print("\n=== Judge Transport Bad Key ===")
    import contextlib
    import io

    questions = build_questions("plan")
    state = {"subject": "Add a retry with backoff to the upload loop."}
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_debug = os.environ.get("CODEX_REFLECTOR_DEBUG")
    os.environ["TYPESAFE_API_KEY"] = "sk-abc\r\nX: y"
    os.environ["TYPESAFE_BASE_URL"] = "http://127.0.0.1:9"
    os.environ["CODEX_REFLECTOR_DEBUG"] = "1"
    try:
        stderr_io = io.StringIO()
        with contextlib.redirect_stderr(stderr_io):
            answers, cause = invoke_judge(state, questions)
        captured = stderr_io.getvalue()
        check(
            "invalid key ends in a ValueError cause without echoing the key",
            (answers, cause, "sk-abc" in cause, "sk-abc" in captured)
            == (None, "judge request failed: ValueError", False, False),
        )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("CODEX_REFLECTOR_DEBUG", prev_debug)


def _selftest_transport_loopback_proxy(check: Callable[[str, object], None]) -> None:
    print("\n=== Judge Loopback Proxy Bypass ===")
    questions = build_questions("plan")
    state = {"subject": "Add a retry with backoff to the upload loop."}
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_proxy_upper = os.environ.get("HTTP_PROXY")
    prev_proxy_lower = os.environ.get("http_proxy")
    ok_reply = _scripted_replies([(200, _answers_reply({}, "jev-1.14.0"), {})])
    try:
        os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
        with _RecordedJudgeServer(ok_reply) as proxy:
            os.environ["HTTP_PROXY"] = proxy.base_url
            os.environ["http_proxy"] = proxy.base_url
            with _RecordedJudgeServer(ok_reply) as judge:
                os.environ["TYPESAFE_BASE_URL"] = judge.base_url
                answers, model = invoke_judge(state, questions)
                check(
                    "loopback judge call bypasses the environment proxy",
                    (
                        answers is not None,
                        model,
                        len(judge.records),
                        proxy.records,
                    )
                    == (True, "jev-1.14.0", 1, []),
                )
    finally:
        _restore_env("HTTP_PROXY", prev_proxy_upper)
        _restore_env("http_proxy", prev_proxy_lower)
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)


def _selftest_redact_before_chunk(check: Callable[[str, object], None]) -> None:
    print("\n=== Redact Before Chunk ===")
    token = "sk-" + "b" * 24
    prev_key = os.environ.get("TYPESAFE_API_KEY")
    prev_base = os.environ.get("TYPESAFE_BASE_URL")
    prev_enabled = os.environ.get("CODEX_REFLECTOR_ENABLED")
    os.environ["TYPESAFE_API_KEY"] = "test-key-1234"
    os.environ.pop("CODEX_REFLECTOR_ENABLED", None)
    try:
        ok_reply = _scripted_replies([(200, _answers_reply({}, "jev-test"), {})])
        with _RecordedJudgeServer(ok_reply) as judge:
            os.environ["TYPESAFE_BASE_URL"] = judge.base_url
            content = "x" * (CHUNK_MAX_BYTES - 10) + token + "\n" + "y" * 1000
            _dispatch_hook_payload(_write_change_hook(content))
            bodies = [record["body"] for record in judge.records]
            pieces = (token, token[:8], token[-8:])
            check(
                "token across an unredacted chunk boundary is in no request",
                (
                    len(bodies),
                    any(piece.encode() in body for body in bodies for piece in pieces),
                )
                == (2, False),
            )
    finally:
        _restore_env("TYPESAFE_API_KEY", prev_key)
        _restore_env("TYPESAFE_BASE_URL", prev_base)
        _restore_env("CODEX_REFLECTOR_ENABLED", prev_enabled)


def _selftest_safe_edit_paths(check: Callable[[str, object], None]) -> None:
    print("\n=== Safe Edit Paths ===")
    cwd = os.getcwd()
    inside = str((Path(cwd) / "src" / "patch.py").resolve())
    check("edit path inside cwd is allowed", _is_safe_edit_path(inside, cwd) is True)
    check(
        "edit path outside cwd and plans is refused",
        _is_safe_edit_path("/etc/hostname", cwd) is False,
    )


def run_self_test() -> None:
    results: list[bool] = []

    def check(desc: str, ok: object) -> None:
        results.append(bool(ok))
        print(f"  {'OK' if ok else 'FAIL'}: {desc}")

    watched_env = (
        "TYPESAFE_BASE_URL",
        "TYPESAFE_API_KEY",
        "TYPESAFE_DEFAULT_MODEL",
        "CODEX_REFLECTOR_ENABLED",
    )
    saved_env = {name: os.environ.get(name) for name in watched_env}
    try:
        _selftest_plan_paths(check)
        _selftest_synthetic_paths(check)
        _selftest_fast_apply(check)
        _selftest_classify(check)
        _selftest_safe_edit_paths(check)
        _selftest_cursor(check)
        _selftest_stateless_stop(check)
        _selftest_questions(check)
        _selftest_question_wording(check)
        _selftest_chunk_text(check)
        _selftest_combine(check)
        _selftest_verdict_rule(check)
        _selftest_amendment_rule(check)
        _selftest_screens(check)
        _selftest_scorecard(check)
        _selftest_chunk_scorecard(check)
        _selftest_transport_wire(check)
        _selftest_transport_failures(check)
        _selftest_transport_bad_key(check)
        _selftest_transport_loopback_proxy(check)
        _selftest_redact_before_chunk(check)
        _selftest_dispatch(check)
        _selftest_chunk_dispatch(check)
        _selftest_chunk_transport(check)
        _selftest_review_bounds(check)
        _selftest_review_refusal(check)
        _selftest_chunk_routes(check)
        _selftest_secrets(check)
    finally:
        for name, value in saved_env.items():
            _restore_env(name, value)
    passed = sum(1 for ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


def main() -> None:
    if "--test-parse" in sys.argv:
        run_self_test()
        return

    if os.environ.get("CODEX_REFLECTOR_ENABLED", "1") == "0":
        sys.exit(0)

    try:
        hook_data = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, OSError):
        sys.exit(0)

    hook_data = _normalize_cursor_input(hook_data)

    event = hook_data.get("hook_event_name", "")
    if not isinstance(event, str):
        event = ""
    cwd = hook_data.get("cwd", os.getcwd())
    if not isinstance(cwd, str):
        cwd = os.getcwd()

    debug(f"event={event} tool={hook_data.get('tool_name', 'N/A')}")

    result: dict[str, object] | None = None

    if event == "Stop":
        result = respond_stop(hook_data)

    elif event == "PostToolUse":
        tool_name = hook_data.get("tool_name", "")
        if not isinstance(tool_name, str):
            tool_name = ""
        tool_input = hook_data.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}
        routed = classify(tool_name)
        if routed is None:
            sys.exit(0)
        debug(f"category={routed}")

        if routed == "code_change":
            result = respond_code_review(
                tool_name, tool_input, cwd=cwd, event_name=event
            )
        elif routed == "plan_review":
            plan = _find_plan_for_session(hook_data)
            if plan is None:
                sys.exit(0)
            plan_path, plan_content = plan
            result = respond_plan_review(plan_path, plan_content, event_name=event)

    else:
        debug(f"unhandled event: {event}")
        sys.exit(0)

    if result:
        exit_code = result.get("_exit", 2 if result.get("decision") == "block" else 0)
        if not isinstance(exit_code, int):
            exit_code = 0
        payload = {k: v for k, v in result.items() if k != "_exit"}
        if exit_code >= 2:
            print(
                payload.get("reason", payload.get("systemMessage", "")), file=sys.stderr
            )
            sys.exit(exit_code)
        print(json.dumps(payload))
    sys.exit(0)


if __name__ == "__main__":
    main()
