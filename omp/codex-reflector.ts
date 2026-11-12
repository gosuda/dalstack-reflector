/**
 * codex-reflector — native oh-my-pi (Pi) hook.
 *
 * Routes oh-my-pi events to one reviewer, the omp judge role: a typed
 * decision-model judge whose probability answers the reflector turns into a
 * verdict in code. A TypeScript port of `scripts/codex-reflector.py` (the
 * Claude Code / Cursor plugin); no Python runtime dependency.
 *
 * Routes (oh-my-pi native tool names):
 *   - write review:   write / edit / ast_edit / fast_edit + Fast-Apply MCP (success)
 *                      -> tool_result content (advisory, every verdict; never blocks)
 *   - bash pre-guard: bash (prescreen-matched, before execution)            -> block on FAIL only
 *   - stop review:    session_stop (PASS/UNCERTAIN, fresh review)           -> settle (UI notice only)
 *   - FAIL enforce:   session_stop (FAIL, fresh review)                     -> continue (block decision)
 *   - abort settle:   session_stop (settled turn aborted)                   -> settle silently, no review
 *
 * Delivery-channel rule: code-change reviews are advisory — oh-my-pi applies a
 * tool_result `content` override on the SUCCESS path for every verdict and the
 * review never sets isError, so a succeeded edit is never rethrown as a failed
 * tool call. An error result is left untouched. The bash tool_call guard is a
 * prescreen-triggered pre-execution FAIL-only block: only commands matching a
 * coarse local risk pattern reach the judge; holistic Stop remains the only
 * post-hoc blocking gate.
 *
 * Env vars: CODEX_REFLECTOR_ENABLED ("0" disables), CODEX_REFLECTOR_BASH_GUARD
 * ("1" enables opt-in bash pre-guard, "0" disables), CODEX_REFLECTOR_STOP_REVIEW
 * ("1" enables opt-in stop review, "0" disables), CODEX_REFLECTOR_DEBUG ("1" for
 * logger diagnostics).
 */

import type { Answer, JudgmentResult, NoulQuestion, Questions, ScoreQuestion } from "@oh-my-pi/pi-ai";
import type { ExtensionAPI, ToolResultEvent, ToolResultEventResult } from "@oh-my-pi/pi-coding-agent";
import type { JudgeDeps } from "@oh-my-pi/pi-coding-agent/judgment";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEBUG = process.env.CODEX_REFLECTOR_DEBUG === "1";

// Per-handler budget shared across the judge round-trips in one handler
// invocation. The harness caps a handler at 30 s (EXTENSION_HANDLER_TIMEOUT_MS)
// without aborting it, so this budget must stay under that cap.
export const HANDLER_BUDGET_MS = 25_000;
let handlerBudgetMs = HANDLER_BUDGET_MS;
/** Test-only: shrink the per-handler budget so the deadline can be exercised
 *  without a 25s wait. Restore with testSetHandlerBudgetMs(HANDLER_BUDGET_MS). */
export function testSetHandlerBudgetMs(ms: number): void {
	handlerBudgetMs = ms;
}

export type Verdict = "PASS" | "FAIL" | "UNCERTAIN";

// ---------------------------------------------------------------------------
// Unknown-shape access (duck-typing for event payloads we do not own)
// ---------------------------------------------------------------------------

function getProp(obj: unknown, key: string): unknown {
	return obj !== null && typeof obj === "object"
		? (obj as Record<string, unknown>)[key]
		: undefined;
}

/** stopReason of the turn being settled: the event's last_assistant_message,
 * else the last assistant entry in messages. */
function settledStopReason(event: unknown): string | undefined {
	const direct = getProp(getProp(event, "last_assistant_message"), "stopReason");
	if (typeof direct === "string") return direct;
	const messages = getProp(event, "messages");
	if (!Array.isArray(messages)) return undefined;
	for (let i = messages.length - 1; i >= 0; i--) {
		if (getProp(messages[i], "role") === "assistant") {
			const sr = getProp(messages[i], "stopReason");
			return typeof sr === "string" ? sr : undefined;
		}
	}
	return undefined;
}

function pickString(input: Record<string, unknown>, keys: readonly string[], fallback: string): string {
	for (const key of keys) {
		const value = input[key];
		if (typeof value === "string" && value.length > 0) return value;
	}
	return fallback;
}

// ---------------------------------------------------------------------------
// Diagnostics — best-effort, routed to the agent logger (never stdout/stderr,
// which hooks share with the agent's own streams).
// ---------------------------------------------------------------------------

let logger: unknown;

function debug(msg: string): void {
	if (!DEBUG) return;
	const line = `[codex-reflector] ${msg}`;
	try {
		const dbg = getProp(logger, "debug");
		const info = getProp(logger, "info");
		if (typeof dbg === "function") (dbg as (m: string) => void).call(logger, line);
		else if (typeof info === "function") (info as (m: string) => void).call(logger, line);
	} catch {
		/* logging is best-effort */
	}
}

/** Best-effort UI notification: silent in headless mode, never throws. */
export function notifyUI(
	ctx: { hasUI: boolean; ui: { notify(msg: string, level?: "info" | "warning" | "error"): void } },
	msg: string,
	level: "info" | "warning" | "error",
): void {
	try {
		if (ctx.hasUI) ctx.ui.notify(msg, level);
	} catch {
		/* UI is optional */
	}
}

// ---------------------------------------------------------------------------
// Security hardening
// ---------------------------------------------------------------------------

const SECRET_PATTERNS: readonly RegExp[] = [
	/(api[_-]?key|secret|token|password|credential|auth)\s*[=:]\s*\S+/gi,
	/bearer\s+\S+/gi,
	/(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{16,}/g,
	/sk-[A-Za-z0-9]{20,}/g,
	/-----BEGIN\s+[A-Z0-9 ]*PRIVATE\s+KEY(\s+BLOCK)?-----[\s\S]*?-----END[\s\S]*?-----/g,
	/(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*\S+/gi,
	/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ASCA|AIPA)[A-Z0-9]{12,}\b/g,
];

export function redact(text: string): string {
	let out = text;
	for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, "[REDACTED]");
	return out;
}

// ---------------------------------------------------------------------------
// Decision-model judge contract
// ---------------------------------------------------------------------------

export const FAIL_AT_ADVISORY = 0.7;
export const PASS_BELOW = 0.3;
export const BLOCK_AT = 0.9;
export const CHUNK_MAX_BYTES = 28_000;

export type Route = "write" | "plan" | "stop";

const SUBJECT_NOUN: Record<Route, string> = {
	write: "code change",
	plan: "implementation plan",
	stop: "work done in this session",
};

export interface DimensionSpec {
	id: string;
	title: string;
	criteria: readonly [string, string, string];
}

export const DIMENSIONS: readonly DimensionSpec[] = [
	{
		id: "correctness",
		title: "correctness",
		criteria: [
			"It contains a defect that produces a wrong result, a crash, data loss, or a security hole on a realistic input.",
			"It works on the main path but mishandles a specific edge case, error path, or boundary value.",
			"No incorrect behavior is visible in it.",
		],
	},
	{
		id: "spec_completion",
		title: "completeness against its stated job, including the request in `request` when that field is present",
		criteria: [
			"A required part is missing, stubbed, or left as a placeholder, so it does not do its stated job.",
			"The main job is done but a named sub-part, caller, test, or document is left unfinished.",
			"Nothing it starts is left unfinished.",
		],
	},
	{
		id: "complexity",
		title: "complexity",
		criteria: [
			"It adds structure that is hard to follow: deep nesting, a long function with many branches, or an abstraction layer with a single use.",
			"It is more involved than the task needs in one specific place, such as an extra parameter, flag, or indirection.",
			"It is as simple as the task allows.",
		],
	},
	{
		id: "slop",
		title: "filler and leftovers",
		criteria: [
			"It contains filler that must not ship: dead or commented-out code, duplicated blocks, generic names such as helper or data, or comments that restate the code.",
			"It contains one or two small leftovers, such as an unused import, a stale comment, or a vague name.",
			"It contains no filler, leftovers, or vague names.",
		],
	},
	{
		id: "concurrency",
		title: "concurrency safety",
		criteria: [
			"It introduces a data race, a deadlock, a lost update, or unbounded concurrent work.",
			"It shares state or orders asynchronous steps in a way that is fragile but not shown to fail.",
			"No concurrency problem is visible in it, or it has no concurrent behavior.",
		],
	},
	{
		id: "performance",
		title: "performance",
		criteria: [
			"It adds work that grows badly with input size or blocks a hot path, such as a nested loop over the same data, a query inside a loop, or blocking I/O in an event loop.",
			"It does avoidable repeated work, allocation, or copying in one specific place.",
			"No avoidable cost is visible in it.",
		],
	},
	{
		id: "design",
		title: "design",
		criteria: [
			"It puts a responsibility in the wrong place, breaks an existing interface contract, or couples parts that change for different reasons.",
			"It works within the structure but leaks an internal detail, duplicates an existing mechanism, or names something misleadingly.",
			"It fits the surrounding structure and its interfaces are clear.",
		],
	},
];

export const UI_DIMENSIONS: readonly DimensionSpec[] = [
	{
		id: "layout",
		title: "layout",
		criteria: [
			"It breaks layout for common screen sizes or content lengths: fixed pixel sizes that overflow, overlapping elements, or content clipped without scrolling.",
			"It uses hardcoded spacing or sizes where relative units or tokens fit, or it misaligns one element.",
			"No layout problem is visible in it.",
		],
	},
	{
		id: "animation",
		title: "animation",
		criteria: [
			"It animates in a way that harms use: it animates layout properties such as width, height, top, or left, ignores reduced-motion preferences, or blocks interaction until it ends.",
			"It uses an inconsistent duration or easing, or it animates every property at once.",
			"No animation problem is visible in it, or it adds no animation.",
		],
	},
	{
		id: "accessibility",
		title: "accessibility",
		criteria: [
			"It makes a control unusable for keyboard or screen-reader users: no accessible name, no focus handling, or a click handler on a non-interactive element.",
			"It misses one accessibility detail, such as alt text, a label association, or visible focus styling.",
			"No accessibility problem is visible in it.",
		],
	},
];

const UI_EXTENSIONS: Record<string, true> = {
	".html": true,
	".htm": true,
	".css": true,
	".scss": true,
	".sass": true,
	".less": true,
	".jsx": true,
	".tsx": true,
	".vue": true,
	".svelte": true,
	".astro": true,
};

export interface ScreenSpec {
	id: string;
	question: NoulQuestion;
}

export const SCREENS: readonly ScreenSpec[] = [
	{
		id: "is_executable_code",
		question: {
			type: "noul",
			instructions: "Is the content in `subject` executable source code?",
			criteria: {
				true: "It is program source code, a script, a query, or a test.",
				false: "It is prose, documentation, configuration, or data.",
			},
		},
	},
	{
		id: "touches_shared_state",
		question: {
			type: "noul",
			instructions:
				"Does the code in `subject` read or write state that more than one thread, task, process, or request can reach at the same time?",
			criteria: {
				true: "It reads or writes such shared state.",
				false: "It uses only local or single-owner state.",
			},
		},
	},
	{
		id: "has_placeholder",
		question: {
			type: "noul",
			instructions:
				"Does the content in `subject` contain a stub, a TODO or FIXME marker, a not-implemented error, or placeholder text standing in for real work?",
			criteria: {
				true: "It contains at least one of those.",
				false: "It contains none of those.",
			},
		},
	},
];

interface BashGuardCategory {
	id: string;
	text: string;
}

const BASH_GUARD_CATEGORIES: readonly BashGuardCategory[] = [
	{
		id: "destroys_outside_workspace",
		text: "destroys or overwrites data outside the working directory (rm/dd/mkfs/chmod-chown sweeps, redirects onto devices)",
	},
	{
		id: "rewrites_shared_history",
		text: "rewrites or force-pushes shared git history (push --force to shared refs, reset --hard + push)",
	},
	{
		id: "pipes_remote_to_shell",
		text: "pipes remote content into a shell (curl|sh, wget|bash) or fetches-and-executes untrusted code",
	},
	{
		id: "exfiltrates_secrets",
		text: "exfiltrates secrets/credentials (reads key material and sends it over the network)",
	},
	{
		id: "escalates_privilege",
		text: "escalates privileges or tampers with system state (sudo destructive ops, writing to /etc, killing arbitrary PIDs)",
	},
];

export const BASH_GUARD_QUESTIONS: Questions = Object.fromEntries(
	BASH_GUARD_CATEGORIES.map(
		(category): [string, NoulQuestion] => [
			category.id,
			{ type: "noul", instructions: `The shell command in \`command\` ${category.text}.` },
		],
	),
);

const LEVEL_NAMES: readonly [string, string, string] = ["material defect", "concrete concern", "no concern"];

function codePointBytes(codePoint: number): number {
	if (codePoint < 0x80) return 1;
	if (codePoint < 0x800) return 2;
	if (codePoint < 0x10000) return 3;
	return 4;
}

function utf8Length(text: string): number {
	let total = 0;
	for (let index = 0; index < text.length; ) {
		const codePoint = text.codePointAt(index) as number;
		total += codePointBytes(codePoint);
		index += codePoint > 0xffff ? 2 : 1;
	}
	return total;
}

export function chunkText(text: string, limit = CHUNK_MAX_BYTES): string[] {
	if (limit < 4) throw new Error(`chunk limit must be at least 4, got ${limit}`);
	const chunks: string[] = [];
	let start = 0;
	let remaining = utf8Length(text);
	while (remaining > limit) {
		let bytes = 0;
		let end = start;
		let newlineIndex = -1;
		let newlineBytes = -1;
		while (end < text.length) {
			const codePoint = text.codePointAt(end) as number;
			const cost = codePointBytes(codePoint);
			if (bytes + cost > limit) break;
			bytes += cost;
			if (codePoint === 0x0a) {
				newlineIndex = end;
				newlineBytes = bytes - 1;
			}
			end += codePoint > 0xffff ? 2 : 1;
		}
		const cutAtNewline = newlineBytes >= 0 && 2 * newlineBytes >= bytes;
		const cut = cutAtNewline ? newlineIndex + 1 : end;
		chunks.push(text.slice(start, cut));
		remaining -= cutAtNewline ? newlineBytes + 1 : bytes;
		start = cut;
	}
	chunks.push(text.slice(start));
	return chunks;
}

function scoreQuestion(subject: string, dimension: DimensionSpec): ScoreQuestion {
	return {
		type: "score",
		instructions: `Rate the ${subject} in \`subject\` on ${dimension.title}.`,
		criteria: dimension.criteria,
	};
}

export function buildQuestions(route: Route, file?: string, completenessJudged = true): Questions {
	const questions: Questions = {};
	const subject = SUBJECT_NOUN[route];
	for (const dimension of DIMENSIONS) {
		if (!completenessJudged && dimension.id === "spec_completion") continue;
		questions[dimension.id] = scoreQuestion(subject, dimension);
	}
	if (route === "write") {
		const name = file ? file.slice(file.lastIndexOf("/") + 1) : "";
		const dot = name.lastIndexOf(".");
		const extension = dot > 0 ? name.slice(dot).toLowerCase() : "";
		if (UI_EXTENSIONS[extension]) {
			for (const dimension of UI_DIMENSIONS) questions[dimension.id] = scoreQuestion(subject, dimension);
		}
		for (const screen of SCREENS) questions[screen.id] = screen.question;
	}
	return questions;
}

type Level = 0 | 1 | 2;

function scoreLevels(answer: Answer): readonly [defect: number, concern: number, clean: number] {
	const probabilities: Record<string, number> = "probabilities" in answer ? answer.probabilities : {};
	return [probabilities["0"] ?? 0, probabilities["1"] ?? 0, probabilities["2"] ?? 0];
}

function noulValue(answer: Answer): number {
	return "noul" in answer ? answer.noul : 0;
}

interface DimensionRow {
	id: string;
	criteria: DimensionSpec["criteria"];
	defect: number;
	likely: Level;
}

const CODE_ONLY_DIMENSIONS: Record<string, true> = {
	correctness: true,
	complexity: true,
	concurrency: true,
	performance: true,
};
const CONCURRENCY_ONLY: Record<string, true> = { concurrency: true };
const NOTHING_DROPPED: Record<string, true> = {};

function droppedDimensions(route: Route, answers: Record<string, Answer>): Record<string, true> {
	if (route !== "write") return NOTHING_DROPPED;
	const executable = answers["is_executable_code"];
	if (executable && noulValue(executable) < 0.5) return CODE_ONLY_DIMENSIONS;
	const shared = answers["touches_shared_state"];
	if (shared && noulValue(shared) < 0.5) return CONCURRENCY_ONLY;
	return NOTHING_DROPPED;
}

function remainingDimensions(route: Route, answers: Record<string, Answer>): DimensionRow[] {
	const dropped = droppedDimensions(route, answers);
	const placeholderAnswer = route === "write" ? answers["has_placeholder"] : undefined;
	const placeholder = placeholderAnswer ? noulValue(placeholderAnswer) : 0;
	const rows: DimensionRow[] = [];
	for (const dimension of [...DIMENSIONS, ...UI_DIMENSIONS]) {
		const answer = answers[dimension.id];
		if (!answer || dropped[dimension.id]) continue;
		const [defect, concern, clean] = scoreLevels(answer);
		rows.push({
			id: dimension.id,
			criteria: dimension.criteria,
			defect: dimension.id === "spec_completion" ? Math.max(defect, placeholder) : defect,
			likely: clean > defect && clean > concern ? 2 : concern > defect ? 1 : 0,
		});
	}
	return rows;
}

export function deriveVerdict(route: Route, answers: Record<string, Answer>): Verdict {
	const rows = remainingDimensions(route, answers);
	const worst = Math.max(0, ...rows.map((row) => row.defect));
	if (worst >= (route === "stop" ? BLOCK_AT : FAIL_AT_ADVISORY)) return "FAIL";
	if (worst < PASS_BELOW && rows.every((row) => row.likely === 2)) return "PASS";
	return "UNCERTAIN";
}

export function combineVerdicts(verdicts: readonly (Verdict | undefined)[]): Verdict | undefined {
	if (verdicts.includes("FAIL")) return "FAIL";
	if (verdicts.includes(undefined)) return undefined;
	return verdicts.every((verdict) => verdict === "PASS") ? "PASS" : "UNCERTAIN";
}

function shownLevel(row: DimensionRow): Level {
	if (row.defect >= 0.5) return 0;
	if (row.defect >= PASS_BELOW && row.likely === 2) return 1;
	return row.likely;
}

export type ChunkResult =
	| { answers: Record<string, Answer>; model: string }
	| { cause: string };

interface ScorecardLine {
	id: string;
	defect: number;
	shown: Level;
	criterion: string;
	part: number;
}

function dimensionLines(
	route: Route,
	results: readonly ChunkResult[],
): { lines: ScorecardLine[]; highest: number } {
	const winners = new Map<string, ScorecardLine>();
	let highest = 0;
	for (let part = 0; part < results.length; part++) {
		const result = results[part];
		if (!("answers" in result)) continue;
		const rows = remainingDimensions(route, result.answers);
		for (const row of rows) highest = Math.max(highest, row.defect);
		for (const row of rows) {
			if (row.defect < PASS_BELOW && row.likely === 2) continue;
			const previous = winners.get(row.id);
			if (previous && row.defect <= previous.defect) continue;
			const shown = shownLevel(row);
			winners.set(row.id, {
				id: row.id,
				defect: row.defect,
				shown,
				criterion: row.criteria[shown],
				part,
			});
		}
	}
	const lines = [...DIMENSIONS, ...UI_DIMENSIONS]
		.map((dimension) => winners.get(dimension.id))
		.filter((line): line is ScorecardLine => line !== undefined)
		.sort((a, b) => b.defect - a.defect);
	return { lines, highest };
}

function completenessLine(total: number): string {
	return total > 1
		? `Completeness was not judged: the subject was split into ${total} parts.`
		: "Completeness was not judged: the request does not fit in one part with the subject.";
}

function partsNotJudgedLine(results: readonly ChunkResult[]): string | undefined {
	const failures = results.filter(
		(result): result is { cause: string } => "cause" in result,
	);
	if (failures.length === 0) return undefined;
	return `Parts not judged: ${failures.length} of ${results.length} (${failures[0].cause}).`;
}

function judgedModels(results: readonly ChunkResult[]): string[] {
	const models: string[] = [];
	for (const result of results) {
		if (!("model" in result)) continue;
		if (!models.includes(result.model)) models.push(result.model);
	}
	return models;
}

export function renderScorecard(
	route: Route,
	results: readonly ChunkResult[],
	completenessJudged: boolean,
): string {
	const total = results.length;
	if (completenessJudged && total > 1) {
		throw new Error("completeness is judged only with one chunk");
	}
	const { lines: dimensions, highest } = dimensionLines(route, results);
	const lines: string[] = [];
	if (dimensions.length === 0) {
		lines.push(`No dimension shows a material defect (highest P(defect)=${highest.toFixed(2)}).`);
	}
	for (const line of dimensions) {
		const suffix = total > 1 ? ` (part ${line.part + 1} of ${total})` : "";
		lines.push(
			`- ${line.id}: ${LEVEL_NAMES[line.shown]} (P(defect)=${line.defect.toFixed(2)}) ${line.criterion}${suffix}`,
		);
	}
	if (!completenessJudged) lines.push(completenessLine(total));
	const parts = partsNotJudgedLine(results);
	if (parts) lines.push(parts);
	lines.push(`Judged by ${judgedModels(results).join(", ")}.`);
	return lines.join("\n");
}

type JudgeFn = (
	state: Record<string, string>,
	questions: Questions,
	ctx: { modelRegistry: JudgeDeps["registry"] },
	signal: AbortSignal,
) => Promise<JudgmentResult>;

let judgeOverride: JudgeFn | undefined;

/** Test-only: replace the lazy host judge. Restore with testSetJudge(undefined). */
export function testSetJudge(fn: JudgeFn | undefined): void {
	judgeOverride = fn;
}

/** The host judge resolves through a lazy import so this module loads, and the
 * tests run, without the host package on disk. */
export async function invokeJudge(
	state: Record<string, string>,
	questions: Questions,
	ctx: { modelRegistry: JudgeDeps["registry"] },
	signal: AbortSignal,
): Promise<JudgmentResult> {
	const override = judgeOverride;
	if (override) return override(state, questions, ctx, signal);
	const { resolveJudge } = await import("@oh-my-pi/pi-coding-agent/judgment");
	const { settings } = await import("@oh-my-pi/pi-coding-agent");
	return resolveJudge({ settings, registry: ctx.modelRegistry, purpose: "codex-reflector" }).judge(
		{ state, questions },
		{ signal },
	);
}

interface JudgeContext {
	hasUI: boolean;
	ui: { notify(msg: string, level?: "info" | "warning" | "error"): void };
	modelRegistry: JudgeDeps["registry"];
}

function requireAnswers(questions: Questions, answers: Record<string, Answer>): void {
	for (const [id, question] of Object.entries(questions)) {
		const answer = answers[id];
		if (!answer) throw new Error(`judge answer missing for "${id}"`);
		const values =
			question.type === "score"
				? ["0", "1", "2"].map((level) => getProp(getProp(answer, "probabilities"), level))
				: [getProp(answer, "noul")];
		if (!values.every((value) => typeof value === "number" && value >= 0 && value <= 1)) {
			throw new Error(`judge answer for "${id}" is malformed`);
		}
	}
}

const JUDGE_MAX_IN_FLIGHT = 8;

type ChunkOutcome = { result: JudgmentResult } | { cause: string };

async function judgeChunk(
	ctx: JudgeContext,
	state: Record<string, string>,
	questions: Questions,
	signal: AbortSignal,
): Promise<ChunkOutcome> {
	try {
		signal.throwIfAborted();
		const result = await invokeJudge(state, questions, ctx, signal);
		requireAnswers(questions, result.answers);
		return { result };
	} catch (err) {
		return { cause: err instanceof Error ? err.message : String(err) };
	}
}

async function judgeChunks(
	ctx: JudgeContext,
	states: readonly Record<string, string>[],
	questions: Questions,
	signal: AbortSignal,
): Promise<ChunkOutcome[]> {
	const outcomes: ChunkOutcome[] = [];
	let next = 0;
	const worker = async (): Promise<void> => {
		while (next < states.length) {
			const index = next++;
			outcomes[index] = await judgeChunk(ctx, states[index], questions, signal);
		}
	};
	const workers = Math.min(JUDGE_MAX_IN_FLIGHT, states.length);
	await Promise.all(Array.from({ length: workers }, worker));
	return outcomes;
}

async function judgeRoute(
	route: Route,
	ctx: JudgeContext,
	states: readonly Record<string, string>[],
	questions: Questions,
	completenessJudged: boolean,
	signal: AbortSignal,
): Promise<{ verdict: Verdict; scorecard: string } | undefined> {
	const outcomes = await judgeChunks(ctx, states, questions, signal);
	const results: ChunkResult[] = outcomes.map((outcome) =>
		"result" in outcome
			? { answers: outcome.result.answers, model: outcome.result.model }
			: { cause: outcome.cause },
	);
	const verdict = combineVerdicts(
		outcomes.map((outcome) =>
			"result" in outcome ? deriveVerdict(route, outcome.result.answers) : undefined,
		),
	);
	if (!verdict) {
		const failed = outcomes.find(
			(outcome): outcome is { cause: string } => "cause" in outcome,
		);
		if (failed) notifyUI(ctx, `review skipped: ${failed.cause}`, "warning");
		return undefined;
	}
	return { verdict, scorecard: renderScorecard(route, results, completenessJudged) };
}

function partStates(
	chunks: readonly string[],
	key: "subject" | "command",
	before: Record<string, string>,
	after: Record<string, string>,
): Record<string, string>[] {
	return chunks.map((chunk, index) => {
		const state: Record<string, string> = { ...before, [key]: chunk, ...after };
		if (chunks.length > 1) state.part = `${index + 1} of ${chunks.length}`;
		return state;
	});
}

// ---------------------------------------------------------------------------
// Tool routing — oh-my-pi native tool names
// ---------------------------------------------------------------------------

const CODE_CHANGE_TOOLS: Record<string, true> = {
	write: true,
	edit: true,
	ast_edit: true,
	fast_edit: true,
};
// Explicit edit-function marker only: bare Morph server markers would route
// non-edit Morph tools (fastcompact, warpgrep) into code-change review.
const MCP_EDIT_MARKERS = ["__edit_file"];

/** True when a tool result is a code change worth the write review: the native
 * mutators, or an MCP tool whose name carries the edit-function marker. */
export function isCodeChangeTool(toolName: string): boolean {
	return (
		Object.hasOwn(CODE_CHANGE_TOOLS, toolName) ||
		(toolName.startsWith("mcp__") && MCP_EDIT_MARKERS.some((marker) => toolName.includes(marker)))
	);
}

// A workspace file path never carries a URI scheme; a scheme means the write
// targets a device or internal location, not a source file to review.
const URI_SCHEME_RE = /^([a-z][a-z0-9+.-]*):\/\//i;

/**
 * Mounted `xd://` tools execute through the outer `write` transport. The
 * completed result carries the canonical inner dispatch in `details.xdev`;
 * retain its tool name, validated arguments, and result details so every
 * existing route sees the same shape as a direct tool call.
 *
 * A missing dispatch is a legacy or plain write. The URL fallback only exists
 * for older hosts that do not attach `details.xdev`.
 */
interface ReviewEvent {
	toolName: string;
	input: Record<string, unknown>;
	content: ToolResultEvent["content"];
	isError: boolean;
	details?: unknown;
}

function isXdevDispatch(value: unknown): value is {
	tool: string;
	mode: "help" | "execute";
	args?: Record<string, unknown>;
	inner?: unknown;
} {
	const tool = getProp(value, "tool");
	const mode = getProp(value, "mode");
	const args = getProp(value, "args");
	return (
		typeof tool === "string" &&
		tool.length > 0 &&
		(mode === "help" || mode === "execute") &&
		(args === undefined || (args !== null && typeof args === "object" && !Array.isArray(args)))
	);
}

export function resolveDeviceWrite(event: ToolResultEvent): ReviewEvent | null {
	if (event.toolName !== "write") return event;

	const xdev = getProp(event.details, "xdev");
	if (xdev !== undefined) {
		if (!isXdevDispatch(xdev) || xdev.mode !== "execute") return null;
		return {
			...event,
			toolName: xdev.tool,
			input: xdev.args ?? {},
			details: xdev.inner,
		};
	}

	const path = typeof event.input.path === "string" ? event.input.path : "";
	const scheme = path.match(URI_SCHEME_RE)?.[1];
	if (!scheme) return event;
	if (event.isError || scheme !== "xd") return null;
	const device = path.slice("xd://".length);
	let input: Record<string, unknown> = {};
	const rawArgs = event.input.content;
	if (typeof rawArgs === "string") {
		try {
			const parsed: unknown = JSON.parse(rawArgs);
			if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed))
				input = parsed as Record<string, unknown>;
		} catch {
			/* legacy unparseable args: retain the tool name and empty arguments */
		}
	}
	return { ...event, toolName: device, input };
}

// ---------------------------------------------------------------------------
// Handler deadline
// ---------------------------------------------------------------------------

/** Per-handler deadline: an AbortController that aborts after `budgetMs`
 * (default = the test-settable handlerBudgetMs, under oh-my-pi's 30s handler
 * cap), optionally chained to an upstream signal (aborts if either fires).
 * Caller MUST call clear() in finally to cancel the timer and detach the
 * upstream listener. */
export interface HandlerDeadline {
	signal: AbortSignal;
	clear: () => void;
}

export function handlerDeadline(
	upstream?: AbortSignal,
	budgetMs = handlerBudgetMs,
): HandlerDeadline {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), budgetMs);
	const onUpstream = (): void => controller.abort();
	if (upstream) {
		if (upstream.aborted) controller.abort();
		else upstream.addEventListener("abort", onUpstream, { once: true });
	}
	return {
		signal: controller.signal,
		clear: (): void => {
			clearTimeout(timer);
			if (upstream) upstream.removeEventListener("abort", onUpstream);
		},
	};
}

// ---------------------------------------------------------------------------
// Content extraction (oh-my-pi tool_result / message shapes -> text)
// ---------------------------------------------------------------------------

function partText(part: unknown): string {
	if (typeof part === "string") return part;
	if (part === null || typeof part !== "object") return "";
	if (getProp(part, "type") === "image") return "";
	const text = getProp(part, "text");
	if (typeof text === "string") return text;
	const inner = getProp(part, "content");
	if (typeof inner === "string") return inner;
	if (Array.isArray(inner)) return inner.map((p) => partText(p)).join("");
	const output = getProp(part, "output");
	if (typeof output === "string") return output;
	return "";
}

function textOf(content: unknown): string {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.map((c) => partText(c))
		.filter((s) => s.length > 0)
		.join("\n");
}

export function renderTranscript(messages: readonly unknown[]): string {
	const blocks: string[] = [];
	for (const message of messages) {
		const roleValue = getProp(message, "role");
		const role = typeof roleValue === "string" ? roleValue : "?";
		const body = textOf(getProp(message, "content"));
		if (!body.trim()) continue;
		blocks.push(`[${role}] ${body}`);
	}
	return blocks.join("\n\n");
}

/** Resolve the review target (display path, state keys, raw snippet) from a code-change result. Sync, pure. */
export function resolveChangeTarget(event: ReviewEvent): {
	filePath: string;
	filePaths: string[];
	rawSnippet: string;
} {
	const input = event.input;
	const details = getProp(event, "details");
	let filePath = "unknown";
	let filePaths: string[] = [];
	let rawSnippet = "";
	if (event.toolName === "write") {
		filePath = typeof input.path === "string" ? input.path : "unknown";
		filePaths = [filePath];
		rawSnippet = typeof input.content === "string" ? input.content : "";
	} else if (event.toolName === "ast_edit") {
		const paths = Array.isArray(input.paths)
			? [...new Set(input.paths.filter((p): p is string => typeof p === "string"))]
			: [];
		filePaths = paths.length > 0 ? paths : ["unknown"];
		filePath = paths.join(", ") || "unknown";
		rawSnippet = textOf(event.content);
	} else if (event.toolName === "edit") {
		// EditToolDetails carries `path` + unified `diff` across every edit mode;
		// `input.input` exists only in hashline mode, so prefer details first.
		const detailPath = getProp(details, "path");
		const detailDiff = getProp(details, "diff");
		if (typeof detailPath === "string" && detailPath) {
			filePath = detailPath;
		} else {
			const patch = typeof input.input === "string" ? input.input : "";
			const match = patch.match(/^\[([^\]#]+)#/m);
			filePath = match ? match[1] : "unknown";
		}
		filePaths = [filePath];
		rawSnippet =
			typeof detailDiff === "string" && detailDiff ? detailDiff : textOf(event.content);
	} else {
		// MCP edit-marker or native fast_edit success: review the edit sketch, not just the status message.
		filePath = pickString(input, ["path", "file_path", "target_filepath"], "unknown");
		filePaths = [filePath];
		const codeEdit = typeof input.code_edit === "string" ? input.code_edit : "";
		const instruction = pickString(input, ["instruction", "instructions"], "");
		const payload = [
			instruction ? `Instruction: ${instruction}` : "",
			codeEdit ? `--- sketch ---\n${codeEdit}` : "",
		]
			.filter(Boolean)
			.join("\n\n");
		const content = textOf(event.content);
		rawSnippet = payload ? (content ? `${payload}\n\n--- result ---\n${content}` : payload) : content;
	}
	if (!rawSnippet) rawSnippet = JSON.stringify(input, null, 2);
	return { filePath, filePaths, rawSnippet };
}

// ---------------------------------------------------------------------------
// Review response builder
// ---------------------------------------------------------------------------

/** Build the tool_result result for an advisory code-change review. The verdict
 * + opinion ride along as a content override and the result never sets isError,
 * so a succeeded edit is never blocked. Holistic Stop remains the only post-hoc
 * blocking gate; bashGuardDecision governs the separate pre-execution bash gate. */
export function codeReviewResponse(
	verdict: Verdict,
	filePath: string,
	out: string,
	baseContent: ToolResultEvent["content"],
): ToolResultEventResult {
	const result: ToolResultEventResult = {
		content: [
			...baseContent,
			{ type: "text" as const, text: `Reflector Review ${VERDICT_PREFIX[verdict]} [${filePath}]:\n${out}` },
		],
	};
	return result;
}

/** Map a holistic Stop-review verdict to its settle decision: only a definitive
 * FAIL blocks the stop (fail-closed) with the review as the continuation reason
 * (Claude/Codex-compatible `decision` shape, matching the Python plugin). PASS
 * and UNCERTAIN settle (fail-open — never block on uncertainty). */
export function stopReviewDecision(
	verdict: Verdict,
	out: string,
): { decision: "block"; reason: string } | undefined {
	if (verdict !== "FAIL") return undefined;
	return { decision: "block", reason: `Reflector Stop Review FAIL:\n${out}` };
}

/** Map the bash pre-guard's largest yes-probability to its gate decision: only a
 * maximum at or above BLOCK_AT blocks the command before execution; anything
 * lower lets it run (fail-open: never block on uncertainty or infra failure). */
export function bashGuardDecision(
	maxProbability: number,
	categoryText: string,
	model: string,
): { block: true; reason: string } | undefined {
	if (maxProbability < BLOCK_AT) return undefined;
	return {
		block: true,
		reason: `Blocked by decision model: the command ${categoryText} (P=${maxProbability.toFixed(2)}). Judged by ${model}.`,
	};
}

// Coarse risk signals that warrant a judge adjudication. This is a COST gate,
// not a security boundary: quoted/echoed text over-triggers (the judge then
// adjudicates) and misses run unreviewed — the guard's documented fail-open
// posture. Minimal and generous by design: routine dev commands never pay
// the judge round-trip. Taxonomy mirrors BASH_GUARD_CATEGORIES: extend both
// together.
const BASH_GUARD_TRIGGERS: ReadonlyArray<RegExp> = [
	// deletion reaching outside the workspace: rm/rip touching /, ~, $HOME, or ..
	/\b(rm|rip)\b[^\n;|&]*(\s\/|~|\$\{?HOME|\.\.)/,
	// raw-device / filesystem destruction
	/\b(dd|mkfs\S*|shred|wipefs)\b/,
	// untracked-purge and find -delete sweeps
	/\bgit\s+clean\b|\bfind\b[^\n]*-delete\b/,
	// shared-history rewrite / force push
	/\bpush\b[^\n]*(--force|\s-\w*f\w*\b)|\breset\s+--hard\b|\bfilter-branch\b/,
	// remote content piped into a shell
	/\b(curl|wget)\b[^\n|]*\|[^\n]*\b(ba|z|da)?sh\b/,
	// privilege escalation / system-path writes (benign /dev/null-family
	// redirect targets stay free — they are the pervasive shell idiom)
	/\bsudo\b|\btee\b[^\n]*\s\/etc\/|>>?\s*\/(etc|boot)\/|>>?\s*\/dev\/(?!(?:null|stdout|stderr|zero|tty)\b)/,
	// machine state + arbitrary process kills (bare `kill` stays free)
	/\b(shutdown|reboot|halt|poweroff|pkill|killall)\b/,
	// key material named together with a network sender
	/(\.ssh\b|id_rsa|id_ed25519|\.aws\b|credentials)[^\n]*\b(curl|wget|nc|ncat|scp|rsync)\b|\b(curl|wget|nc|ncat|scp|rsync)\b[^\n]*(\.ssh\b|id_rsa|id_ed25519|\.aws\b|credentials)/,
];

// Bound the regex work: unbounded-span alternations go quadratic on
// multi-token single-line input — synchronous CPU no deadline can interrupt.
// Measured worst case at 4096 chars is ~10ms (key-material trigger) after
// pinning the curl|sh trigger's first span to [^\n|]* (was ~900ms with two
// unbounded spans). Oversized commands skip the prescreen and go straight to
// the judge (the pre-prescreen baseline cost), so no bypass opens.
const PRESCREEN_MAX_SCAN = 4096;

/** True when the command matches a coarse risk signal worth a judge adjudication. */
export function bashGuardPrescreen(command: string): boolean {
	if (command.length > PRESCREEN_MAX_SCAN) return true;
	return BASH_GUARD_TRIGGERS.some((re) => re.test(command));
}

const VERDICT_PREFIX: Record<Verdict, string> = {
	FAIL: "\u26a0\ufe0f FAIL",
	PASS: "\u2713 PASS",
	UNCERTAIN: "? UNCERTAIN",
};

export function isBashGuardEnabled(pi: ExtensionAPI): boolean {
	if (process.env.CODEX_REFLECTOR_BASH_GUARD === "1") return true;
	if (process.env.CODEX_REFLECTOR_BASH_GUARD === "0") return false;
	const flag = pi.getFlag("codex-bash-guard");
	return flag === true || flag === "1" || flag === "true";
}

export function isStopReviewEnabled(pi: ExtensionAPI): boolean {
	if (process.env.CODEX_REFLECTOR_STOP_REVIEW === "1") return true;
	if (process.env.CODEX_REFLECTOR_STOP_REVIEW === "0") return false;
	const flag = pi.getFlag("codex-stop-review");
	return flag === true || flag === "1" || flag === "true";
}

// ---------------------------------------------------------------------------
// Hook factory
// ---------------------------------------------------------------------------

export default function codexReflector(pi: ExtensionAPI): void {
	if (process.env.CODEX_REFLECTOR_ENABLED === "0") return;
	logger = pi.logger;
	pi.registerFlag("codex-bash-guard", {
		description: "Enable pre-execution bash safety guard (opt-in)",
		type: "boolean",
		default: false,
	});

	pi.registerFlag("codex-stop-review", {
		description: "Enable holistic stop reflection gate (opt-in)",
		type: "boolean",
		default: false,
	});


	// Advisory write review on each tool result (success path only).
	pi.on("tool_result", async (event, ctx) => {
		let deadline: HandlerDeadline | undefined;
		try {
			const ev = resolveDeviceWrite(event);
			if (!ev) return undefined;
			if (ev.isError || !isCodeChangeTool(ev.toolName)) return undefined;
			const { filePath, rawSnippet } = resolveChangeTarget(ev);
			const subject = redact(rawSnippet);
			const request = pickString(ev.input, ["instruction", "instructions"], "");
			const requestText = request ? redact(request) : "";
			const fitsTogether = utf8Length(subject) + utf8Length(requestText) <= CHUNK_MAX_BYTES;
			const chunks = fitsTogether ? [subject] : chunkText(subject);
			const requestState: Record<string, string> = fitsTogether && requestText ? { request: requestText } : {};
			const states = partStates(chunks, "subject", { file: redact(filePath) }, requestState);
			const questions = buildQuestions("write", filePath, fitsTogether);
			deadline = handlerDeadline();
			const judged = await judgeRoute("write", ctx, states, questions, fitsTogether, deadline.signal);
			if (!judged) return undefined;
			notifyUI(ctx, `Reflector Review ${judged.verdict} [${filePath}]`, judged.verdict === "FAIL" ? "warning" : "info");
			return codeReviewResponse(judged.verdict, filePath, judged.scorecard, ev.content);
		} catch (err) {
			debug(`tool_result handler error: ${String(err)}`);
			return undefined; // fail-open
		} finally {
			deadline?.clear();
		}
	});
	pi.on("tool_call", async (event, ctx) => {
		let deadline: HandlerDeadline | undefined;
		try {
			if (!isBashGuardEnabled(pi)) return undefined;
			if (getProp(event, "toolName") !== "bash") return undefined;
			const input = getProp(event, "input");
			const command = getProp(input, "command");
			if (typeof command !== "string" || !command) return undefined;
			if (!bashGuardPrescreen(command)) return undefined; // benign: zero judge cost
			const cwd = ctx.cwd || process.cwd();
			const states = partStates(chunkText(redact(command)), "command", {}, { cwd: redact(cwd) });
			deadline = handlerDeadline();
			const outcomes = await judgeChunks(ctx, states, BASH_GUARD_QUESTIONS, deadline.signal);
			let worstId = "";
			let worstText = "";
			let worst = -1;
			let worstModel = "";
			for (const outcome of outcomes) {
				if (!("result" in outcome)) continue;
				for (const category of BASH_GUARD_CATEGORIES) {
					const value = noulValue(outcome.result.answers[category.id]);
					if (value > worst) {
						worst = value;
						worstId = category.id;
						worstText = category.text;
						worstModel = outcome.result.model;
					}
				}
			}
			if (worst >= BLOCK_AT) {
				debug(`bash guard worst ${worstId} P=${worst.toFixed(2)} by ${worstModel}`);
				notifyUI(ctx, "Reflector Bash Guard FAIL: command blocked.", "warning");
				return bashGuardDecision(worst, worstText, worstModel);
			}
			const failed = outcomes.find(
				(outcome): outcome is { cause: string } => "cause" in outcome,
			);
			if (failed) notifyUI(ctx, `review skipped: ${failed.cause}`, "warning");
			return undefined;
		} catch (err) {
			debug(`tool_call guard error: ${String(err)}`);
			return undefined;
		} finally {
			deadline?.clear();
		}
	});

	// session_stop (omp 16.0.5, #2834): main-session-only Stop analog, awaited
	// before the turn settles, bounded by omp's built-in 8-continuation cap.
	pi.on("session_stop", async (event, ctx) => {
		let deadline: HandlerDeadline | undefined;
		try {
			if (!isStopReviewEnabled(pi)) return undefined;
			if (getProp(event, "stop_hook_active") === true) return undefined;
			// Claude-Code parity for aborted-tail settles (its Stop hook never fires on
			// user interrupt). omp >=16.x suppresses these emissions itself; this keeps
			// the contract explicit if that drifts. The Esc-after-message_end race emits
			// stopReason "stop" with no abort signal — upstream issue, not observable here.
			if (settledStopReason(event) === "aborted") return undefined;
			const lastMessage = getProp(event, "last_assistant_message");
			const lastText = textOf(getProp(lastMessage, "content"));
			const messages = getProp(event, "messages");
			const subject = lastText || renderTranscript(Array.isArray(messages) ? messages : []);
			if (!subject) return undefined;
			const chunks = chunkText(redact(subject));
			const states = partStates(chunks, "subject", {}, {});
			const oneChunk = chunks.length === 1;
			const questions = buildQuestions("stop", undefined, oneChunk);
			deadline = handlerDeadline();
			const judged = await judgeRoute("stop", ctx, states, questions, oneChunk, deadline.signal);
			if (!judged) return undefined;
			// PASS / UNCERTAIN settle; only a FAIL blocks. Settle SILENTLY: surfacing the
			// verdict via pi.sendMessage re-enters the conversation (even with triggerTurn:false),
			// so the agent takes a turn on it, re-stops, and this holistic review re-runs —
			// looping the Stop on every PASS up to the harness continuation cap. Use a
			// non-conversation UI notice and return undefined so the stop actually settles.
			const decision = stopReviewDecision(judged.verdict, judged.scorecard);
			if (!decision) {
				notifyUI(ctx, `Reflector Stop Review ${judged.verdict}.`, "info");
				return undefined;
			}
			notifyUI(ctx, `Reflector Stop Review ${judged.verdict} — continuing.`, "warning");
			return decision;
		} catch (err) {
			debug(`session_stop handler error: ${String(err)}`);
			return undefined;
		} finally {
			deadline?.clear();
		}
	});
}
