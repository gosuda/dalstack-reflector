# Codex Reflector Agent Notes

This file is only for repo-specific constraints that are easy to break and expensive to rediscover. README owns installation and user-facing usage; do not duplicate it here.

## Surface split

- **Rule:** Treat the repository as two hook surfaces, not one implementation. The Claude/Cursor plugin is `scripts/codex-reflector.py` wired by `hooks/hooks.json`; the oh-my-pi port is `omp/codex-reflector.ts` loaded through `package.json` `omp.extensions`.
  **Why:** Both surfaces call the decision-model judge on every route and expose the same reflector idea, but their hook delivery and stop-enforcement mechanisms differ. Editing the wrong surface fixes nothing.

- **Rule:** For shared behavior changes, check both surfaces before declaring parity: the frozen judge contract (question wording, thresholds, state shapes, scorecard text, notice text), redaction, stop-review enforcement, and changed-file target resolution.
  **Why:** The TypeScript file is a native port of the Python hook, while the OMP tests codify port-specific contracts. Silent drift produces different review outcomes for Claude/Cursor vs OMP users.

- **Rule:** Any shipped OMP or Claude plugin code/config change bumps the paired release manifests in the same commit: the OMP version (`package.json` `version`) and the Claude plugin version in all three Claude fields (`.claude-plugin/plugin.json` `version`, plus both `version` and `plugins[0].version` in `.claude-plugin/marketplace.json`); also refresh any marketplace `metadata.lastUpdated` date present. Shared Python hook changes also bump the Cursor plugin version in all three Cursor fields (`.cursor-plugin/plugin.json` `version`, plus both `version` and `plugins[0].version` in `.cursor-plugin/marketplace.json`).
  **Why:** The OMP and Claude surfaces ship independently but evolve together, so bumping only one side hides paired release changes from users inspecting either manifest. The Python hook code also powers Cursor; Cursor manifests are tracked source, but they should move when the shared Python/Cursor surface changes rather than on OMP-only changes.

## Python Claude/Cursor plugin invariants

- **Rule:** Keep `hooks/hooks.json` as routing glue and keep real classification in `classify()` inside `scripts/codex-reflector.py`; `classify()` returns only a category. Cursor-specific matcher generation belongs in `scripts/install-cursor.sh`, not in the core dispatch path.
  **Why:** Claude and Cursor expose different hook payloads and matcher behavior. A duplicated routing table becomes a drift source; the Python script normalizes payloads and owns the routing decision.

- **Rule:** Python blocking is exit-code based. Advisory reviews exit `0` with JSON; Stop blocks by returning `decision: "block"`/`_exit: 2`, which `main()` emits on stderr before exiting `2`.
  **Why:** Claude consumes exit `2` stderr as blocking context. Treating Stop like PostToolUse JSON feedback either fails schema validation or silently approves work that should block.

- **Rule:** `hookSpecificOutput` is only for `PostToolUse`, the one remaining event whose schema accepts it. Stop must use `systemMessage` or `decision`/`reason`.
  **Why:** Stop rejects `hookSpecificOutput`; putting it there breaks the hook response instead of injecting useful context.

- **Rule:** Compute the verdict in code from the judge's per-question probabilities. NEVER parse a verdict from model text. No route calls Codex.
  **Why:** The judge returns probabilities and the verdict rule is arithmetic on them. A text parse reintroduces the deleted verdict parser, and a buried or rewritten verdict line would silently change fail-open/fail-closed behavior.

- **Rule:** The Python plugin is stateless: no `.json` FAIL cache and no `fcntl` state file. `respond_code_review`/`respond_plan_review` inject the verdict and scorecard inline as `systemMessage` (every verdict), adding `hookSpecificOutput.additionalContext` for FAIL/UNCERTAIN. `respond_stop` is a fresh judge review run once per stop chain: only a FAIL blocks (`decision: "block"`/`_exit: 2`); PASS and UNCERTAIN settle via `systemMessage` (fail-open, never block on uncertainty), and the retained `stop_hook_active` guard settles a re-stop.
  **Why:** Per-tool reviews self-correct inline; the holistic Stop review is the gate. Python has no continuation cap, so `stop_hook_active` is the only safe loop bound: re-reviewing every stop without it could never settle.

- **Rule:** Keep Cursor payload adaptation contained in `_normalize_cursor_input()` and generated settings from `scripts/install-cursor.sh`. That normalizer also synthesizes `stop_hook_active` from Cursor's `loop_count` (`loop_count > 0`), the only Stop loop bound on Cursor.
  **Why:** Cursor compatibility maps event names and fields into Claude-shaped hook data. Scattering Cursor field handling through responders makes every future hook change harder to audit. Cursor's Stop payload has no native `stop_hook_active`, so without the synthesis `respond_stop`'s guard never fires and the holistic Stop review re-blocks on every continuation: an infinite Stop loop.

## OMP native extension invariants

- **Rule:** The OMP surface is a default-export hook factory. `CODEX_REFLECTOR_ENABLED=0` must register no handlers.
  **Why:** OMP loads the extension through the manifest/factory contract; the kill switch must be safe even when the package is present.

- **Rule:** On successful `tool_result` code-change reviews, return a `content` override carrying the verdict and scorecard for every verdict, advisory only; NEVER set `isError`. The per-tool review never blocks the edit. An error result is never reviewed and never overridden; the original failed tool call already reports the failure.
  **Why:** A per-tool `isError: true` would rethrow a *succeeded* edit (its side effect already applied) as a failed tool call, misleading the agent about state; code-change reviews are advice, not gates. Overriding a genuine error result would corrupt the harness error path.

- **Rule:** The OMP bash pre-guard (`tool_call`) is OMP-only and opt-in (disabled by default): registered via `pi.registerFlag("codex-bash-guard", { type: "boolean", default: false })` and enabled when `CODEX_REFLECTOR_BASH_GUARD=1` or the flag is set to true (`CODEX_REFLECTOR_BASH_GUARD=0` explicitly disables). When enabled, bash commands matching the local risk prescreen (`bashGuardPrescreen`) are judged before execution by five yes/no questions that mirror `BASH_GUARD_TRIGGERS` one to one; extend `BASH_GUARD_TRIGGERS` and the question set together. The guard blocks when the largest answer probability reaches 0.9 (`BLOCK_AT`) and returns `{ block: true, reason }`; every lower answer lets the command run. The prescreen stays the cost gate, not a security boundary; non-matching commands run without review. Judge errors and deadline expiry let the command run and emit the `review skipped: <cause>` notice.
  **Why:** A pre-execution gate that fails closed bricks every shell command during a judge outage; the prescreen keeps cost minimal for default OMP users and keeps review traffic proportional to risk. The Python plugin has no PreToolUse wiring, so this is a deliberate, documented surface difference, not drift.

- **Rule:** The OMP extension is stateless: no `FailTracker`, no `appendEntry` FAIL entries, no `session_start` replay. Statelessness is the parity contract with the Python plugin: per-tool reviews carry no cross-call memory (see the per-tool advisory rule above), so holistic Stop is the only post-hoc review that blocks.
  **Why:** Statelessness keeps the two surfaces' per-tool model identical; the Stop enforcement split (OMP `{ decision: "block", reason }` vs Python exit `2`) remains post-hoc and holistic, while OMP's separate bash guard can block only before command execution.

- **Rule:** The OMP Stop gate (`session_stop`) is opt-in (disabled by default on OMP): registered via `pi.registerFlag("codex-stop-review", { type: "boolean", default: false })` and enabled when `CODEX_REFLECTOR_STOP_REVIEW=1` or the flag is set to true (`CODEX_REFLECTOR_STOP_REVIEW=0` explicitly disables). When enabled, it runs a fresh judge review on the native `session_stop` event (main-session-only, awaited before settle), centralized in the pure `stopReviewDecision` helper: only a FAIL blocks (worst defect probability at 0.9 or above) and returns `{ decision: "block", reason }` (matching the Python plugin); PASS and UNCERTAIN settle (fail-open, never block on uncertainty). Settle SILENTLY: return `undefined` and inject NO conversation message, because surfacing the verdict via `pi.sendMessage` (even with `triggerTurn:false`) re-enters the conversation, so the agent takes a turn on it and re-stops, looping the Stop on every PASS; use `notifyUI` for a non-conversation notice. Guard re-stops with the harness-provided `stop_hook_active` flag: when `event.stop_hook_active` is true, settle immediately (`return undefined`) WITHOUT re-reviewing, mirroring the Python plugin's `respond_stop`. This runs the judge review ONCE per stop chain: it blocks once on FAIL, and the agent's re-stop settles. The flag is harness-owned and reset per stop chain (`#resetSessionStopContinuationState`), so it is NOT port-side state; oh-my-pi's built-in 8-continuation cap remains the backstop.
  An aborted-tail settle (`last_assistant_message.stopReason === "aborted"`, falling back to the messages tail) settles immediately without review, mirroring Claude Code's Stop-on-interrupt semantics; omp itself suppresses these events at current versions, so the guard is cross-version contract insurance.
  **Why:** `session_stop` (omp 16.0.5, #2834) is the main-agent Stop analog; `agent_end` also fires for subagent sessions and its return value is ignored. The `stop_hook_active` guard reads a harness-provided flag (not a port-side counter), so OMP matches the Python plugin's once-per-stop-chain semantics when active: a FAIL blocks once, then the re-stop settles, the same accepted tradeoff on both surfaces. Making Stop review opt-in on OMP is a documented surface difference (Python plugin defaults to on).

- **Rule:** Every judge call inside an OMP handler MUST receive the shared per-handler `handlerDeadline()` signal (`HANDLER_BUDGET_MS`, kept under oh-my-pi's fixed 30s `EXTENSION_HANDLER_TIMEOUT_MS`), with `deadline.clear()` in a `finally`. The judge call takes that signal as its only cancellation source and MUST NOT start a second timer.
  **Why:** The harness caps a handler at 30s via `Promise.race` without aborting it, so a hung judge request outlives the cap and the review is dropped (the `handler timed out after 30000ms` failure mode). The shared deadline aborts the request and fails the handler open before the cap. OMP-only: the Python plugin runs as its own process under Claude-hook timeouts of 240s or more, above its bound of three 10s request attempts, so no 30s race exists there.

## Decision-model invariants

- **Rule:** The shared judge contract (question ids, instruction templates, criteria wording, thresholds, state shapes, scorecard text, notice text) is frozen and identical on both surfaces. A wording or threshold change lands on both surfaces in one commit. The `cross-surface judge contract` test in `omp/codex-reflector.test.ts` runs the Python surface and compares its questions, thresholds, verdicts, and scorecards with the OMP surface; keep it green and extend its cases with the contract.
  **Why:** Both surfaces review the same changes. A wording or threshold drift makes PASS depend on which harness the user runs.

- **Rule:** No route (write review, plan review, Stop gate, bash guard) spawns a process or calls a text-generating model, including for compaction. The decision-model judge is the only reviewer, and there is no fallback reviewer.
  **Why:** A hidden fallback reviewer doubles latency on the judge path and makes the threshold behavior unverifiable.

- **Rule:** A judge failure NEVER blocks. Every judge failure emits exactly one notice, `review skipped: <cause>`, and the route proceeds unreviewed.
  **Why:** Reviews are advice or single gates, never availability-critical paths. A review outage must not brick the agent, and a silent skip would hide the gap from the user.

- **Rule:** On both surfaces, a judge number is valid only when it is a real number from 0 to 1 inclusive; any other value makes the answer malformed, and the review is skipped.
  **Why:** A value above 1 would cross the 0.9 block threshold and force a block from bad data.

- **Rule:** The Python surface reads judge credentials and endpoint only from the process environment (`os.environ`; no file, no `.env`), stays standard library only, refuses redirects, and refuses non-loopback `http` base URLs.
  **Why:** `urllib` follows redirects by default and would resend the bearer token to a redirect target. A non-loopback `http` endpoint ships credentials and review content in cleartext. The stdlib-only floor is the README promise that keeps the plugin pip-free.

- **Rule:** The Python default judge model is the pinned versioned id `jev-1.14.0`. Re-pin it only together with a re-check of the thresholds against the new model.
  **Why:** The thresholds (0.7, 0.3, 0.9) are tuned to the pinned model. A moving alias can change behavior under the same thresholds without anyone noticing.

- **Rule:** The OMP surface reaches the judge only through `resolveJudge` imported lazily from the `@oh-my-pi/pi-coding-agent/judgment` subpath, and tests use the exported `testSetJudge` seam. Re-verify that subpath on every omp upgrade.
  **Why:** The subpath is not a documented extension API, so an upgrade can silently move or drop it. The lazy import keeps the module loadable without the host package; the seam keeps tests off the live judge.

- **Rule:** One question holds one judgment. NEVER merge two dimensions, or a screen and a dimension, into one question; combining happens in code (the verdict rule, the dimension drops, the `max` with `has_placeholder`).
  **Why:** The verdict rule reads per-question probabilities. A combined question makes the drops and the max incomputable and blurs the scorecard line.

## Safety invariants

- **Rule:** Redact secrets before any state leaves the process: every state value passes through redaction before `fitState`. Untrusted tool and transcript data sits only in `state`, and instructions sit only in `questions`; NEVER move subject text into a question.
  **Why:** The reflector reviews arbitrary tool output, diffs, shell errors, and transcripts. The judge receives `state` verbatim, so an unredacted secret leaves the process, and subject text placed in a question becomes instructions.

- **Rule:** Confine attacker-influenced file paths to an allowlist before reading them and forwarding them to the judge: plan paths must pass `_validate_plan_path` (resolved under `~/.claude/plans/`, `.md` suffix, synthetic/traversal rejected); edit targets must pass `_is_safe_edit_path(file_path, cwd)` resolved against the hook-supplied `cwd`, never the reflector process cwd. Any new disk-read site must route through the validator.
  **Why:** `ExitPlanMode` `filePath` and edit `file_path` come from tool payloads an attacker can shape (`/etc/passwd`, `../../` traversal). Without the gate the reflector reads the file and ships it to the judge; resolving against the process cwd instead of the hook cwd silently breaks the confinement.
