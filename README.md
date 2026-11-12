# Outline-Driven Development: Reflector

> Review layer for Outline-Driven Development. Add-on for the Claude Code plugin, with a native oh-my-pi port.

**Methodology**: [outline-driven-development](https://github.com/OutlineDriven/outline-driven-development) &nbsp;·&nbsp; **Claude Code plugin**: [odin-claude-plugin](https://github.com/OutlineDriven/odin-claude-plugin) &nbsp;·&nbsp; **Site**: [outlinedriven.github.io](https://outlinedriven.github.io)

---

Independent critic and oracle for coding agents.

The agent acts. A decision model judges changes, plans, stops, and risky commands. Code changes get a second opinion by default.

## Requirements

- **oh-my-pi (omp)**: a working `judge` model role (`modelRoles.judge`). It answers the review questions.
- **Claude Code plugin (Python)**: `TYPESAFE_API_KEY` in the environment. Python 3.8+, standard library only. The judge calls go to the TypeSafe decision-model API.

The reflector ships in two surfaces; install whichever matches your agent:

- **[Claude Code plugin](#claude-code-plugin)**: the original single-file Python hook. Needs Python 3.8+ (stdlib only, no pip dependencies).
- **[oh-my-pi (omp)](#oh-my-pi-omp)**: a native TypeScript port, no Python runtime. Needs the `omp` CLI.

---

## Claude Code plugin

A single-file Python hook (`scripts/codex-reflector.py`, stdlib only) wired through `hooks/hooks.json`. Requires Python 3.8+ and `TYPESAFE_API_KEY` in the environment.

### Install

```bash
claude plugin marketplace add OutlineDriven/odin-reflector; claude plugin install codex-reflector@odin-reflector
```

### Activation

Place this plugin at `~/.claude/codex-reflector/` and restart Claude Code.

```
~/.claude/codex-reflector/
├── .claude-plugin/plugin.json
├── hooks/hooks.json
├── scripts/codex-reflector.py
├── LICENSE
├── README.md
└── .gitignore
```

### Hook events

| Event | Trigger | Mode | Purpose |
|---|---|---|---|
| PostToolUse | Write, Edit, Fast-Apply MCP edit | async | Decision-model scorecard review (PASS/FAIL/UNCERTAIN) |
| PostToolUse | ExitPlanMode | async | Decision-model plan review, advisory (PASS/FAIL/UNCERTAIN) |
| Stop | Agent finishing | sync | Fresh judge review; blocks on FAIL only (PASS/UNCERTAIN settle) |

### Use with Cursor

Cursor can run this plugin through its Claude Code third-party hooks compatibility layer.

#### Install as a Cursor plugin

This repository includes native Cursor plugin metadata at `.cursor-plugin/plugin.json`.

To install it as a local Cursor plugin, copy or symlink this repository into:

```bash
~/.cursor/plugins/local/codex-reflector
```

Then reload Cursor. The plugin components are auto-discovered from this repository:

- `hooks/hooks.json`
- `rules/codex-reflector-usage.mdc`
- `skills/codex-reflector/SKILL.md`
- `agents/codex-reflector-reviewer.md`
- `commands/install-cursor-plugin.md`

#### Direct-export hooks

1. Enable **Third-party skills** in Cursor Settings.
2. Install the direct-export Claude settings:

```bash
scripts/install-cursor.sh
```

That writes `~/.claude/settings.json` with absolute paths to this checkout. To install into a specific project instead, pass the project path:

```bash
scripts/install-cursor.sh /path/to/project
```

When this repository itself is opened in Cursor, the checked-in `.claude/settings.json` also works directly because Cursor provides `CLAUDE_PROJECT_DIR`.

Cursor compatibility notes:

- `PostToolUse` and `Stop` run through Cursor's Claude hook compatibility.
- Cursor treats Claude `Stop` blocks as follow-up messages, so a blocked Stop review causes the agent to continue with the judge's reason instead of hard-stopping the UI.
- The direct export mirrors the Claude plugin matcher. Cursor only fires the parts whose tool names are exposed through its Claude hook compatibility layer.

---

## oh-my-pi (omp)

A native TypeScript port of this reflector ships at `omp/codex-reflector.ts`, with no Python runtime. It registers oh-my-pi extension handlers that mirror the plugin: a scorecard review on `write`/`edit`/`ast_edit` and Fast-Apply MCP edits, an opt-in Stop gate, and an opt-in bash guard.

### Installation Guide

#### 1. Install the omp CLI

Skip if you already have it ([more options](https://omp.sh)):

```sh
curl -fsSL https://omp.sh/install | sh       # macOS / Linux
bun install -g @oh-my-pi/pi-coding-agent      # any platform, bun >= 1.3.14
```

#### 2. Install the reflector from GitHub (recommended)

Install this repository directly as an oh-my-pi plugin:

```sh
omp plugin install https://github.com/OutlineDriven/odin-reflector
```

The repository's `package.json` declares `omp.extensions: ["./omp/codex-reflector.ts"]`, so omp installs the GitHub package and loads the native extension from that manifest. This is the canonical install path for normal use: no local clone, symlink, or config-file edit is required.

For a named omp profile, run the same command with that profile selected:

```sh
omp --profile <profile> plugin install https://github.com/OutlineDriven/odin-reflector
```

### Behavior

Reads the shared [environment variables](#environment-variables). The `TYPESAFE_*` judge variables are Python-only.

Run the unit tests with `bun test omp/codex-reflector.test.ts`.

**Behavioral delta from the Claude plugin:** both surfaces are stateless. Scorecard reviews inject their verdict inline every time. On OMP, the pre-execution bash guard (`tool_call`) and the Stop gate (`session_stop`) are opt-in and disabled by default; you can toggle them via extension flags (`codex-bash-guard`, `codex-stop-review`) in `/settings` or enable them via env vars (`CODEX_REFLECTOR_BASH_GUARD=1`, `CODEX_REFLECTOR_STOP_REVIEW=1`). The Python Stop gate is always on, and Python has no bash guard. When active, the Stop gate runs a fresh judge review on the native `session_stop` event: only a FAIL blocks (the worst defect probability at 0.9 or above); PASS and UNCERTAIN settle (fail-open, never block on uncertainty). It runs once per stop chain: a FAIL returns `{ decision: "block", reason }` so the agent keeps working with that context, then the harness `stop_hook_active` flag settles the re-stop; the native 8-continuation cap is the backstop.

### Hook events

| omp event | Trigger | Mode | Purpose |
|---|---|---|---|
| `tool_result` | `write` / `edit` / `ast_edit`, Fast-Apply MCP edit | async | Decision-model scorecard review (PASS/FAIL/UNCERTAIN) |
| `tool_call` | `bash`, before execution | sync | Opt-in bash guard; five yes/no answers; blocks at 0.9 |
| `session_stop` | main agent about to settle | sync | Fresh judge review once per stop chain (`stop_hook_active` guard); only FAIL blocks (PASS/UNCERTAIN settle); native 8-continuation cap backstop |

---

## Environment Variables

Both surfaces read `CODEX_REFLECTOR_ENABLED` and `CODEX_REFLECTOR_DEBUG`. The `TYPESAFE_*` variables are Python-only. The two gate variables are OMP-only: the Python Stop gate is always on, and Python has no bash guard.

| Variable | Default | Description |
|---|---|---|
| `CODEX_REFLECTOR_ENABLED` | `1` | Set to `0` to disable all hooks (both surfaces) |
| `CODEX_REFLECTOR_BASH_GUARD` | `0` | OMP only. Set to `1` to enable the opt-in pre-execution bash guard (`0` disables). Python has no bash guard |
| `CODEX_REFLECTOR_STOP_REVIEW` | `0` (OMP) | OMP only. Set to `1` to enable the opt-in Stop gate (`0` disables). The Python Stop gate is always on |
| `CODEX_REFLECTOR_DEBUG` | `0` | Set to `1` for stderr diagnostics (both surfaces) |
| `TYPESAFE_API_KEY` | _(none)_ | Python only. Required. Bearer token for the TypeSafe decision-model API |
| `TYPESAFE_BASE_URL` | `https://api.typesafe.ai` | Python only. Judge API base URL |
| `TYPESAFE_DEFAULT_MODEL` | `jev-1.14.0` | Python only. Judge model id |

## How It Works

Both surfaces keep no FAIL state: reviews inject their verdict and scorecard inline, and the Stop gate runs a fresh review rather than consulting persisted state. Every route asks the decision model. The implementation specifics below (exit-code blocking) describe the Python plugin; the omp port mirrors the behavior with the [delta noted above](#behavior).

| Route | Reviews it | Outcome |
|---|---|---|
| Write review (Write/Edit tool calls) | Decision model | Scorecard with PASS/FAIL/UNCERTAIN, advisory |
| Plan review (Python only) | Decision model | Scorecard, advisory |
| Stop gate (Python always on, OMP opt-in) | Decision model | Scorecard, blocks on FAIL |
| Bash guard (OMP only, opt-in) | Decision model | Five yes/no answers, blocks at 0.9 |

If the judge does not answer, the route proceeds unreviewed and shows `review skipped: <cause>`. It never blocks.

### Code Reviews (async)

After Write/Edit tool calls, the decision model judges the change. It answers scored questions on seven dimensions: correctness, completeness against the stated job, complexity, slop, concurrency, performance, and design. UI files (`.html`, `.htm`, `.css`, `.scss`, `.sass`, `.less`, `.jsx`, `.tsx`, `.vue`, `.svelte`, `.astro`) add layout, animation, and accessibility. The answers become a scorecard, and the reflector injects it inline so the agent sees it on the next turn.

The verdict is computed in code from the judge's probabilities:

- FAIL when the worst defect probability reaches the route threshold: 0.7 on the advisory routes (write review, plan review).
- PASS when the worst defect probability is below 0.3 and no concern is strictly the most likely level on every dimension that still applies.
- UNCERTAIN otherwise. A dimension that leans to a concrete concern makes the verdict UNCERTAIN, so the agent sees it.

Only a FAIL blocks, and only at the Stop gate and the bash guard. Write and plan reviews are advisory. The Stop gate runs once per stop chain and blocks when the worst defect probability reaches 0.9: in the Python plugin a FAIL blocks via exit `2`, then the `stop_hook_active` guard lets a re-stop settle; in omp a FAIL returns `{ decision: "block", reason }` and the same guard settles the re-stop, with the native 8-continuation cap as backstop.

## The Scorecard

A scorecard is the review text. It starts with the verdict and the file, lists one line per dimension that shows a concern, and names the judge model:

```
Reflector Review ⚠️ FAIL [src/orders.py]:
- correctness: material defect (P(defect)=0.86) It contains a defect that produces a wrong result, a crash, data loss, or a security hole on a realistic input.
- slop: concrete concern (P(defect)=0.41) It contains one or two small leftovers, such as an unused import, a stale comment, or a vague name.
Judged by jev-1.14.0.
```

When no dimension shows a concern, the body reads `No dimension shows a material defect (highest P(defect)=0.04).`

The thresholds are fixed in code: FAIL at 0.7 on the advisory routes (write review, plan review), PASS below 0.3, block at 0.9 (Stop gate, bash guard).

## Limits

A scorecard names the dimension and the criterion. It does not name the line or the fix; to find the line, read the criterion against the change.

The decision model reads text. Text inside the change it judges can steer it. Treat a scorecard as one signal, the same way you treat any review.

Layout, animation, and accessibility are judged from the source text of UI files. The judge never sees a rendered page.

The reflector does not explain a failed command and does not reflect on thinking steps.

## Safety

- **Fail-open**: an internal error or a missing judge answer never blocks the agent. The route proceeds unreviewed with the `review skipped: <cause>` notice; the Python plugin exits `0`, the omp hook returns without a block.
- **Redaction**: secrets are redacted before any text leaves the process, on the judge path.
- **Loop prevention**: both surfaces check the `stop_hook_active` flag to run the Stop review once per stop chain, with oh-my-pi's built-in 8-continuation cap as the omp backstop.

## License

Apache-2.0
