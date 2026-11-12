# Concepts

Project-specific vocabulary for codex-reflector. One definition per term. Implementation paths live in code and AGENTS.md, not here.

## Decision model

A model that answers questions with probabilities instead of prose. The reflector calls it the judge, sends it questions, and computes the verdict in code from the answers.

### Dimension
One scored question about one quality of the subject. It has three levels: material defect, concrete concern, and no concern. The write route asks seven dimensions; UI files add three.

### Screen
One yes/no question on the write route that adjusts the dimension set: executable code, shared state, and placeholder.

### Defect probability
The probability the judge assigns to the material-defect level of a dimension. The verdict rule compares the worst defect probability against the route threshold.

### Scorecard
The review text a route emits: the verdict prefix, one line per dimension that shows a concern, and the judge model id.

### Judge unavailable
Any failure to get judge answers: no credential, HTTP error, timeout, abort, malformed answer, or a missing question id. The route proceeds unreviewed and emits one notice, `review skipped: <cause>`.

## Review surfaces

### Claude/Cursor surface
The Python plugin that receives Claude Code (and Cursor-adapted) hook events, asks the TypeSafe decision model for verdicts on write review, plan review, and Stop, and blocks Stop via exit code 2.

### OMP surface
The native oh-my-pi extension that registers the same review idea as hook handlers. It asks the omp judge (`modelRoles.judge`) for verdicts on write review, Stop, and the bash guard. Per-tool reviews are advisory; the Stop gate and the bash guard may block.

### Stop gate
Also called the holistic Stop review. The single blocking review run once per stop chain, answered by the decision model. It blocks when the worst defect probability reaches 0.9. PASS and UNCERTAIN settle fail-open. Re-stops with the harness stop-active flag settle without re-reviewing.

## Flagged ambiguities

- "'codex' no longer names a reviewer": the package, the plugin, the files, and the settings keep the name codex although no route calls Codex.
- "The verdict is computed, not written": a scorecard verdict is computed in code from the judge's probabilities; the model answers numbers and never writes the verdict.
