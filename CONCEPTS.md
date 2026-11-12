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

### Part
One consecutive piece of an oversized subject, at most 28,000 UTF-8 bytes. A piece is cut after the last newline that lies in its second half. The code calls it a chunk. A subject in one part gives the same scorecard as before parts existed.

### Combined verdict
The verdict over the parts of a split subject. Per part the verdict rule applies unchanged. The combined verdict is FAIL when any judged part is FAIL. When every part has a verdict, it is PASS when all parts are PASS, and UNCERTAIN otherwise. A FAIL stands when other parts have no verdict.

### Scorecard
The review text a route emits: the verdict prefix, one line per dimension that shows a concern, and the judge model id. With more than one part, each dimension keeps the line with the highest defect probability, the earliest part on a tie, and that line ends with the part it came from, ` (part <i> of <n>)`. The model line names each distinct judge model once, in part order, joined by `, `. A split subject adds one of two completeness lines, `Completeness was not judged: the subject was split into <n> parts.` or `Completeness was not judged: the request does not fit in one part with the subject.`, and a review with unjudged parts adds `Parts not judged: <k> of <n> (<cause>).`.

### Judge unavailable
Any failure to get judge answers: no credential, HTTP error, timeout, abort, malformed answer, or a missing question id. The route proceeds unreviewed and emits one notice, `review skipped: <cause>`. On a split subject, a FAIL from a judged part stands even when other parts have no verdict; the scorecard then holds the `Parts not judged` line. Without a FAIL, one part without a verdict skips the whole review with the notice.

## Review surfaces

### Claude/Cursor surface
The Python plugin that receives Claude Code (and Cursor-adapted) hook events, asks the TypeSafe decision model for verdicts on write review, plan review, and Stop, and blocks Stop via exit code 2.

### OMP surface
The native oh-my-pi extension that registers the same review idea as hook handlers. It asks the omp judge (`modelRoles.judge`) for verdicts on write review, Stop, and the bash guard. Per-tool reviews are advisory; the Stop gate and the bash guard may block.

### Stop gate
Also called the holistic Stop review. The single blocking review run once per stop chain, answered by the decision model. Its subject is the text of the last assistant message, with the transcript as fallback only when that message has no text. It blocks when the worst defect probability reaches 0.9. PASS and UNCERTAIN settle fail-open. Re-stops with the harness stop-active flag settle without re-reviewing.

## Flagged ambiguities

- "'codex' no longer names a reviewer": the package, the plugin, the files, and the settings keep the name codex although no route calls Codex.
- "The verdict is computed, not written": a scorecard verdict is computed in code from the judge's probabilities; the model answers numbers and never writes the verdict.
