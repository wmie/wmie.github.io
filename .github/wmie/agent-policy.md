## WMIE review and merge

GitHub Agentic Workflows runs the review locally in this repository.
WMIE Agent provides the required PR approval and publishes `WMIE CI` and `WMIE approval`.
A complete positive review and successful applicable CI allow the bot to merge automatically.
Findings, incomplete analysis, technical errors, stale commits, and missing required checks keep the merge blocked.
Push corrections to the same branch and let the checks and review run again.

PR size is a reviewability concern. The process imposes no blanket line-count cap.
Dependency changes require security, compatibility, and lockfile review. A new dependency alone does not block a PR.
The automatic issue resolver is disabled.
Workflow files and agent instructions remain protected. Changes follow the authorized maintenance path.
Scope and infrastructure questions still require the task owner's decision.
