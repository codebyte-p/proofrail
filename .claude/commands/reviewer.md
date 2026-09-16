---
description: Dispatch the reviewer agent to review a diff or files for defects
argument-hint: [diff | branch | paths]
allowed-tools: Agent
---

Dispatch the `reviewer` agent to review: $ARGUMENTS

If no target is given, have it review the uncommitted working-tree diff.
Pass it enough context to work cold — it does not share your conversation history.
Relay its findings ranked by severity. Do not apply fixes unless I ask.
