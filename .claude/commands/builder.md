---
description: Dispatch the builder agent to implement a change
argument-hint: <what to build>
allowed-tools: Agent
---

Dispatch the `builder` agent with this implementation task: $ARGUMENTS

Pass it enough context to work cold — the target files, the plan if one exists, and
the scope boundary. It does not share your conversation history.
Relay what it changed, including anything it reported as incomplete or failing.
