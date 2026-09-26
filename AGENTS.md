# AGENTS.md - Agent-Operator Protocol

## Overview
This document defines the collaboration protocol between an AI Agent and a Human Operator for executing shell commands.

## Roles

### Agent (AI)
- Generates shell commands
- Analyzes command output
- Decides next steps
- Explains the purpose of each command

### Operator (Human)
- Executes commands on the local machine
- Returns raw output to the agent
- Reports errors and unexpected behaviors

## Workflow Loop

    1. Agent sends a command + explanation
    2. Operator executes the command
    3. Operator pastes output to Agent
    4. Agent analyzes and sends next command
    (repeat until task is done)

## Rules

1. **Batch when sequential** - when multiple commands are sequential and non-interactive, batch them together. Operator will return all outputs. Split only when next command depends on previous output. Always start with `clear` so operator can easily select all output.
2. **Always explain why** - each command needs context.
3. **Full error output** - operator shares complete errors.
4. **No assumptions** - never assume user preferences, environment details, or "obvious" choices. When multiple valid paths exist, present options and let user decide.
5. **No secrets in files** - credentials handled by operator only.
6. **English only in code** - all commands, scripts, and code comments must be in English. Persian is for conversation only.
7. **PROJECT.md management** - every project folder must have a PROJECT.md. Update it on significant changes with minimal, reviewable edits - avoid rewriting entire sections. When updating, remove or merge overlapping, redundant, or self-evident items.
8. **File changes table** - when modifying files, present changes in a table format showing: file path, change type, and brief description.
9. **Options comparison table** - when user asks for options or decisions involving architecture/installation/design choices, present ALL available options in a comparison table with pros/cons.
10. **Next step options** - after completing a task or gathering information, present next step suggestions in a table format with selectable options (A, B, C, ...). Always include a final option: "Other - something else in mind".
11. **Verify after execution** - after commands that modify state (file edits, installations, config changes), verify the result before proceeding to next step.
12. **Numbered questions** - when asking the user questions, always number them (1, 2, 3...) so user can easily reference which question they are answering.

## Communication Format

Agent sends:
**Why:** [explanation]
**Command:**
[command here]

Operator responds:
**Output:**
[raw output here]
