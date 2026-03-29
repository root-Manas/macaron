# macaronV2 Product Principles

## 1) User Intent First

The user should answer one question quickly:
- `What do I want now: setup, scan, inspect, or export?`

Design rule:
- Command model should map directly to that intent.

## 2) Progressive Depth

Default output should be concise and actionable.
Deep detail must be opt-in.

Design rule:
- One-line summary by default.
- Rich detail via explicit `results`, `serve`, or JSON export.

## 3) Trustworthy State

Every action should be recoverable and queryable.

Design rule:
- Persist scans in SQLite as source of truth.
- Keep per-target JSON mirrors for portability.

## 4) Stage Transparency

Users must always know what pipeline stages are active.

Design rule:
- Stage list is explicit and customizable.
- Run plan shown before scan starts.

## 5) Safe by Default

The tool should not nudge users into unsafe behavior.

Design rule:
- No bypass/evasion guidance.
- Clear authorization warning in docs/help.

## 6) Fast Feedback Loops

Users should see useful data in seconds, not after full completion.

Design rule:
- Keep fast profile available.
- Make status/result query paths cheap.

## 7) Frictionless Setup

Users should be able to move from clone to first scan quickly.

Design rule:
- Setup command reports missing tools and install commands.
- Optional auto-install path for Linux.
