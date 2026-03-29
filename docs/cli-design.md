# CLI Design (Intent Model)

## Commands

- `macaron setup`
- `macaron scan <target...>`
- `macaron status`
- `macaron results`
- `macaron export`
- `macaron serve`

The same actions remain available through legacy flags for backward compatibility.

## UX Rules

- Scan commands print a run plan before execution.
- Default scan output is one summary table.
- Use `results` or `serve` for deeper detail.
- Error text should include a direct fix action.

## Profiles

- `passive`: lower rate and threads, reduced stages.
- `balanced`: default recommended mode.
- `aggressive`: high throughput for authorized testing.

## Setup UX

`macaron setup` should show:
- installed/missing status
- required/optional tags
- exact installation command per tool

## Compatibility Rules

- Keep legacy short flags functional.
- Keep legacy `-setup` accepted and translated.
- Never break `-s`, `-S`, `-R`, `--serve`.
