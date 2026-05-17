# Demo Recording Workflow

Use this workflow for every meaningful live-test milestone.

## Rule

Do not leave a milestone as text-only proof. Record the live command execution with asciinema, convert the cast to GIF, and link both artifacts from the relevant research notes before committing.

## Artifact Names

Use descriptive, dated names under `artifacts/`:

```text
artifacts/<milestone>_YYYYMMDD.cast
artifacts/<milestone>_YYYYMMDD.gif
artifacts/<milestone>_YYYYMMDD.txt
```

The `.txt` transcript is optional when the cast already contains the full run, but useful for grep-friendly output.

## Recording Pattern

Record from the visible operator command when possible:

```bash
TERM=xterm-256color asciinema record --overwrite --return \
  --idle-time-limit 1 --window-size 132x38 \
  --title "<clear milestone title>" \
  --command '<shell command that prints the exact exploit/test command, then executes it>' \
  artifacts/<milestone>_YYYYMMDD.cast
```

Convert to GIF:

```bash
agg --theme monokai --idle-time-limit 1 --last-frame-duration 4 \
  --cols 132 --rows 38 \
  artifacts/<milestone>_YYYYMMDD.cast \
  artifacts/<milestone>_YYYYMMDD.gif
```

## Validation

Before committing:

```bash
jq -c . artifacts/<milestone>_YYYYMMDD.cast >/dev/null
file artifacts/<milestone>_YYYYMMDD.gif
ls -lh artifacts/<milestone>_YYYYMMDD.cast artifacts/<milestone>_YYYYMMDD.gif
```

Then update the relevant `docs/*.md` file with:

- what was tested,
- exact target style, such as host port, Docker IP, or VM IP,
- whether it succeeded,
- links to the cast and GIF.
