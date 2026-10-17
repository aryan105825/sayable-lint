# sayable-lint

Measure how ready any MCP server is for voice agents.

Voice agents often consume MCP servers that were built for screens: markdown tables, ISO timestamps,
long dumps, and destructive tools with no confirmation. `sayable-lint` connects to a **Streamable HTTP**
MCP server (spec 2025-11-25 or later) over the network and scores it. It needs no changes to the server.

## Install

```bash
pip install git+https://github.com/aryan105825/sayable-lint.git
# or, from a clone:
pip install .
```

Python 3.10 or newer.

## Use

```bash
sayable-lint https://your-server.example/mcp \
  --probe-args probe_args.json \
  --out report.json --html report.html
```

It prints a scorecard, writes the JSON and a single-file HTML report, and exits 0.
Useful flags: `--max-words 45`, `--latency-ms 800`, `--repeats 10`, `--wait` (wait for the server to come up),
`--min-score N` (exit 1 if the total is below N). Exit code 2 means the linter itself could not run
(for example, the server is unreachable).

## Two scores, kept separate

- **spec_score**: protocol checks over raw HTTP (PROTO-01..09): protocol version, bad version header,
  `notifications/initialized` returns 202, Origin handling, GET behaviour, session handling,
  `tools/list` schema validity, unknown-method error, OAuth discovery on 401. These follow the MCP spec.
- **heuristic_score**: latency (LAT-01..03), speech (SPEECH-00..07) and design (DES-01..06) checks:
  reply length, no markdown, URLs or ISO timestamps in speakable text, structured output, tool annotations,
  confirmation parameters. These are opinionated and configurable.

The total is 0-100. The scoring formula and every check ID are in [CHECKS.md](CHECKS.md).

## Safety: tools are only called if you opt in

The linter calls **only** the tools named in your probe file, with the arguments you give. Choose
read-only tools. Without a probe file the speech checks report a warning and no tool is called.
`examples/probe_args.json` shows the format; entries are keyed by the server's own `serverInfo.name`:

```json
{
  "my-server": {
    "list_things": {"limit": 3}
  }
}
```

## Use it in CI

```yaml
- run: pip install git+https://github.com/aryan105825/sayable-lint.git
- run: sayable-lint http://127.0.0.1:8000/mcp --probe-args probe_args.json --min-score 80 --wait
```

## Develop

```bash
pip install -e ".[dev]"
pytest -q
```

## Not affiliated

This is an independent open-source tool (MIT). It is not Amazon-certified and makes no claim about
certification for any voice assistant.