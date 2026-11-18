"""Single CLI command: python cli.py analyze --input sample_request.json --output out.json

The CLI only calls the running API. All detection logic lives in the API.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def run_analyze(args: argparse.Namespace) -> int:
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError:
        return fail(f"input file not found: {args.input}")
    except json.JSONDecodeError as exc:
        return fail(f"input file is not valid JSON: {exc}")

    url = args.api_url.rstrip("/") + "/analyze"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        return fail(f"API returned HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}")
    except (urllib.error.URLError, TimeoutError) as exc:
        return fail(f"cannot reach API at {url} ({exc}). Is it running?")

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    except OSError as exc:
        return fail(f"cannot write output file {args.output}: {exc}")

    print(f"decision={result['decision']} risk_score={result['risk_score']} -> {args.output}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="cli.py", description="GuardRail Mini CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="send a request JSON file to POST /analyze")
    analyze.add_argument("--input", required=True, help="request JSON file")
    analyze.add_argument("--output", required=True, help="file to write the response JSON to")
    analyze.add_argument("--api-url", default=os.getenv("API_BASE_URL", "http://localhost:8000"))
    analyze.set_defaults(func=run_analyze)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
