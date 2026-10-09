"""Command line interface.

    emailicioso                      open the GUI
    emailicioso suspicious.eml       open the GUI with a file loaded
    emailicioso analyze FILE...      headless analysis (text, JSON, ticket summary, IOCs, HTML report)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from emailicioso import APP_NAME, __version__

LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_COLORS = {4: "\033[1;31m", 3: "\033[31m", 2: "\033[33m", 1: "\033[36m", 0: "\033[90m"}
_RESET = "\033[0m"


def _color(enabled: bool, level: int, text: str) -> str:
    return f"{_COLORS.get(level, '')}{text}{_RESET}" if enabled else text


def _text_output(result, color: bool, defang: bool) -> str:
    from emailicioso.core import domains as dom

    e = result.email
    f_url = dom.defang_url if defang else (lambda v: v)
    lvl = int(result.level)
    out = [
        _color(color, lvl, f"[{result.verdict.upper()}] score {result.score}/100") + f"  {e.path or ''}",
        f"  Subject : {e.subject}",
        f"  From    : {e.from_}",
    ]
    if result.reply_to:
        out.append(f"  Reply-To: {', '.join(str(a) for a in result.reply_to)}")
    out.append(f"  Date    : {e.date}")
    if result.originating_ip:
        out.append(f"  Orig. IP: {result.originating_ip}")
    auth = result.auth_summary()
    if auth:
        out.append("  Auth    : " + "  ".join(f"{k}={v}" for k, v in auth.items()))
    if result.findings:
        out.append("")
        for f in result.findings:
            if f.severity == 0:
                continue
            out.append("  " + _color(color, int(f.severity), f"{f.severity.label.upper():<8}") +
                       f" {f.category:<14} {f.title}")
    if result.urls:
        out.append("")
        out.append(f"  URLs ({len(result.urls)}):")
        for u in result.urls[:30]:
            mark = _color(color, int(u.severity), "!" if u.severity >= 2 else "-")
            out.append(f"   {mark} {f_url(u.target)}")
    if result.attachments:
        out.append("")
        out.append(f"  Attachments ({len(result.attachments)}):")
        for a in result.attachments:
            mark = _color(color, int(a.severity), "!" if a.severity >= 2 else "-")
            out.append(f"   {mark} {a.filename}  [{a.detected_type}]  sha256={a.sha256}")
    return "\n".join(out) + "\n"


def cmd_analyze(args: argparse.Namespace) -> int:
    from emailicioso.core import iocs as ioc_mod
    from emailicioso.core import report
    from emailicioso.core.analyzer import analyze_file
    from emailicioso.core.parser import ParseError

    color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    defang = not args.no_defang
    worst = 0
    exit_code = 0
    many = len(args.files) > 1
    json_results = []

    for path in args.files:
        try:
            result = analyze_file(path, lookback=args.lookback)
        except (OSError, ParseError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        worst = max(worst, int(result.level))

        if args.format == "json":
            json_results.append(result.to_dict())
        elif args.format == "summary":
            sys.stdout.write(report.summary_text(result, args.lang))
        elif args.format == "iocs-csv":
            sys.stdout.write(ioc_mod.to_csv(result.iocs, defang))
        elif args.format == "iocs-txt":
            sys.stdout.write(ioc_mod.to_text(result.iocs, defang))
        elif args.format == "kql":
            for q in result.hunting:
                sys.stdout.write(f"// {q.title}\n// {q.description}\n{q.query}\n\n")
        else:
            sys.stdout.write(_text_output(result, color, defang))
        if many and args.format not in ("json",):
            sys.stdout.write("\n")

        stem = Path(path).stem
        if args.html:
            target = Path(args.html)
            if many or target.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                target = target / f"{stem}.report.html"
            report.save_html(result, target, defang)
            print(f"HTML report: {target}", file=sys.stderr)
        if args.json:
            target = Path(args.json)
            if many or target.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                target = target / f"{stem}.analysis.json"
            target.write_text(report.to_json(result), encoding="utf-8")
            print(f"JSON: {target}", file=sys.stderr)

    if args.format == "json":
        payload = json_results[0] if len(json_results) == 1 and not many else json_results
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")

    if args.fail_on and worst >= LEVELS[args.fail_on]:
        return 2
    return exit_code


def cmd_gui(file: str | None) -> int:
    try:
        from emailicioso.ui.app import run
    except ImportError as exc:  # PySide6 missing
        print(f"The GUI needs PySide6 ({exc}). Install it with: pip install PySide6\n"
              f"Headless mode still works: {Path(sys.argv[0]).name} analyze FILE", file=sys.stderr)
        return 1
    return run(file)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="emailicioso",
        description=f"{APP_NAME} {__version__} - portable email forensics for SOC analysts.",
    )
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    sub = p.add_subparsers(dest="command")

    a = sub.add_parser("analyze", help="analyze .eml/.msg files without the GUI")
    a.add_argument("files", nargs="+", help=".eml or .msg files")
    a.add_argument("-f", "--format", choices=["text", "json", "summary", "iocs-csv", "iocs-txt", "kql"],
                   default="text", help="what to print on stdout (default: text)")
    a.add_argument("--html", metavar="PATH", help="also write an HTML report (file, or directory for many inputs)")
    a.add_argument("--json", metavar="PATH", help="also write the full JSON analysis")
    a.add_argument("--lang", choices=["en", "es"], default="en", help="language of --format summary")
    a.add_argument("--lookback", default="30d", help="time window of the KQL queries (default 30d)")
    a.add_argument("--no-defang", action="store_true", help="print indicators as-is (not defanged)")
    a.add_argument("--no-color", action="store_true")
    a.add_argument("--fail-on", choices=list(LEVELS), help="exit with code 2 if any file reaches this level")

    g = sub.add_parser("gui", help="open the graphical interface")
    g.add_argument("file", nargs="?", help="file to open")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("analyze", "gui", "-h", "--help", "--version") and Path(argv[0]).suffix:
        return cmd_gui(argv[0])
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        return cmd_analyze(args)
    return cmd_gui(getattr(args, "file", None))


if __name__ == "__main__":
    raise SystemExit(main())
