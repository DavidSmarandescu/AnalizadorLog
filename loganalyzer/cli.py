from __future__ import annotations

import argparse
import sys
from datetime import date

from .detectors import Config, analyze
from .models import SEVERITIES
from .parsers import parse_line
from .report import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    defaults = Config()
    ap = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Detecta ataques en logs de SSH y de servidor web.",
    )
    ap.add_argument("files", nargs="+", help="archivos de log ('-' para stdin)")
    ap.add_argument("--json", action="store_true", help="salida en JSON")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low",
                    help="oculta hallazgos por debajo de esta gravedad")
    ap.add_argument("--fail-on", choices=SEVERITIES,
                    help="termina con código 1 si hay hallazgos de esta gravedad "
                         "o superior (útil en CI o cron)")
    ap.add_argument("--year", type=int, default=date.today().year,
                    help="año de los logs syslog, que no lo incluyen")
    ap.add_argument("--ssh-threshold", type=int, default=defaults.ssh_fail_threshold,
                    help="logins SSH fallidos para marcar fuerza bruta")
    ap.add_argument("--ssh-window", type=int, default=defaults.ssh_window,
                    help="ventana en segundos para la fuerza bruta SSH")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    events = []
    lines = 0
    for name in args.files:
        try:
            fh = sys.stdin if name == "-" else open(name, errors="replace")
        except OSError as exc:
            print(f"error: no se puede leer {name}: {exc.strerror}", file=sys.stderr)
            return 2
        with fh:
            for line in fh:
                lines += 1
                if (event := parse_line(line, args.year)) is not None:
                    events.append(event)

    cfg = Config(ssh_fail_threshold=args.ssh_threshold, ssh_window=args.ssh_window)
    findings = analyze(events, cfg)

    rank = SEVERITIES.index
    shown = [f for f in findings if rank(f.severity) >= rank(args.min_severity)]
    stats = {
        "lines": lines,
        "events": len(events),
        "ssh_events": sum(1 for e in events if e.source == "ssh"),
        "web_events": sum(1 for e in events if e.source == "web"),
    }

    if args.json:
        print(render_json(shown, stats))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(render_text(shown, stats, color=color))

    if args.fail_on and any(rank(f.severity) >= rank(args.fail_on) for f in findings):
        return 1
    return 0
