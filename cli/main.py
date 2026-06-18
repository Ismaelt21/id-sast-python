from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from api.schemas import ScanRequest
from config.settings import Settings
from service.scan_service import ScanService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="id-sast-python",
        description="Python static application security testing microservice",
    )

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a Python project")
    scan_parser.add_argument("path", help="Path to the project or file")
    scan_parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    scan_parser.add_argument("--no-persist", action="store_true", help="Do not persist the scan result")
    scan_parser.add_argument("--json-only", action="store_true", help="Generate JSON only")
    scan_parser.add_argument("--html-only", action="store_true", help="Generate HTML only")
    scan_parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    subparsers.add_parser("health", help="Show service status")
    subparsers.add_parser("version", help="Show service version")

    return parser


def main() -> None:
    Settings.initialize_directories()

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    service = ScanService()

    if args.command == "health":
        print(
            json.dumps(
                {
                    "status": "ok",
                    "service": Settings.APP_NAME,
                    "version": Settings.VERSION,
                },
                indent=2,
            )
        )
        return

    if args.command == "version":
        print(f"{Settings.APP_NAME} {Settings.VERSION} ({Settings.ENVIRONMENT})")
        return

    if args.command == "scan":
        request = ScanRequest(
            project_path=str(Path(args.path).resolve()),
            use_ai=not args.no_ai,
            persist=not args.no_persist,
            json_only=args.json_only,
            html_only=args.html_only,
            verbose=args.verbose,
        )

        result = service.run_scan(request)
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
        return


if __name__ == "__main__":
    main()

