"""HawkScan Autonomous AI Pentester CLI
Usage:
    python3 -m hawkscan.cli start -u http://127.0.0.1:8000 -r .
"""

import sys
import argparse
import asyncio
from hawkscan.config import settings
from hawkscan.orchestrator.pipeline import HawkScanPipeline


def main():
    parser = argparse.ArgumentParser(
        prog="hawkscan",
        description="HawkScan: Autonomous White-Box AI Pentester (Proof-by-Exploitation)"
    )
    subparsers = parser.add_subparsers(dest="command", help="HawkScan commands")

    start_cmd = subparsers.add_parser("start", help="Start an autonomous penetration test")
    start_cmd.add_argument("-u", "--url", default=settings.DEFAULT_TARGET_URL, help="Target running application URL")
    start_cmd.add_argument("-r", "--repo", default=settings.DEFAULT_REPO_PATH, help="Path to target source code repository")
    start_cmd.add_argument("-o", "--output", default="sarif", choices=["sarif", "markdown", "json"], help="Output report format")

    args = parser.parse_args()

    if args.command == "start":
        print(f"[*] HawkScan AI Pentester starting...")
        print(f"[*] Target Application URL: {args.url}")
        print(f"[*] Target Source Repository: {args.repo}")

        def cli_emitter(stage: str, event_type: str, msg: str, details: dict = None):
            if stage in ("tinyfish", "browser"):
                print(f"\033[1;36m[TINYFISH]\033[0m 🐟 {msg}")
            else:
                print(f"[{stage.upper()}] {msg}")

        pipeline = HawkScanPipeline(
            target_url=args.url,
            repo_path=args.repo,
            emit_callback=cli_emitter
        )

        dossier = asyncio.run(pipeline.run())
        print(f"\n[+] Pentest Complete. Verified Breaches: {dossier['summary']['verified_vulnerabilities']}")
        
        if args.output == "markdown":
            print("\n" + dossier["markdown_report"])
        elif args.output == "json":
            import json
            print(json.dumps(dossier, indent=2))
        elif args.output == "sarif":
            import json
            print(json.dumps(dossier.get("sarif", {}), indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
