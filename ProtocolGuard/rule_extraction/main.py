# protocolProject/main.py
import argparse
import subprocess
import sys
from pathlib import Path


def display_command(cmd):
    return ' '.join('[REDACTED]' if i and cmd[i-1] in ('--apikey', '--api-key') else word for i, word in enumerate(cmd))


def run_command(cmd: list, cwd: str = None):
    """Universal command execution function"""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT
        )
        print(f"[SUCCESS] Command executed successfully: {display_command(cmd)}")
        if result.stdout:
            print("Output summary:\n" + "\n".join(result.stdout.splitlines()[:5]))
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Command execution failed: {display_command(e.cmd)}")
        print(f"Error message:\n{e.stdout}")
        sys.exit(1)


def main():
    # Parameter parsing
    parser = argparse.ArgumentParser(
        description="Protocol Analysis Full Process Management System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--apikey", help="DeepSeek API Key")
    parser.add_argument("--protocol", required=True, help="Protocol name (e.g., MQTT, HTTP)")
    parser.add_argument("--version", required=True, help="Protocol version (e.g., 5.0, 1.1)")
    parser.add_argument("--html-file",
                        help="Original HTML file path (relative to current directory)")
    parser.add_argument("--profile", help="Offline x402 profile JSON (paths relative to the profile)")
    args = parser.parse_args()
    if args.protocol.lower() == "x402":
        if args.version != "2":
            parser.error("The pinned offline x402 profile supports protocol version 2")
        pipeline = Path(__file__).resolve().parents[1] / "x402/pipeline.py"
        cmd = [sys.executable, str(pipeline)]
        if args.profile:
            cmd += ["--profile", str(Path(args.profile).resolve())]
        subprocess.run(cmd, check=True)
        return
    if not args.apikey or not args.html_file:
        parser.error("Legacy protocols require --apikey and --html-file; x402 uses the offline profile")

    # Verify HTML file exists
    html_path = Path(args.html_file)
    if not html_path.exists():
        print(f"❌ HTML file does not exist: {html_path.absolute()}")
        sys.exit(1)

    # Define execution commands for each stage
    steps = [
        {
            "name": "Document Processing Stage",
            "cmd": [
                sys.executable, "-m", "documentProcess",
                "--api-key", args.apikey,
                "--protocol", args.protocol,
                "--version", args.version,
                "--html-file", str(html_path.absolute())
            ],
            "cwd": None  # Execute in root directory
        },
        {
            "name": "Keyword Processing Stage",
            "cmd": [
                sys.executable, "-m", "keywordProcess",
                "--apikey", args.apikey,
                "--protocol", args.protocol,
                "--version", args.version
            ],
            "cwd": None
        },
        {
            "name": "Rule Processing Stage",
            "cmd": [
                sys.executable, "__main__.py",
                "--apikey", args.apikey,
                "--protocol", args.protocol,
                "--version", args.version
            ],
            "cwd": "ruleProcess"  # Need to execute in subdirectory
        }
    ]

    # Execute each stage sequentially
    for step in steps:
        print(f"\n{'=' * 40}")
        print(f"🚀 Starting {step['name']}")
        print(f"📂 Working directory: {step['cwd'] or 'Current directory'}")
        print(f"⚙️ Executing command: {display_command(step['cmd'])}")
        print("=" * 40)

        run_command(
            cmd=step["cmd"],
            cwd=step["cwd"]
        )

    print("\n✅ All processes completed!")


if __name__ == "__main__":
    main()