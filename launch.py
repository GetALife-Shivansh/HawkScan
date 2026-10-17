"""HawkScan Monorepo Launcher
Single-command launcher that initializes the target testbed database,
concurrently boots the target application (port 8000) and HawkScan AI Pentester (port 9090),
and opens the HawkScan War Room UI in the browser.
"""

import os
import sys
import time
import signal
import subprocess
import webbrowser
import httpx

BANNER = """
\033[1;34m
██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗ ██████╗  █████╗ ███╗   ██╗
██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝██╔════╝ ██╔══██╗████╗  ██║
███████║███████║██║ █╗ ██║█████═╝ ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██╔══██║██║███╗██║██╔═██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚███╔███╔╝██║ ╚██╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\033[0m
\033[1;36mAutonomous White-Box AI Pentester · Proof-by-Exploitation\033[0m
\033[90m-------------------------------------------------------------------\033[0m
"""


def check_health(url: str, max_retries: int = 20) -> bool:
    for _ in range(max_retries):
        try:
            with httpx.Client(timeout=1.0) as client:
                r = client.get(url)
                if r.status_code == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def free_port(port: int):
    """Detects and terminates lingering or orphaned processes holding the specified port."""
    try:
        cmd = ["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        pids = [p.strip() for p in res.stdout.split() if p.strip()]
        for pid in pids:
            try:
                pid_int = int(pid)
                if pid_int != os.getpid():
                    print(f"\033[1;33m[*] Port {port} is in use: terminating orphaned process (PID {pid_int})...\033[0m")
                    os.kill(pid_int, signal.SIGKILL)
            except Exception:
                pass
        if pids:
            time.sleep(0.5)
    except Exception:
        pass


def main():
    print(BANNER)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    python_bin = sys.executable

    # Automatically free ports 8000 and 9090 if previous instances were not cleanly closed
    free_port(8000)
    free_port(9090)

    print("\033[1;34m[*] Python Environment:\033[0m " + python_bin)
    print("\033[1;34m[*] Target Application:\033[0m ApexPortal Testbed (Port 8000)")
    print("\033[1;34m[*] Pentester Console: \033[0m HawkScan War Room (Port 9090)")
    print()

    # Ensure database is in Insecure / Vulnerable state for pentest demonstration
    try:
        from target_app.database import init_db
        init_db(force_insecure=True)
        print("\033[1;35m[*] Target Security Posture: INSECURE (IDOR & SQLi flaws active for exploitation)\033[0m")
    except Exception as e:
        print(f"\033[1;33m[*] Notice: init_db fallback: {e}\033[0m")

    # Step 1: Start Target Application (Port 8000)
    print("\033[1;33m[1/3] Starting ApexPortal Target Application (127.0.0.1:8000)...\033[0m")
    env = os.environ.copy()
    env["PYTHONPATH"] = base_dir

    target_proc = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "target_app.app:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
        cwd=base_dir,
        env=env,
        start_new_session=True
    )

    if not check_health("http://127.0.0.1:8000/api/health"):
        print("\033[1;31m[-] Error: Target application failed to start on port 8000.\033[0m")
        target_proc.terminate()
        sys.exit(1)
    print("\033[1;32m[✓] Target Application is live.\033[0m")

    # Step 2: Start HawkScan Server (Port 9090)
    print("\033[1;33m[2/3] Starting HawkScan AI Pentester Server (127.0.0.1:9090)...\033[0m")
    hawkscan_proc = subprocess.Popen(
        [python_bin, "-m", "uvicorn", "hawkscan.server.app:app", "--host", "127.0.0.1", "--port", "9090", "--log-level", "warning"],
        cwd=base_dir,
        env=env,
        start_new_session=True
    )

    if not check_health("http://127.0.0.1:9090/api/health"):
        print("\033[1;31m[-] Error: HawkScan server failed to start on port 9090.\033[0m")
        target_proc.terminate()
        hawkscan_proc.terminate()
        sys.exit(1)
    print("\033[1;32m[✓] HawkScan AI Pentester Server is live.\033[0m")

    # Step 3: Launch Browser UI
    ui_url = "http://127.0.0.1:9090"
    print(f"\033[1;33m[3/3] Opening HawkScan War Room UI at {ui_url}...\033[0m")
    time.sleep(0.5)
    webbrowser.open(ui_url)

    print()
    print("\033[1;32m===================================================================\033[0m")
    print("\033[1;32m  HAWKSCAN IS LIVE AND READY FOR AUTONOMOUS PENTESTING!           \033[0m")
    print("\033[1;32m===================================================================\033[0m")
    print(f"  • HawkScan War Room:   \033[1;36m{ui_url}\033[0m")
    print("  • Target Webview:      \033[1;36mhttp://127.0.0.1:8000\033[0m")
    print("  • SARIF 2.1.0 Export:  \033[1;36mhttp://127.0.0.1:9090/api/export/sarif\033[0m")
    print("  • SSE Telemetry Feed:  \033[1;36mhttp://127.0.0.1:9090/api/stream\033[0m")
    print()
    print("\033[90mPress Ctrl+C, Ctrl+Q, or 'q' to terminate all services.\033[0m")

    # Interactive Stdin handling
    old_term_attrs = None
    is_interactive = sys.stdin.isatty()
    if is_interactive:
        try:
            import termios
            old_term_attrs = termios.tcgetattr(sys.stdin)
            new_attrs = termios.tcgetattr(sys.stdin)
            new_attrs[0] &= ~termios.IXON # Disable XON/XOFF flow control
            termios.tcsetattr(sys.stdin, termios.TCSANOW, new_attrs)
        except Exception:
            old_term_attrs = None

    shutdown_lock = False

    def shutdown(sig=None, frame=None):
        nonlocal shutdown_lock
        if shutdown_lock:
            return
        shutdown_lock = True

        if old_term_attrs is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_term_attrs)
            except Exception:
                pass

        print("\n\033[1;33m[*] Stopping HawkScan and Target servers...\033[0m")
        for proc in (target_proc, hawkscan_proc):
            if proc:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    proc.wait(timeout=2.0)
                except Exception:
                    try:
                        pgid = os.getpgid(proc.pid)
                        os.killpg(pgid, signal.SIGKILL)
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass

        print("\033[1;32m[✓] All services stopped cleanly. Goodbye!\033[0m")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    if hasattr(signal, "SIGQUIT"):
        signal.signal(signal.SIGQUIT, shutdown)

    try:
        import select
        while True:
            if target_proc.poll() is not None:
                print("\033[1;31m[-] Notice: Target application stopped.\033[0m")
                shutdown()
            if hawkscan_proc.poll() is not None:
                print("\033[1;31m[-] Notice: HawkScan server stopped.\033[0m")
                shutdown()

            if is_interactive:
                try:
                    rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
                    if rlist:
                        ch = os.read(sys.stdin.fileno(), 1024)
                        if not ch or b"\x11" in ch or b"\x03" in ch or b"q" in ch or b"Q" in ch:
                            shutdown()
                except Exception:
                    time.sleep(0.5)
            else:
                time.sleep(0.5)
    except (KeyboardInterrupt, SystemExit):
        shutdown()


if __name__ == "__main__":
    main()
