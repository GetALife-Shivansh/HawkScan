"""HawkScan Cloudflare Tunnel Manager
Manages ephemeral trycloudflare.com tunnels so remote cloud browser agents (TinyFish Cloud)
can navigate and exploit web applications hosted on localhost / loopback interfaces.
"""

import os
import re
import shutil
import asyncio
import inspect
import logging
from urllib.parse import urlparse, urlunparse
from typing import Optional, List, Callable, Dict, Any

logger = logging.getLogger("hawkscan.tunnel")

CLOUDFLARE_URL_REGEX = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")


class CloudflareTunnelManager:
    """Manages ephemeral Cloudflare Quick Tunnels for local target reachability."""

    _instance: Optional["CloudflareTunnelManager"] = None

    def __init__(self, emit_fn: Optional[Callable] = None):
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.public_url: Optional[str] = None
        self.local_target_url: Optional[str] = None
        self.emit_fn = emit_fn
        self._lock = asyncio.Lock()
        self._reader_tasks: List[asyncio.Task] = []
        self._found_event: Optional[asyncio.Event] = None

    @classmethod
    def get_instance(cls, emit_fn: Optional[Callable] = None) -> "CloudflareTunnelManager":
        if cls._instance is None:
            cls._instance = CloudflareTunnelManager(emit_fn=emit_fn)
        elif emit_fn and not cls._instance.emit_fn:
            cls._instance.emit_fn = emit_fn
        return cls._instance

    @staticmethod
    def find_cloudflared_binary() -> Optional[str]:
        """Locates the cloudflared executable on the system PATH or common locations."""
        found = shutil.which("cloudflared")
        if found:
            return found
        common_paths = [
            "/opt/homebrew/bin/cloudflared",
            "/usr/local/bin/cloudflared",
            "/usr/bin/cloudflared",
            os.path.expanduser("~/.cloudflared/cloudflared"),
        ]
        for p in common_paths:
            if os.path.exists(p) and os.access(p, os.X_OK):
                return p
        return None

    def _log(self, message: str, level: str = "INFO"):
        time_str = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
        from datetime import datetime
        t_now = datetime.now().strftime("%H:%M:%S")
        print(f"\033[90m[{t_now}]\033[0m \033[1;35m[CLOUDFLARE TUNNEL]\033[0m {message}", flush=True)

        if self.emit_fn:
            try:
                res = self.emit_fn("tunnel", level.lower(), message, {"public_url": self.public_url})
                if inspect.isawaitable(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    def is_active(self) -> bool:
        """Returns True if the tunnel process is running and a public URL exists."""
        return bool(self.proc and self.proc.returncode is None and self.public_url)

    async def start_tunnel(self, local_url: str = "http://127.0.0.1:8000", timeout: float = 16.0) -> Optional[str]:
        """Starts an ephemeral trycloudflare.com tunnel targeting the local application."""
        async with self._lock:
            # Normalize local URL (ensure port is present)
            parsed = urlparse(local_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            host = parsed.hostname or "127.0.0.1"
            normalized_local = f"http://{host}:{port}"

            if self.is_active():
                if self.local_target_url == normalized_local:
                    return self.public_url
                else:
                    await self._stop_internal()

            bin_path = self.find_cloudflared_binary()
            if not bin_path:
                self._log("⚠️ cloudflared binary not found on system PATH. Cloudflare tunnel disabled.", level="WARNING")
                return None

            self.local_target_url = normalized_local
            self._log(f"🚇 Provisioning Cloudflare Quick Tunnel for {normalized_local}...")
            self._found_event = asyncio.Event()
            self.public_url = None

            try:
                self.proc = await asyncio.create_subprocess_exec(
                    bin_path,
                    "tunnel",
                    "--url",
                    normalized_local,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            except Exception as e:
                self._log(f"❌ Failed to spawn cloudflared process: {e}", level="ERROR")
                return None

            async def _stream_reader(stream: asyncio.StreamReader, stream_name: str):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    text = line.decode("utf-8", errors="ignore").strip()
                    m = CLOUDFLARE_URL_REGEX.search(text)
                    if m and self._found_event and not self._found_event.is_set():
                        self.public_url = m.group(0).rstrip("/")
                        self._found_event.set()

            self._reader_tasks = [
                asyncio.create_task(_stream_reader(self.proc.stdout, "stdout")),
                asyncio.create_task(_stream_reader(self.proc.stderr, "stderr"))
            ]

            try:
                await asyncio.wait_for(self._found_event.wait(), timeout=timeout)
                self._log(f"✅ Cloudflare Tunnel live: {normalized_local} -> {self.public_url}", level="SUCCESS")
                return self.public_url
            except asyncio.TimeoutError:
                self._log(f"⚠️ Timed out waiting for Cloudflare Tunnel URL ({timeout}s).", level="WARNING")
                await self._stop_internal()
                return None

    def map_local_to_tunnel(self, url: str) -> str:
        """Translates a localhost/loopback URL into the active Cloudflare Tunnel public URL."""
        if not self.public_url or not url:
            return url
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
                t_parsed = urlparse(self.public_url)
                new_netloc = t_parsed.netloc
                new_scheme = t_parsed.scheme
                return urlunparse((
                    new_scheme,
                    new_netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment
                ))
            return url
        except Exception:
            return url

    def map_tunnel_to_local(self, url: str) -> str:
        """Translates a Cloudflare Tunnel URL back to the local target address."""
        if not self.public_url or not self.local_target_url or not url:
            return url
        try:
            if url.startswith(self.public_url):
                sub = url[len(self.public_url):]
                if not sub.startswith("/"):
                    sub = "/" + sub
                return f"{self.local_target_url.rstrip('/')}{sub}"
            return url
        except Exception:
            return url

    async def _stop_internal(self):
        """Internal teardown without lock acquisition."""
        for t in self._reader_tasks:
            t.cancel()
        self._reader_tasks.clear()

        if self.proc:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=2.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

        if self.public_url:
            self._log(f"🛑 Terminated Cloudflare Tunnel ({self.public_url})")
        self.public_url = None
        self.local_target_url = None
        self._found_event = None

    async def stop_tunnel(self):
        """Clean teardown of the active Cloudflare tunnel."""
        async with self._lock:
            await self._stop_internal()


tunnel_manager = CloudflareTunnelManager.get_instance()
