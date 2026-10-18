"""HawkScan TinyFish Browser Automation Engine
Provides dual-mode browser execution:
1. TinyFish Cloud CDP connection (for remote/cloud application testing)
2. Local Headless Playwright Chromium (for offline, CI/CD, and loopback testing)

Automatically selects the optimal engine based on target URL and connectivity,
with real-time terminal stdout logging and live telemetry emitter dispatch.
"""

import os
import asyncio
import logging
import httpx
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
from hawkscan.config import settings

logger = logging.getLogger("hawkscan.tinyfish")
logger.setLevel(logging.INFO)


class TinyFishEngine:
    """Autonomous browser execution engine backed by TinyFish Cloud CDP and Playwright."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        headless: bool = True,
        target_url: Optional[str] = None,
        emit_fn: Optional[Callable[..., Any]] = None,
        verbose_terminal: bool = True,
    ):
        self.api_key = api_key if api_key is not None else settings.TINYFISH_API_KEY
        self.api_url = (api_url or settings.TINYFISH_API_URL).rstrip("/")
        self.headless = headless
        self.target_url = target_url or ""
        self.emit_fn = emit_fn
        self.verbose_terminal = verbose_terminal
        
        self.engine_mode: str = "UNINITIALIZED"
        self.session_id: Optional[str] = None
        self.cdp_url: Optional[str] = None
        self.base_url: Optional[str] = None
        self.tunnel_url: Optional[str] = None
        self.cloud_target_url: Optional[str] = None
        self.active_url: str = self.target_url
        self.last_action: str = "READY"
        self.last_screenshot_b64: Optional[str] = None

        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._active_page: Optional[Page] = None

    def _log(self, message: str, level: str = "INFO", details: Optional[Dict[str, Any]] = None):
        """Outputs structured, colored logs directly to the OS terminal and notifies telemetry emitter."""
        if self.verbose_terminal:
            time_str = datetime.now().strftime("%H:%M:%S")
            if level == "ERROR":
                badge = "\033[1;31m[TINYFISH ERROR]\033[0m"
            elif level == "WARNING":
                badge = "\033[1;33m[TINYFISH WARN]\033[0m"
            elif level == "SUCCESS":
                badge = "\033[1;32m[TINYFISH]\033[0m"
            else:
                badge = "\033[1;36m[TINYFISH]\033[0m"

            print(f"\033[90m[{time_str}]\033[0m {badge} {message}", flush=True)

        if level == "ERROR":
            logger.error(message)
        elif level == "WARNING":
            logger.warning(message)
        else:
            logger.info(message)

        if self.emit_fn:
            try:
                import inspect
                sig = inspect.signature(self.emit_fn)
                num_params = len(sig.parameters)
                if num_params == 2:
                    res = self.emit_fn("tinyfish", message)
                else:
                    res = self.emit_fn("tinyfish", level.lower(), message, details or {})

                if inspect.isawaitable(res):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)
                    except RuntimeError:
                        pass
            except Exception:
                pass

    def _is_loopback(self, url: str) -> bool:
        """Determines if the target URL resolves to localhost/loopback."""
        if not url:
            return True
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            return host in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or host.endswith(".local")
        except Exception:
            return False

    async def start(self, target_url: Optional[str] = None, force_cloud: bool = False, force_local: bool = False) -> str:
        """Initializes the browser session using TinyFish Cloud (default) or Local Playwright."""
        url = target_url or self.target_url
        if url:
            self.target_url = url
            self.active_url = url

        self._log(f"Initializing autonomous browser session (Target: {url or 'about:blank'}, Headless: {self.headless})")
        self._playwright = await async_playwright().start()

        # Decide whether to use TinyFish Cloud (Default) or Local Playwright
        is_local_target = self._is_loopback(url)
        has_api_key = bool(self.api_key and self.api_key.strip())
        test_force_local = (os.getenv("HAWKSCAN_FORCE_LOCAL_TESTS") == "1")
        use_cloud = not (force_local or test_force_local) and (has_api_key or force_cloud)

        if use_cloud:
            target_cloud_url = url
            if is_local_target:
                # Target is on localhost: establish an ephemeral Cloudflare Tunnel so TinyFish Cloud in AWS can access it
                from hawkscan.engine.tunnel_manager import tunnel_manager
                self._log(f"Target is on localhost ({url}). Establishing Cloudflare Tunnel for TinyFish Cloud agent...")
                try:
                    tunnel_url = await tunnel_manager.start_tunnel(local_url=url, timeout=16.0)
                    if tunnel_url:
                        self.tunnel_url = tunnel_url
                        target_cloud_url = tunnel_url
                        self.cloud_target_url = tunnel_url
                        self._log(f"Cloudflare Tunnel established: {url} -> {tunnel_url}", level="SUCCESS")
                    else:
                        self._log("Cloudflare tunnel unavailable; will attempt fallback to Local Playwright.", level="WARNING")
                        target_cloud_url = None
                except Exception as te:
                    self._log(f"Error establishing Cloudflare tunnel: {te}", level="WARNING")
                    target_cloud_url = None

            if target_cloud_url:
                self._log(f"Querying TinyFish Cloud CDP endpoint ({self.api_url}) for {target_cloud_url}...")
                try:
                    # Attempt connection to TinyFish Cloud CDP
                    cdp_url = await self._acquire_tinyfish_cdp_url(target_url=target_cloud_url)
                    if cdp_url:
                        self._browser = await self._playwright.chromium.connect_over_cdp(cdp_url)
                        if self._browser.contexts:
                            self._context = self._browser.contexts[0]
                        else:
                            self._context = await self._browser.new_context(
                                viewport={"width": 1280, "height": 800},
                                user_agent="HawkScan-TinyFish-Browser/1.0"
                            )
                        if self._context.pages:
                            self._active_page = self._context.pages[0]
                        self.engine_mode = "TINYFISH_CLOUD"
                        self.last_action = "CONNECTED_TINYFISH_CLOUD"
                        tunnel_info = f" [via Cloudflare Tunnel: {self.tunnel_url}]" if self.tunnel_url else ""
                        self._log(f"Connected to TinyFish Cloud CDP session {self.session_id}{tunnel_info} (CDP: {cdp_url[:45]}...)", level="SUCCESS")
                        return self.engine_mode
                except Exception as e:
                    self._log(f"TinyFish Cloud CDP connection failed: {e}. Falling back to Local Playwright.", level="WARNING")

        # Fallback to local Playwright Chromium
        self._log(f"Launching local headless Playwright Chromium (Fallback/Offline)")
        self._browser = await self._playwright.chromium.launch(
            headless=self.headless,
            args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        self._context = await self._browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="HawkScan-Browser-Agent/1.0"
        )
        self.engine_mode = "LOCAL_PLAYWRIGHT"
        self.session_id = f"local-session-{hex(abs(hash(url or 'hawkscan')))[2:10]}"
        self.last_action = "CONNECTED_LOCAL_PLAYWRIGHT"
        self._log(f"Local Playwright Chromium active (Session: {self.session_id})", level="SUCCESS")
        return self.engine_mode

    async def _acquire_tinyfish_cdp_url(self, target_url: Optional[str] = None) -> Optional[str]:
        """Queries TinyFish Cloud API to provision a CDP browser session."""
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        cloud_url = target_url or self.cloud_target_url or self.target_url or "https://www.tinyfish.ai"
        async with httpx.AsyncClient(timeout=12.0) as client:
            try:
                resp = await client.post(
                    self.api_url,
                    headers=headers,
                    json={"url": cloud_url}
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    self.session_id = data.get("session_id")
                    self.cdp_url = data.get("cdp_url")
                    self.base_url = data.get("base_url")
                    return self.cdp_url
            except Exception as e:
                self._log(f"TinyFish session creation error: {e}", level="WARNING")

            # Fallback to direct websocket format if supported
            ws_url = f"{self.api_url.replace('http', 'ws')}/cdp?token={self.api_key}"
            return ws_url

    async def get_page(self) -> Page:
        """Retrieves or creates an active page."""
        if self._active_page is None or self._active_page.is_closed():
            if not self._context:
                await self.start()
            if self._context and self._context.pages:
                self._active_page = self._context.pages[0]
            elif self._context:
                self._active_page = await self._context.new_page()
        return self._active_page

    async def navigate(self, url: str, wait_until: str = "domcontentloaded", timeout: int = 15000) -> bool:
        """Navigates the active page to the specified URL."""
        target_url = (url or "").strip()
        if target_url and not target_url.startswith(("http://", "https://", "about:", "chrome:", "data:")):
            if target_url.startswith(("localhost", "127.0.0.1", "0.0.0.0")):
                target_url = f"http://{target_url}"
            else:
                target_url = f"https://{target_url}"

        # If TinyFish Cloud is active with an established Cloudflare Tunnel, translate localhost destination
        nav_url = target_url
        if self.engine_mode == "TINYFISH_CLOUD" and self.tunnel_url:
            from hawkscan.engine.tunnel_manager import tunnel_manager
            nav_url = tunnel_manager.map_local_to_tunnel(target_url)

        self._log(f"Navigating browser viewport -> {target_url}" + (f" (via Tunnel: {nav_url})" if nav_url != target_url else ""))
        page = await self.get_page()
        try:
            self.last_action = f"NAVIGATE: {target_url}"
            self.active_url = target_url
            await page.goto(nav_url, wait_until=wait_until, timeout=timeout)
            title = ""
            try:
                title = await page.title()
            except Exception:
                pass
            await self._capture_latest_screenshot()
            self._log(f"Navigated to {target_url} (DOM Title: '{title}')", level="SUCCESS")
            return True
        except Exception as e:
            self._log(f"Navigation failed to {target_url}: {e}", level="ERROR")
            return False

    async def _capture_latest_screenshot(self) -> Optional[str]:
        """Takes a base64-encoded viewport screenshot for the live UI."""
        if not self._active_page or self._active_page.is_closed():
            return None
        try:
            import base64
            shot_bytes = await self._active_page.screenshot(type="jpeg", quality=75, full_page=False)
            self.last_screenshot_b64 = f"data:image/jpeg;base64,{base64.b64encode(shot_bytes).decode('utf-8')}"
            return self.last_screenshot_b64
        except Exception:
            return None

    async def get_state(self) -> Dict[str, Any]:
        """Returns snapshot of current TinyFish browser engine state."""
        cookies = await self.get_cookies()
        title = ""
        url = self.active_url
        if self._active_page and not self._active_page.is_closed():
            try:
                title = await self._active_page.title()
                url = self._active_page.url or self.active_url
            except Exception:
                pass

        if not self.last_screenshot_b64 and self._active_page:
            await self._capture_latest_screenshot()

        reason = ""
        if self.engine_mode == "TINYFISH_CLOUD":
            if self.tunnel_url:
                reason = f"Active TinyFish Cloud session via Cloudflare Tunnel ({self.tunnel_url} -> {self.target_url})"
            else:
                reason = f"Active TinyFish Cloud session ({self.session_id})"
        elif self.engine_mode == "LOCAL_PLAYWRIGHT":
            reason = "Running in Local Playwright Chromium mode."

        return {
            "engine_mode": self.engine_mode,
            "engine_reason": reason,
            "session_id": self.session_id or ("local-playwright-session" if self.engine_mode == "LOCAL_PLAYWRIGHT" else "pending"),
            "cdp_url": self.cdp_url,
            "base_url": self.base_url,
            "tunnel_url": self.tunnel_url,
            "target_url": self.target_url,
            "active_url": url,
            "title": title,
            "last_action": self.last_action,
            "cookies": cookies,
            "cookies_count": len(cookies),
            "screenshot_b64": self.last_screenshot_b64
        }

    async def get_cookies(self, urls: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Retrieves cookies from the current browser context with full security attributes."""
        if not self._context:
            return []
        cookies = await self._context.cookies(urls)
        normalized = []
        for c in cookies:
            normalized.append({
                "name": c.get("name"),
                "value": c.get("value"),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "expires": c.get("expires"),
                "http_only": c.get("httpOnly", False),
                "secure": c.get("secure", False),
                "same_site": c.get("sameSite", "None"),
            })
        return normalized

    async def set_cookies(self, cookies: List[Dict[str, Any]]):
        """Sets or injects cookies into the browser context."""
        if not self._context:
            await self.start()
        converted = []
        for c in cookies:
            cookie_domain = c.get("domain")
            if self.engine_mode == "TINYFISH_CLOUD" and self.tunnel_url:
                parsed_tun = urlparse(self.tunnel_url)
                cookie_domain = parsed_tun.hostname
            elif not cookie_domain:
                cookie_domain = "127.0.0.1"

            cookie_dict = {
                "name": c["name"],
                "value": c["value"],
                "domain": cookie_domain,
                "path": c.get("path", "/"),
            }
            if "http_only" in c:
                cookie_dict["httpOnly"] = c["http_only"]
            elif "httpOnly" in c:
                cookie_dict["httpOnly"] = c["httpOnly"]

            if "secure" in c:
                cookie_dict["secure"] = c["secure"]

            if "same_site" in c:
                cookie_dict["sameSite"] = c["same_site"]
            elif "sameSite" in c:
                cookie_dict["sameSite"] = c["sameSite"]

            converted.append(cookie_dict)
        await self._context.add_cookies(converted)
        self._log(f"Injected {len(converted)} cookie(s) into context: {[c['name'] for c in converted]}")

    async def execute_js(self, script: str) -> Any:
        """Evaluates JavaScript expression in current page."""
        self._log(f"Evaluating DOM JavaScript: {script}")
        page = await self.get_page()
        self.last_action = f"EVALUATE_JS: {script}"
        res = await page.evaluate(script)
        await self._capture_latest_screenshot()
        res_preview = str(res)[:100] if res is not None else "undefined"
        self._log(f"JS Evaluation returned: {res_preview}")
        return res

    async def get_dom_text(self, selector: str = "body") -> str:
        """Extracts text content from a DOM selector."""
        page = await self.get_page()
        try:
            elem = await page.query_selector(selector)
            if elem:
                text = await elem.inner_text()
                self._log(f"Extracted DOM text from '{selector}' ({len(text)} chars)")
                return text
        except Exception as e:
            self._log(f"Failed extracting DOM text from '{selector}': {e}", level="WARNING")
        return ""

    async def take_screenshot(self, path: Optional[str] = None) -> bytes:
        """Captures page screenshot."""
        page = await self.get_page()
        kwargs = {"type": "png", "full_page": True}
        if path:
            kwargs["path"] = path
        data = await page.screenshot(**kwargs)
        self._log(f"Full-page screenshot captured ({round(len(data)/1024, 1)} KB)" + (f" -> {path}" if path else ""))
        return data

    async def close(self):
        """Clean teardown of browser, context, and Playwright session."""
        try:
            sid = self.session_id or "local"
            if self._active_page and not self._active_page.is_closed():
                await self._active_page.close()
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
            self._log(f"Closed browser context and terminated engine session ({sid})")
        except Exception as e:
            logger.debug(f"Error during TinyFishEngine close: {e}")
        finally:
            self._active_page = None
            self._context = None
            self._browser = None
            self._playwright = None
            self.engine_mode = "CLOSED"
