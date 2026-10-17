"""HawkScan TinyFish Browser Automation Engine
Provides dual-mode browser execution:
1. TinyFish Cloud CDP connection (for remote/cloud application testing)
2. Local Headless Playwright Chromium (for offline, CI/CD, and loopback testing)

Automatically selects the optimal engine based on target URL and connectivity.
"""

import asyncio
import logging
import httpx
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
from hawkscan.config import settings

logger = logging.getLogger("hawkscan.tinyfish")


class TinyFishEngine:
    """Autonomous browser execution engine backed by TinyFish Cloud CDP and Playwright."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        headless: bool = True,
        target_url: Optional[str] = None,
    ):
        self.api_key = api_key if api_key is not None else settings.TINYFISH_API_KEY
        self.api_url = (api_url or settings.TINYFISH_API_URL).rstrip("/")
        self.headless = headless
        self.target_url = target_url or ""
        
        self.engine_mode: str = "UNINITIALIZED"
        self.session_id: Optional[str] = None
        self.cdp_url: Optional[str] = None
        self.base_url: Optional[str] = None
        self.active_url: str = self.target_url
        self.last_action: str = "READY"
        self.last_screenshot_b64: Optional[str] = None

        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._active_page: Optional[Page] = None

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

    async def start(self, target_url: Optional[str] = None) -> str:
        """Initializes the browser session using TinyFish Cloud or Local Playwright."""
        url = target_url or self.target_url
        if url:
            self.target_url = url
            self.active_url = url
        self._playwright = await async_playwright().start()

        # Decide whether to use TinyFish Cloud or Local Playwright
        is_local_target = self._is_loopback(url)
        has_api_key = bool(self.api_key and self.api_key.strip())

        if has_api_key and not is_local_target:
            try:
                # Attempt connection to TinyFish Cloud CDP
                cdp_url = await self._acquire_tinyfish_cdp_url()
                if cdp_url:
                    self._browser = await self._playwright.chromium.connect_over_cdp(cdp_url)
                    self._context = await self._browser.new_context(
                        viewport={"width": 1280, "height": 800},
                        user_agent="HawkScan-TinyFish-Browser/1.0"
                    )
                    self.engine_mode = "TINYFISH_CLOUD"
                    self.last_action = "CONNECTED_TINYFISH_CLOUD"
                    return self.engine_mode
            except Exception as e:
                logger.warning(f"TinyFish Cloud CDP connection failed: {e}. Falling back to Local Playwright.")

        # Fallback to local Playwright Chromium
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
        return self.engine_mode

    async def _acquire_tinyfish_cdp_url(self) -> Optional[str]:
        """Queries TinyFish Cloud API to provision a CDP browser session."""
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(
                    self.api_url,
                    headers=headers,
                    json={"url": self.target_url or "https://www.tinyfish.ai"}
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    self.session_id = data.get("session_id")
                    self.cdp_url = data.get("cdp_url")
                    self.base_url = data.get("base_url")
                    return self.cdp_url
            except Exception as e:
                logger.warning(f"TinyFish session creation failed: {e}")

            # Fallback to direct websocket format if supported
            ws_url = f"{self.api_url.replace('http', 'ws')}/cdp?token={self.api_key}"
            return ws_url

    async def get_page(self) -> Page:
        """Retrieves or creates an active page."""
        if self._active_page is None or self._active_page.is_closed():
            if not self._context:
                await self.start()
            self._active_page = await self._context.new_page()
        return self._active_page

    async def navigate(self, url: str, wait_until: str = "domcontentloaded", timeout: int = 15000) -> bool:
        """Navigates the active page to the specified URL."""
        page = await self.get_page()
        try:
            self.last_action = f"NAVIGATE: {url}"
            self.active_url = url
            await page.goto(url, wait_until=wait_until, timeout=timeout)
            await self._capture_latest_screenshot()
            return True
        except Exception as e:
            logger.error(f"TinyFish navigation to {url} failed: {e}")
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

        return {
            "engine_mode": self.engine_mode,
            "session_id": self.session_id or ("local-playwright-session" if self.engine_mode == "LOCAL_PLAYWRIGHT" else "pending"),
            "cdp_url": self.cdp_url,
            "base_url": self.base_url,
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
        # Normalize fields
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
        # Convert snake_case to Playwright expected camelCase
        converted = []
        for c in cookies:
            cookie_dict = {
                "name": c["name"],
                "value": c["value"],
                "domain": c.get("domain", "127.0.0.1"),
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

    async def execute_js(self, script: str) -> Any:
        """Evaluates JavaScript expression in current page."""
        page = await self.get_page()
        self.last_action = f"EVALUATE_JS: {script}"
        res = await page.evaluate(script)
        await self._capture_latest_screenshot()
        return res

    async def get_dom_text(self, selector: str = "body") -> str:
        """Extracts text content from a DOM selector."""
        page = await self.get_page()
        try:
            elem = await page.query_selector(selector)
            if elem:
                return await elem.inner_text()
        except Exception:
            pass
        return ""

    async def take_screenshot(self, path: Optional[str] = None) -> bytes:
        """Captures page screenshot."""
        page = await self.get_page()
        kwargs = {"type": "png", "full_page": True}
        if path:
            kwargs["path"] = path
        return await page.screenshot(**kwargs)

    async def close(self):
        """Clean teardown of browser, context, and Playwright session."""
        try:
            if self._active_page and not self._active_page.is_closed():
                await self._active_page.close()
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception as e:
            logger.debug(f"Error during TinyFishEngine close: {e}")
        finally:
            self._active_page = None
            self._context = None
            self._browser = None
            self._playwright = None
            self.engine_mode = "CLOSED"
