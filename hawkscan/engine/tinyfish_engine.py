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
        return self.engine_mode

    async def _acquire_tinyfish_cdp_url(self) -> Optional[str]:
        """Queries TinyFish Cloud API to provision a CDP browser session."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(timeout=8.0) as client:
            # 1. Try session creation endpoint
            try:
                resp = await client.post(
                    f"{self.api_url}/v1/sessions",
                    headers=headers,
                    json={"target": self.target_url, "options": {"headless": self.headless}}
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    return data.get("cdp_url") or data.get("ws_url")
            except Exception:
                pass

            # 2. Try direct websocket connection format
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
            await page.goto(url, wait_until=wait_until, timeout=timeout)
            return True
        except Exception as e:
            logger.error(f"TinyFish navigation to {url} failed: {e}")
            return False

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
        return await page.evaluate(script)

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
