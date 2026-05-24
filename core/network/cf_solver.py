import asyncio
import logging
from typing import Optional, Dict

logger = logging.getLogger("cf_solver")

CF_COOKIES = {"cf_clearance", "__cf_bm", "__cfduid"}
BROWSER_TIMEOUT = 45


async def solve_challenge(target_url: str, headless: bool = True,
                          timeout: int = BROWSER_TIMEOUT) -> Optional[Dict[str, str]]:
    """Open a real browser, wait for Cloudflare challenge to clear, return cookies."""
    try:
        import nodriver as uc
    except ImportError:
        logger.error("nodriver not installed. Run: pip install nodriver")
        return None

    browser = None
    try:
        browser = await uc.start(headless=headless, browser_executable_path=None)
        page = await browser.get(target_url)
        logger.info("Browser opened: %s (headless=%s)", target_url, headless)

        for second in range(timeout):
            await asyncio.sleep(1)
            try:
                title = await page.title()
                cookies = await page.cookies.all()
            except Exception:
                continue

            cf_cookies = {}
            for c in cookies:
                if c.name.lower() in CF_COOKIES:
                    cf_cookies[c.name] = c.value
            has_cf = "cf_clearance" in cf_cookies or "__cf_bm" in cf_cookies
            is_blocked = any(k in (title or "").lower() for k in
                             ["attention required", "just a moment", "cloudflare"])
            if has_cf and not is_blocked:
                logger.info("Challenge solved in %ds: %s", second + 1, list(cf_cookies.keys()))
                return cf_cookies
            if second % 5 == 0:
                logger.debug("Waiting... %ds title=%s", second + 1, title)

        logger.warning("Challenge timeout after %ds", timeout)
        try:
            cookies = await page.cookies.all()
            return {c.name: c.value for c in cookies if c.name.lower() in CF_COOKIES}
        except Exception:
            return {}
    except Exception as e:
        logger.error("Browser error: %s", str(e))
        return None
    finally:
        if browser:
            try:
                browser.stop()
            except Exception:
                pass


async def solve_and_inject(target_url: str, curl_session, headless: bool = True) -> bool:
    """Solve CF challenge and inject cookies into a curl_cffi session."""
    cookies = await solve_challenge(target_url, headless=headless)
    if not cookies:
        return False
    for name, value in cookies.items():
        curl_session.cookies.set(name, value)
    logger.info("Injected %d cookies into session", len(cookies))
    return True
