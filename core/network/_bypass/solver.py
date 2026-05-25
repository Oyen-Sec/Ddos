import asyncio
import logging
import subprocess
import sys
from typing import Optional, Dict

logger = logging.getLogger("cf_solver")

CF_COOKIES = {"cf_clearance", "__cf_bm", "__cfduid"}
BROWSER_TIMEOUT = 60


async def _ensure_nodriver() -> bool:
    try:
        import nodriver as uc
        return True
    except ImportError:
        logger.warning("nodriver not installed. Attempting auto-install...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "nodriver"],
                timeout=60
            )
            import nodriver as uc
            return True
        except Exception as e:
            logger.error(f"Auto-install failed: {e}")
            return False


async def solve_challenge(target_url: str, headless: bool = True,
                          timeout: int = BROWSER_TIMEOUT,
                          retries: int = 2) -> Optional[Dict[str, str]]:
    if not await _ensure_nodriver():
        return None

    import nodriver as uc

    for attempt in range(1, retries + 2):
        browser = None
        try:
            browser = await uc.start(headless=headless, browser_executable_path=None)
            page = await browser.get(target_url)
            logger.info("Browser opened: %s (headless=%s, attempt=%d)", target_url, headless, attempt)

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
                                 ["attention required", "just a moment", "cloudflare",
                                  "challenge", "security check"])
                if has_cf and not is_blocked:
                    logger.info("Challenge solved in %ds: %s", second + 1, list(cf_cookies.keys()))
                    return cf_cookies
                if second % 5 == 0:
                    logger.debug("Waiting... %ds title=%s", second + 1, title)

            logger.warning("Challenge timeout after %ds (attempt %d)", timeout, attempt)
            try:
                cookies = await page.cookies.all()
                result = {c.name: c.value for c in cookies if c.name.lower() in CF_COOKIES}
                if result:
                    return result
            except Exception:
                pass

        except Exception as e:
            logger.error("Browser error (attempt %d): %s", attempt, str(e))
            if attempt > retries:
                return None
        finally:
            if browser:
                try:
                    browser.stop()
                except Exception:
                    pass

    return None


async def solve_and_inject(target_url: str, curl_session, headless: bool = True) -> bool:
    cookies = await solve_challenge(target_url, headless=headless)
    if not cookies:
        return False
    for name, value in cookies.items():
        curl_session.cookies.set(name, value)
    logger.info("Injected %d cookies into session", len(cookies))
    return True