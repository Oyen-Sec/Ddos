import asyncio
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp


@dataclass
class SEOTarget:
    url: str
    keywords: List[str]
    niche: str
    competitors: List[str]
    priority: int = 1


@dataclass
class SEOAuditPage:
    url: str
    status: int
    title: str
    meta_description_len: int
    canonical: str
    robots_meta: str
    h1_count: int
    internal_links: int
    external_links: int
    amp_url: str
    issues: List[str]


class SEOBackheart:
    def __init__(self, target: SEOTarget):
        self.target = target

    async def run(self) -> Dict:
        target_url = self._normalize_url(self.target.url)
        origin = urlparse(target_url).netloc.lower()

        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=self._headers()) as session:
            robots_text, robots_status = await self._fetch_text(session, urljoin(target_url, "/robots.txt"))
            sitemap_candidates = self._extract_sitemaps_from_robots(robots_text) if robots_text else []
            if not sitemap_candidates:
                sitemap_candidates = [urljoin(target_url, "/sitemap.xml")]

            sitemap_urls: List[str] = []
            for sm in sitemap_candidates[:3]:
                sm_text, sm_status = await self._fetch_text(session, sm)
                if sm_text and sm_status in (200, 301, 302):
                    sitemap_urls.extend(self._extract_urls_from_sitemap(sm_text))
                    if sitemap_urls:
                        break

            pages_to_audit = [target_url]
            if sitemap_urls:
                pages_to_audit.extend([u for u in sitemap_urls[:4] if u not in pages_to_audit])

            audited_pages: List[SEOAuditPage] = []
            for page_url in pages_to_audit:
                audited_pages.append(await self._audit_page(session, page_url, origin))

        return {
            "target": target_url,
            "robots_status": robots_status,
            "robots_has_sitemap": bool(sitemap_candidates),
            "sitemap_discovered_urls": len(sitemap_urls),
            "pages": [p.__dict__ for p in audited_pages],
        }

    async def _audit_page(self, session: aiohttp.ClientSession, page_url: str, origin: str) -> SEOAuditPage:
        issues: List[str] = []
        html, status = await self._fetch_text(session, page_url)

        if status not in (200, 301, 302):
            issues.append(f"status_{status}")
            return SEOAuditPage(
                url=page_url,
                status=status,
                title="",
                meta_description_len=0,
                canonical="",
                robots_meta="",
                h1_count=0,
                internal_links=0,
                external_links=0,
                amp_url="",
                issues=issues,
            )

        title = self._extract_title(html)
        if not title:
            issues.append("missing_title")

        desc = self._extract_meta(html, "description")
        desc_len = len(desc) if desc else 0
        if desc_len == 0:
            issues.append("missing_meta_description")
        elif desc_len < 50:
            issues.append("meta_description_too_short")
        elif desc_len > 170:
            issues.append("meta_description_too_long")

        canonical = self._extract_link_rel(html, "canonical")
        if not canonical:
            issues.append("missing_canonical")

        robots_meta = self._extract_meta(html, "robots")
        h1_count = len(re.findall(r"<h1\\b", html, flags=re.I))
        if h1_count == 0:
            issues.append("missing_h1")
        elif h1_count > 1:
            issues.append("multiple_h1")

        amp_url = self._extract_link_rel(html, "amphtml")

        internal_links, external_links = self._count_links(html, page_url, origin)
        if internal_links == 0:
            issues.append("no_internal_links")

        return SEOAuditPage(
            url=page_url,
            status=status,
            title=title,
            meta_description_len=desc_len,
            canonical=canonical,
            robots_meta=robots_meta,
            h1_count=h1_count,
            internal_links=internal_links,
            external_links=external_links,
            amp_url=amp_url,
            issues=issues,
        )

    async def _fetch_text(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, int]:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                ct = resp.headers.get("content-type", "")
                text = await resp.text(errors="ignore") if "text" in ct or "xml" in ct or "html" in ct else ""
                return text, resp.status
        except Exception:
            return "", 0

    def _normalize_url(self, url: str) -> str:
        url = url.strip()
        if not url:
            return url
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Connection": "keep-alive",
        }

    def _extract_title(self, html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.I | re.S)
        if not m:
            return ""
        title = re.sub(r"\\s+", " ", m.group(1)).strip()
        title = re.sub(r"<[^>]+>", "", title).strip()
        return title[:200]

    def _extract_meta(self, html: str, name: str) -> str:
        pattern = rf"<meta[^>]+name=[\"']{re.escape(name)}[\"'][^>]*content=[\"'](.*?)[\"'][^>]*>"
        m = re.search(pattern, html, flags=re.I | re.S)
        if not m:
            pattern2 = rf"<meta[^>]+content=[\"'](.*?)[\"'][^>]*name=[\"']{re.escape(name)}[\"'][^>]*>"
            m = re.search(pattern2, html, flags=re.I | re.S)
        if not m:
            return ""
        value = re.sub(r"\\s+", " ", m.group(1)).strip()
        return value[:500]

    def _extract_link_rel(self, html: str, rel: str) -> str:
        pattern = rf"<link[^>]+rel=[\"']{re.escape(rel)}[\"'][^>]*href=[\"'](.*?)[\"'][^>]*>"
        m = re.search(pattern, html, flags=re.I | re.S)
        if not m:
            pattern2 = rf"<link[^>]+href=[\"'](.*?)[\"'][^>]*rel=[\"']{re.escape(rel)}[\"'][^>]*>"
            m = re.search(pattern2, html, flags=re.I | re.S)
        return m.group(1).strip()[:500] if m else ""

    def _count_links(self, html: str, base_url: str, origin: str) -> Tuple[int, int]:
        hrefs = re.findall(r"href=[\"'](.*?)[\"']", html, flags=re.I)
        internal = 0
        external = 0
        for h in hrefs[:3000]:
            if not h or h.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            abs_url = urljoin(base_url, h)
            netloc = urlparse(abs_url).netloc.lower()
            if not netloc:
                continue
            if netloc == origin:
                internal += 1
            else:
                external += 1
        return internal, external

    def _extract_sitemaps_from_robots(self, robots: str) -> List[str]:
        urls = []
        for line in robots.splitlines():
            if line.lower().startswith("sitemap:"):
                u = line.split(":", 1)[1].strip()
                if u:
                    urls.append(u)
        return urls

    def _extract_urls_from_sitemap(self, xml: str) -> List[str]:
        return [m.group(1).strip() for m in re.finditer(r"<loc>(.*?)</loc>", xml, flags=re.I | re.S)]


__all__ = ["SEOTarget", "SEOBackheart", "SEOAuditPage"]
