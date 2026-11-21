#!/usr/bin/env python3
"""Download standalone APKMirror releases (Phonesky, Via) using Python stdlib."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import html
import http.cookiejar
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

APKMIRROR_BASE = "https://www.apkmirror.com"


@dataclass(frozen=True)
class AppSource:
    slug: str
    feed_urls: tuple[str, ...]
    page_urls: tuple[str, ...]
    expected_package: str | None = None


APP_SOURCES: dict[str, AppSource] = {
    "phonesky": AppSource(
        slug="/apk/google-inc/google-play-store/",
        feed_urls=("https://www.apkmirror.com/apk/google-inc/google-play-store/feed/",),
        page_urls=("https://www.apkmirror.com/apk/google-inc/google-play-store/",),
        expected_package="com.android.vending",
    ),
    "via": AppSource(
        slug="/apk/tu-yafeng/via-browser-fast-light-geek-best-choice/",
        feed_urls=(
            "https://www.apkmirror.com/apk/tu-yafeng/via-browser-fast-light-geek-best-choice/feed/",
            "https://www.apkmirror.com/apk/yafeng-tu/via/feed/",
        ),
        page_urls=(
            "https://www.apkmirror.com/apk/tu-yafeng/via-browser-fast-light-geek-best-choice/",
            "https://www.apkmirror.com/apk/yafeng-tu/via/",
        ),
        expected_package=None,
    ),
}

_ANDROID_VER_TO_SDK = {
    "4.4": 19,
    "5.0": 21,
    "6.0": 23,
    "7.0": 24,
    "8.0": 26,
    "9": 28,
    "10": 29,
    "11": 30,
    "12": 31,
    "13": 33,
    "14": 34,
    "15": 35,
    "16": 36,
    "17": 37,
}


def build_opener() -> urllib.request.OpenerDirector:
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def fetch_text(
    opener: urllib.request.OpenerDirector,
    url: str,
    *,
    referer: str | None = None,
    timeout: int = 30,
) -> str:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if referer:
        headers["Referer"] = referer
    req = urllib.request.Request(url, headers=headers)
    with opener.open(req, timeout=timeout) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


def download_binary(
    opener: urllib.request.OpenerDirector,
    url: str,
    dest: Path,
    *,
    referer: str | None = None,
    min_bytes: int = 65536,
    timeout: int = 240,
) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest.with_name(f"{dest.name}.tmp.{os.getpid()}")
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }
    if referer:
        headers["Referer"] = referer
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp, tmp_path.open("wb") as out:
            while True:
                chunk = resp.read(262144)
                if not chunk:
                    break
                out.write(chunk)
        verify_standalone_apk(tmp_path, min_bytes=min_bytes)
        os.replace(tmp_path, dest)
        return dest
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def verify_standalone_apk(path: Path, min_bytes: int = 65536) -> None:
    if not path.is_file():
        raise ValueError(f"Downloaded file missing: {path}")
    size = path.stat().st_size
    if size < min_bytes:
        raise ValueError(f"Downloaded APK too small ({size} < {min_bytes} bytes): {path}")
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                raise ValueError(f"Archive is not a standalone APK (missing AndroidManifest.xml): {path}")
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Downloaded file is not a valid APK zip: {exc}") from exc


def extract_release_urls_from_feed(rss_xml: str, limit: int = 8) -> list[str]:
    root = ET.fromstring(rss_xml)
    urls: list[str] = []
    seen: set[str] = set()
    for item in root.findall("./channel/item"):
        link_el = item.find("link")
        if link_el is None or not link_el.text:
            continue
        url = link_el.text.strip()
        if url.endswith("-release/") and url not in seen:
            seen.add(url)
            urls.append(url)
            if len(urls) >= limit:
                break
    return urls


def extract_release_urls_from_html(page_html: str, limit: int = 8) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(r'href="(/apk/[^"]+-release/)"', page_html):
        full = urllib.parse.urljoin(APKMIRROR_BASE, html.unescape(match.group(1)))
        if full not in seen:
            seen.add(full)
            urls.append(full)
            if len(urls) >= limit:
                break
    return urls


def _extract_row_blocks(release_html: str) -> list[str]:
    marker = '<div class="table-row headerFont">'
    parts = release_html.split(marker)
    if len(parts) <= 1:
        return []
    blocks: list[str] = []
    for chunk in parts[1:]:
        # Trim at closing container markers so unrelated links after table don't leak in.
        end_idx = chunk.find('<div class="widget')
        blocks.append(chunk if end_idx == -1 else chunk[:end_idx])
    return blocks


def _parse_row_sdk_hint(row_html: str, href: str) -> int | None:
    m_href = re.search(r"-(\d{2})-0-pr-", href)
    if m_href:
        return int(m_href.group(1))
    m_text = re.search(r"Android\s+(\d+(?:\.\d+)?)\+", row_html, re.IGNORECASE)
    if m_text:
        return _ANDROID_VER_TO_SDK.get(m_text.group(1))
    return None


def select_variant_url(release_html: str, *, target_sdk: int = 35) -> str | None:
    """Pick the highest-scoring standalone APK variant (strictly skipping BUNDLE)."""
    best_score = -10_000
    best_url: str | None = None

    for row in _extract_row_blocks(release_html):
        href_match = re.search(r'href="(/apk/[^"]+-download/)"', row)
        if not href_match:
            continue
        badge_match = re.search(r'apkm-badge[^>]*>([^<]+)<', row)
        badge = badge_match.group(1).strip().upper() if badge_match else "APK"
        if badge == "BUNDLE" or "BUNDLE" in badge:
            continue

        href = html.unescape(href_match.group(1))
        row_lower = row.lower()

        if "x86_64" in row_lower or re.search(r'\bx86\b', row_lower):
            continue
        if "armeabi-v7a" in row_lower and "arm64-v8a" not in row_lower and "universal" not in row_lower:
            continue

        score = 100
        if "arm64-v8a" in row_lower:
            score += 40
        elif "universal" in row_lower or "noarch" in row_lower:
            score += 30

        if "nodpi" in row_lower:
            score += 10

        sdk_hint = _parse_row_sdk_hint(row, href)
        if sdk_hint is not None:
            if sdk_hint > target_sdk:
                score -= 200
            else:
                score += sdk_hint

        if score > best_score:
            best_score = score
            best_url = urllib.parse.urljoin(APKMIRROR_BASE, href)

    return best_url


def extract_download_button_url(variant_html: str) -> str | None:
    patterns = (
        r'<a[^>]*class="[^"]*downloadButton[^"]*"[^>]*href="([^"]+)"',
        r'href="(/apk/[^"]+/download/\?key=[^"]+)"',
    )
    for pat in patterns:
        m = re.search(pat, variant_html, re.IGNORECASE)
        if m:
            return urllib.parse.urljoin(APKMIRROR_BASE, html.unescape(m.group(1)))
    return None


def extract_direct_download_url(dl_page_html: str) -> str | None:
    patterns = (
        r'id="download-link"[^>]*href="([^"]*download\.php[^"]*)"',
        r'href="([^"]*wp-content/themes/APKMirror/download\.php[^"]*)"',
    )
    for pat in patterns:
        m = re.search(pat, dl_page_html, re.IGNORECASE)
        if m:
            return urllib.parse.urljoin(APKMIRROR_BASE, html.unescape(m.group(1)))
    return None


def download_from_apkmirror(
    app: str,
    output: Path,
    *,
    target_sdk: int = 35,
    min_bytes: int = 65536,
    opener: urllib.request.OpenerDirector | None = None,
) -> Path:
    if app not in APP_SOURCES:
        raise ValueError(f"Unsupported APKMirror app key: {app}")
    src = APP_SOURCES[app]
    client = opener or build_opener()

    release_urls: list[str] = []
    for feed_url in src.feed_urls:
        try:
            rss_text = fetch_text(client, feed_url)
            release_urls.extend(extract_release_urls_from_feed(rss_text))
            if release_urls:
                break
        except Exception:
            continue

    if not release_urls:
        for page_url in src.page_urls:
            try:
                page_html = fetch_text(client, page_url)
                release_urls.extend(extract_release_urls_from_html(page_html))
                if release_urls:
                    break
            except Exception:
                continue

    if not release_urls:
        raise RuntimeError(f"No APKMirror releases found for {app}")

    last_error: Exception | None = None
    for rel_url in release_urls[:6]:
        try:
            rel_html = fetch_text(client, rel_url)
            variant_url = select_variant_url(rel_html, target_sdk=target_sdk)
            if not variant_url:
                continue
            variant_html = fetch_text(client, variant_url, referer=rel_url)
            btn_url = extract_download_button_url(variant_html)
            if not btn_url:
                continue
            dl_page_html = fetch_text(client, btn_url, referer=variant_url)
            direct_url = extract_direct_download_url(dl_page_html)
            if not direct_url:
                continue
            return download_binary(
                client,
                direct_url,
                output,
                referer=btn_url,
                min_bytes=min_bytes,
            )
        except Exception as exc:
            last_error = exc
            continue

    raise RuntimeError(f"Failed to download standalone APK for {app} from APKMirror: {last_error}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, choices=sorted(APP_SOURCES))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-sdk", type=int, default=35)
    parser.add_argument("--min-bytes", type=int, default=65536)
    args = parser.parse_args(argv)
    try:
        saved = download_from_apkmirror(
            args.app,
            args.output,
            target_sdk=args.target_sdk,
            min_bytes=args.min_bytes,
        )
        print(f"Downloaded {args.app} APK from APKMirror: {saved}")
        return 0
    except Exception as exc:
        print(f"APKMirror download error ({args.app}): {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
