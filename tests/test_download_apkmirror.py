import gzip
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))
import download_apkmirror as am


SAMPLE_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <item>
      <title>Google Play Store 54.4.11</title>
      <link>https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/</link>
    </item>
    <item>
      <title>Google Play Store 54.4.10</title>
      <link>https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-10-release/</link>
    </item>
  </channel>
</rss>
"""

SAMPLE_RELEASE_HTML = """
<div class="table-row headerFont">
  <a class="accent_color" href="/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-1-android-apk-download/">54.4.11</a>
  <span class="apkm-badge">BUNDLE</span>
  <div>arm64-v8a</div>
  <div>nodpi</div>
</div>
<div class="table-row headerFont">
  <a class="accent_color" href="/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-24-0-pr-2-android-apk-download/">54.4.11</a>
  <span class="apkm-badge">APK</span>
  <div>universal</div>
  <div>nodpi</div>
</div>
<div class="table-row headerFont">
  <a class="accent_color" href="/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-3-android-apk-download/">54.4.11</a>
  <span class="apkm-badge">APK</span>
  <div>universal</div>
  <div>nodpi</div>
</div>
<div class="table-row headerFont">
  <a class="accent_color" href="/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-4-android-apk-download/">54.4.11</a>
  <span class="apkm-badge">APK</span>
  <div>x86_64</div>
  <div>nodpi</div>
</div>
<div class="widget"></div>
"""

SAMPLE_VARIANT_HTML = """
<a rel="nofollow" class="accent_bg btn btn-flat downloadButton zxE"
   href="/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-3-android-apk-download/download/?key=abc&amp;forcebaseapk=true">
   Download APK
</a>
"""

SAMPLE_DL_PAGE_HTML = """
<a id="download-link" rel="nofollow"
   href="/wp-content/themes/APKMirror/download.php?id=123&amp;key=def&amp;forcebaseapk=true">here</a>
"""


class _FakeResponse:
    def __init__(self, payload: bytes):
        self._buf = io.BytesIO(payload)

    def read(self, size: int = -1) -> bytes:
        return self._buf.read(size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeOpener(urllib.request.OpenerDirector):
    def __init__(self, routes: dict[str, bytes]):
        self.routes = routes
        self.seen_urls: list[str] = []

    def open(self, req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        self.seen_urls.append(url)
        if url not in self.routes:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return _FakeResponse(self.routes[url])


class ApkMirrorTests(unittest.TestCase):
    def test_parsers_skip_bundle_and_pick_highest_compatible_apk(self):
        releases = am.extract_release_urls_from_feed(SAMPLE_FEED)
        self.assertEqual(
            releases[0],
            "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/",
        )
        chosen = am.select_variant_url(SAMPLE_RELEASE_HTML, target_sdk=36)
        self.assertEqual(
            chosen,
            "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-3-android-apk-download/",
        )
        # When target SDK is 28, prefer the compatible 24-0-pr standalone APK over 34-0-pr.
        chosen_older = am.select_variant_url(SAMPLE_RELEASE_HTML, target_sdk=28)
        self.assertEqual(
            chosen_older,
            "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-24-0-pr-2-android-apk-download/",
        )

        btn = am.extract_download_button_url(SAMPLE_VARIANT_HTML)
        self.assertEqual(
            btn,
            "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-3-android-apk-download/download/?key=abc&forcebaseapk=true",
        )
        direct = am.extract_direct_download_url(SAMPLE_DL_PAGE_HTML)
        self.assertEqual(
            direct,
            "https://www.apkmirror.com/wp-content/themes/APKMirror/download.php?id=123&key=def&forcebaseapk=true",
        )

    def test_download_from_apkmirror_end_to_end_and_rejects_bundle_zip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk_buf = io.BytesIO()
            with zipfile.ZipFile(apk_buf, "w") as zf:
                zf.writestr("AndroidManifest.xml", "<manifest package='com.android.vending'/>")
                zf.writestr("classes.dex", b"0" * 70000)

            opener = _FakeOpener(
                {
                    am.APP_SOURCES["phonesky"].feed_urls[0]: SAMPLE_FEED.encode("utf-8"),
                    "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/": SAMPLE_RELEASE_HTML.encode("utf-8"),
                    "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-3-android-apk-download/": SAMPLE_VARIANT_HTML.encode("utf-8"),
                    "https://www.apkmirror.com/apk/google-inc/google-play-store/google-play-store-54-4-11-release/google-play-store-54-4-11-34-0-pr-3-android-apk-download/download/?key=abc&forcebaseapk=true": SAMPLE_DL_PAGE_HTML.encode("utf-8"),
                    "https://www.apkmirror.com/wp-content/themes/APKMirror/download.php?id=123&key=def&forcebaseapk=true": apk_buf.getvalue(),
                }
            )
            dest = root / "Phonesky.apk"
            saved = am.download_from_apkmirror(
                "phonesky", dest, target_sdk=36, min_bytes=65536, opener=opener
            )
            self.assertEqual(saved, dest)
            self.assertTrue(dest.is_file())
            with zipfile.ZipFile(dest, "r") as zf:
                self.assertIn("AndroidManifest.xml", zf.namelist())

            # A bundle zip without AndroidManifest.xml must be rejected.
            bundle_path = root / "bundle.apkm"
            with zipfile.ZipFile(bundle_path, "w") as zf:
                zf.writestr("info.json", "{}")
                zf.writestr("base.apk", b"x" * 70000)
            with self.assertRaises(ValueError):
                am.verify_standalone_apk(bundle_path, min_bytes=1024)

    def test_fetch_text_decompresses_gzip_payload(self):
        feed_url = "https://www.apkmirror.com/apk/test/feed/"
        gz_payload = gzip.compress(SAMPLE_FEED.encode("utf-8"))
        opener = _FakeOpener({feed_url: gz_payload})
        text = am.fetch_text(opener, feed_url)
        self.assertIn("Google Play Store 54.4.11", text)

    def test_403_short_circuits_after_two_forbidden_releases(self):
        many_releases = "\n".join(
            f"<item><link>https://www.apkmirror.com/apk/g/app/rel-{i}-release/</link></item>"
            for i in range(6)
        )
        rss = f'<?xml version="1.0"?><rss><channel>{many_releases}</channel></rss>'

        class _ForbiddenOpener(_FakeOpener):
            def open(self, req, timeout=None):
                url = req.full_url if hasattr(req, "full_url") else str(req)
                self.seen_urls.append(url)
                if url == am.APP_SOURCES["via"].feed_urls[0]:
                    return _FakeResponse(rss.encode("utf-8"))
                raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

        opener = _ForbiddenOpener({})
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(RuntimeError) as ctx:
                am.download_from_apkmirror("via", Path(td) / "Via.apk", opener=opener)
        self.assertIn("403", str(ctx.exception))
        # 1 feed request + 2 release requests before failing fast
        self.assertEqual(len(opener.seen_urls), 3)

    def test_switches_to_curl_transport_on_403_when_no_custom_opener(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "Via.apk"
            apk_buf = io.BytesIO()
            with zipfile.ZipFile(apk_buf, "w") as zf:
                zf.writestr("AndroidManifest.xml", "<manifest package='mark.via.gp'/>")
                zf.writestr("classes.dex", b"a" * 70000)

            class _UrllibForbiddenOpener(urllib.request.OpenerDirector):
                def open(self, req, timeout=None):
                    url = req.full_url if hasattr(req, "full_url") else str(req)
                    raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

            def _fake_curl(cmd, capture_output=True, text=True, check=False):
                url = cmd[-1]
                out_path = None
                if "-o" in cmd:
                    out_path = Path(cmd[cmd.index("-o") + 1])
                if out_path is not None:
                    out_path.write_bytes(apk_buf.getvalue())
                    return mock.Mock(returncode=0, stdout="", stderr="")
                if url.endswith("/feed/"):
                    return mock.Mock(returncode=0, stdout=SAMPLE_FEED, stderr="")
                if url.endswith("-release/"):
                    return mock.Mock(returncode=0, stdout=SAMPLE_RELEASE_HTML, stderr="")
                if url.endswith("-android-apk-download/"):
                    return mock.Mock(returncode=0, stdout=SAMPLE_VARIANT_HTML, stderr="")
                if "download/?key=" in url:
                    return mock.Mock(returncode=0, stdout=SAMPLE_DL_PAGE_HTML, stderr="")
                return mock.Mock(returncode=22, stdout="", stderr="404")

            with (
                mock.patch.object(am, "build_opener", return_value=_UrllibForbiddenOpener()),
                mock.patch.object(am.shutil, "which", return_value="/usr/bin/curl"),
                mock.patch.object(am.subprocess, "run", side_effect=_fake_curl),
            ):
                saved = am.download_from_apkmirror("phonesky", dest, target_sdk=36, min_bytes=65536)

            self.assertEqual(saved, dest)
            self.assertTrue(dest.is_file())


if __name__ == "__main__":
    unittest.main()
