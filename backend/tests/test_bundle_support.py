"""Split-APK bundle (.apks/.xapk/.apkm) extraction and base-APK selection."""
import io
import json
import os
import zipfile

import pytest

from app.utils import file_utils as fu

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "sample_apks", "InsecureShop.apk")

pytestmark = pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="sample APK missing")


def _dummy_split() -> bytes:
    # A split APK: zip with a (non-binary) manifest; androguard fails to parse it,
    # which must not make it the base.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"not-a-binary-manifest")
        z.writestr("lib/arm64-v8a/libdummy.so", b"\x7fELF")
    return buf.getvalue()


def _make_bundle(path, extra=None):
    with zipfile.ZipFile(path, "w") as z:
        z.write(SAMPLE, "base.apk")
        z.writestr("split_config.arm64_v8a.apk", _dummy_split())
        for name, data in (extra or {}).items():
            z.writestr(name, data)


def test_extension_helpers():
    for n in ("a.apk", "a.XAPK", "a.apks", "a.apkm"):
        assert fu.is_allowed_upload(n)
    assert not fu.is_allowed_upload("a.zip")
    assert fu.is_bundle_filename("x.apks") and not fu.is_bundle_filename("x.apk")


def test_extract_and_base_selection(tmp_path):
    bundle = tmp_path / "app.apks"
    _make_bundle(bundle)
    assert fu.is_valid_bundle(str(bundle))

    info = fu.extract_bundle(str(bundle), str(tmp_path))
    assert info["base_apk"] == "bundle/base.apk"
    assert info["splits"] == ["bundle/split_config.arm64_v8a.apk"]
    assert info["package_name"] == "com.insecureshop"
    assert info["format"] == "apks"

    splits_json = tmp_path / "bundle" / "splits.json"
    assert json.loads(splits_json.read_text())["base_apk"] == "bundle/base.apk"

    base = fu.resolve_analysis_apk(str(tmp_path), "app.apks")
    assert os.path.samefile(base, tmp_path / "bundle" / "base.apk")
    assert fu.resolve_analysis_apk(str(tmp_path), "bundle/base.apk") == os.path.join(str(tmp_path), "bundle/base.apk")

    splits = fu.get_split_apks(base)
    assert len(splits) == 1 and splits[0].endswith("split_config.arm64_v8a.apk")
    assert fu.get_split_apks(SAMPLE) == []


def test_path_traversal_rejected(tmp_path):
    bundle = tmp_path / "evil.xapk"
    _make_bundle(bundle, {"../../escape.txt": b"x"})
    with pytest.raises(ValueError):
        fu.extract_bundle(str(bundle), str(tmp_path / "case"))
    assert not (tmp_path / "escape.txt").exists()


def test_non_bundle_rejected(tmp_path):
    p = tmp_path / "x.apks"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", b"hi")
    assert not fu.is_valid_bundle(str(p))
