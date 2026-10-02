import os
import shutil
import struct
import zipfile

import pytest

from app.utils.apk_repair import is_apk_tampered, repair_and_sign_apk

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "sample_apks", "InsecureShop.apk")


def _set_fake_encryption_flag(path: str, member: str) -> None:
    """Set the 'encrypted' general-purpose bit on a member in both the local header
    and the central directory — the anti-analysis trick used by real Android malware."""
    data = bytearray(open(path, "rb").read())
    name = member.encode()
    # Local file headers (PK\x03\x04): flag at offset 6, name length at 26, name at 30
    i = 0
    while (i := data.find(b"PK\x03\x04", i)) != -1:
        n = struct.unpack_from("<H", data, i + 26)[0]
        if data[i + 30:i + 30 + n] == name:
            data[i + 6] |= 1
        i += 4
    # Central directory headers (PK\x01\x02): flag at offset 8, name length at 28, name at 46
    i = 0
    while (i := data.find(b"PK\x01\x02", i)) != -1:
        n = struct.unpack_from("<H", data, i + 28)[0]
        if data[i + 46:i + 46 + n] == name:
            data[i + 8] |= 1
        i += 4
    open(path, "wb").write(bytes(data))


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample APK not present")
def test_detects_and_repairs_fake_encryption(tmp_path):
    clean = tmp_path / "clean.apk"
    shutil.copy(SAMPLE, clean)
    assert is_apk_tampered(str(clean))[0] is False

    tampered = tmp_path / "tampered.apk"
    shutil.copy(SAMPLE, tampered)
    _set_fake_encryption_flag(str(tampered), "AndroidManifest.xml")

    is_tampered, members = is_apk_tampered(str(tampered))
    assert is_tampered is True
    assert "AndroidManifest.xml" in members

    repaired = repair_and_sign_apk(str(tampered), str(tmp_path / "repaired.apk"))
    assert repaired and os.path.exists(repaired)
    assert is_apk_tampered(repaired)[0] is False
    with zipfile.ZipFile(repaired) as z:
        assert z.read("AndroidManifest.xml")  # readable again
