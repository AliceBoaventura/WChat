#!/usr/bin/env python3
"""Generate a minimal APK using the provided classes.dex payload.

The script reconstructs a binary AndroidManifest.xml containing a launcher
activity that points at the MainTabUI class from the bundled classes.dex file.
It then packages the manifest together with the dex file and signs the result
with a debug keystore so the APK can be installed on devices that accept
self-signed debug builds.

The environment used for this repository does not provide the Android SDK, so
we build the manifest by hand following the Android binary XML specification.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

# Android XML / APK constants
RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
DATA_TYPE_STRING = 0x03
ANDROID_NAME_RESOURCE_ID = 0x01010003

def encode_length(value: int) -> bytes:
    """Encode a string length using the variable-length format used by AXML."""
    if value < 0 or value > 0x3FFF:
        raise ValueError("value out of range for 1- or 2-byte encoding")
    if value <= 0x7F:
        return bytes([value])
    return bytes([(value & 0x7F) | 0x80, value >> 7])

def build_string_pool(strings: list[str]) -> tuple[bytes, dict[str, int]]:
    header_size = 28
    flags_utf8 = 0x00000100
    offsets: list[int] = []
    body = bytearray()
    for text in strings:
        encoded = text.encode("utf-8")
        offsets.append(len(body))
        body += encode_length(len(text))
        body += encode_length(len(encoded))
        body += encoded + b"\x00"
    while len(body) % 4:
        body += b"\x00"
    strings_start = header_size + len(strings) * 4
    chunk_size = strings_start + len(body)
    header = struct.pack("<HHI", RES_STRING_POOL_TYPE, header_size, chunk_size)
    chunk = bytearray(header)
    chunk += struct.pack("<IIIII", len(strings), 0, flags_utf8, strings_start, 0)
    for offset in offsets:
        chunk += struct.pack("<I", offset)
    chunk += body
    mapping = {text: index for index, text in enumerate(strings)}
    return bytes(chunk), mapping

def build_resource_map(resource_ids: list[int]) -> bytes:
    header_size = 8
    chunk_size = header_size + 4 * len(resource_ids)
    chunk = struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE, header_size, chunk_size)
    for res_id in resource_ids:
        chunk += struct.pack("<I", res_id)
    return chunk

def namespace_chunk(chunk_type: int, prefix_index: int, uri_index: int) -> bytes:
    header_size = 0x18
    chunk_size = header_size
    return (
        struct.pack("<HHI", chunk_type, header_size, chunk_size)
        + struct.pack("<II", 0, 0)
        + struct.pack("<II", prefix_index, uri_index)
    )

def start_element_chunk(
    ns_index: int | None,
    name_index: int,
    attributes: list[tuple[int | None, int, int, tuple[int, int]]],
) -> bytes:
    header_size = 0x24
    attribute_size = 0x14
    chunk_size = header_size + attribute_size * len(attributes)
    chunk = bytearray()
    chunk += struct.pack("<HHI", RES_XML_START_ELEMENT_TYPE, header_size, chunk_size)
    chunk += struct.pack("<II", 0, 0)
    chunk += struct.pack("<II", ns_index if ns_index is not None else 0xFFFFFFFF, name_index)
    chunk += struct.pack("<HHHHHH", 0x14, 0x14, len(attributes), 0, 0, 0)
    for attr_ns, attr_name, raw_index, (data_type, data_value) in attributes:
        chunk += struct.pack("<I", attr_ns if attr_ns is not None else 0xFFFFFFFF)
        chunk += struct.pack("<I", attr_name)
        chunk += struct.pack("<I", raw_index if raw_index is not None else 0xFFFFFFFF)
        chunk += struct.pack("<HBBI", 8, 0, data_type, data_value)
    return bytes(chunk)

def end_element_chunk(ns_index: int | None, name_index: int) -> bytes:
    header_size = 0x18
    chunk_size = header_size
    return (
        struct.pack("<HHI", RES_XML_END_ELEMENT_TYPE, header_size, chunk_size)
        + struct.pack("<II", 0, 0)
        + struct.pack("<II", ns_index if ns_index is not None else 0xFFFFFFFF, name_index)
    )

def build_manifest() -> bytes:
    strings = [
        "manifest",
        "http://schemas.android.com/apk/res/android",
        "android",
        "package",
        "application",
        "activity",
        "intent-filter",
        "action",
        "category",
        "name",
        "com.tencent.mm",
        "com.tencent.mm.ui.MainTabUI",
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
    ]
    string_pool, indexes = build_string_pool(strings)
    res_map = build_resource_map([ANDROID_NAME_RESOURCE_ID])
    ns_uri = indexes["http://schemas.android.com/apk/res/android"]
    ns_prefix = indexes["android"]
    manifest = [string_pool, res_map]
    manifest.append(namespace_chunk(RES_XML_START_NAMESPACE_TYPE, ns_prefix, ns_uri))
    manifest.append(
        start_element_chunk(
            None,
            indexes["manifest"],
            [
                (
                    None,
                    indexes["package"],
                    indexes["com.tencent.mm"],
                    (DATA_TYPE_STRING, indexes["com.tencent.mm"]),
                )
            ],
        )
    )
    manifest.append(start_element_chunk(None, indexes["application"], []))
    manifest.append(
        start_element_chunk(
            ns_uri,
            indexes["activity"],
            [
                (
                    ns_uri,
                    indexes["name"],
                    indexes["com.tencent.mm.ui.MainTabUI"],
                    (DATA_TYPE_STRING, indexes["com.tencent.mm.ui.MainTabUI"]),
                )
            ],
        )
    )
    manifest.append(start_element_chunk(None, indexes["intent-filter"], []))
    manifest.append(
        start_element_chunk(
            ns_uri,
            indexes["action"],
            [
                (
                    ns_uri,
                    indexes["name"],
                    indexes["android.intent.action.MAIN"],
                    (DATA_TYPE_STRING, indexes["android.intent.action.MAIN"]),
                )
            ],
        )
    )
    manifest.append(end_element_chunk(ns_uri, indexes["action"]))
    manifest.append(
        start_element_chunk(
            ns_uri,
            indexes["category"],
            [
                (
                    ns_uri,
                    indexes["name"],
                    indexes["android.intent.category.LAUNCHER"],
                    (DATA_TYPE_STRING, indexes["android.intent.category.LAUNCHER"]),
                )
            ],
        )
    )
    manifest.append(end_element_chunk(ns_uri, indexes["category"]))
    manifest.append(end_element_chunk(None, indexes["intent-filter"]))
    manifest.append(end_element_chunk(ns_uri, indexes["activity"]))
    manifest.append(end_element_chunk(None, indexes["application"]))
    manifest.append(end_element_chunk(None, indexes["manifest"]))
    manifest.append(namespace_chunk(RES_XML_END_NAMESPACE_TYPE, ns_prefix, ns_uri))
    payload = b"".join(manifest)
    header = struct.pack("<HHI", RES_XML_TYPE, 8, len(payload) + 8)
    return header + payload

def sign_apk(apk_path: Path, keystore: Path, alias: str = "androiddebugkey") -> None:
    subprocess.run(
        [
            "jarsigner",
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-keypass",
            "android",
            str(apk_path),
            alias,
        ],
        check=True,
    )

def ensure_debug_keystore(keystore: Path) -> None:
    if keystore.exists():
        return
    subprocess.run(
        [
            "keytool",
            "-genkeypair",
            "-v",
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-keypass",
            "android",
            "-alias",
            "androiddebugkey",
            "-dname",
            "CN=Android Debug,O=Android,C=US",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
        ],
        check=True,
    )

def build_apk(output: Path, dex_path: Path) -> None:
    manifest_bytes = build_manifest()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        manifest_path = tmp_dir / "AndroidManifest.xml"
        manifest_path.write_bytes(manifest_bytes)
        with ZipFile(output, "w", ZIP_DEFLATED) as zf:
            zf.write(manifest_path, arcname="AndroidManifest.xml")
            zf.write(dex_path, arcname="classes.dex")
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"Created {output} (sha256 {checksum})")

def main() -> None:
    parser = argparse.ArgumentParser(description="Build a debug APK from classes.dex")
    parser.add_argument(
        "--dex",
        default="classes.dex",
        type=Path,
        help="Path to the dex payload (default: classes.dex in repo root)",
    )
    parser.add_argument(
        "--output",
        default="app-debug.apk",
        type=Path,
        help="Where to write the signed APK",
    )
    parser.add_argument(
        "--keystore",
        default=Path("debug.keystore"),
        type=Path,
        help="Debug keystore used for signing (created if missing)",
    )
    args = parser.parse_args()

    if not args.dex.exists():
        raise SystemExit(f"Dex payload not found: {args.dex}")
    build_apk(args.output, args.dex)
    ensure_debug_keystore(args.keystore)
    sign_apk(args.output, args.keystore)
    print(f"Signed APK written to {args.output}")

if __name__ == "__main__":
    main()