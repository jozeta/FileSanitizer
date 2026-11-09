"""
Additional identification / content-sniffing use cases and edge cases.

Covers magic-bytes-over-extension precedence, the empty/tiny-file shellcode
false-positive regression, the email-vs-markup boundary (FS-DET-001), and that
genuine shellcode is still detected. Expectations were captured from the actual
analyzer behaviour, not assumed.
"""

import tempfile
from pathlib import Path

import pytest

from app.analyzers.identification import detect_file_type
from app.analyzers.shellcode_analyzer import ShellcodeAnalyzer


def _f(data: bytes, name: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix="fs_ident_"))
    p = d / name
    p.write_bytes(data)
    return p


# --- Magic bytes win over a misleading extension -------------------------------

@pytest.mark.parametrize("name,data,expected_cat", [
    ("elf_as_pdf.pdf", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64, "executable"),
    ("pdf_as_txt.txt", b"%PDF-1.7\n1 0 obj<<>>endobj\n", "pdf"),
    ("gif_as_dat.dat", b"GIF89a" + b"\x00" * 32, "image"),
    ("zip_as_pdf.pdf", b"PK\x03\x04" + b"\x00" * 32, "archive"),
])
def test_magic_bytes_override_extension(name, data, expected_cat):
    _, cat, _ = detect_file_type(_f(data, name), name)
    assert cat == expected_cat


def test_plain_text_is_text():
    _, cat, _ = detect_file_type(_f(b"just some ascii text, nothing special", "a.txt"), "a.txt")
    assert cat == "text"


# --- Email vs leading markup (FS-DET-001) --------------------------------------

def test_email_with_leading_markup_is_email():
    raw = b"From: a@b.test\r\nTo: c@d.test\r\nSubject: x\r\n\r\n<svg onload=alert(1)></svg>"
    _, cat, _ = detect_file_type(_f(raw, "m.eml"), "m.eml")
    assert cat == "email"


# --- Empty / tiny files must NOT be mislabelled as shellcode (regression) ------

def test_empty_file_is_not_shellcode():
    p = _f(b"", "empty.bin")
    mime, cat, _ = detect_file_type(p, "empty.bin")
    assert cat != "executable"
    assert mime != "application/x-shellcode"


@pytest.mark.parametrize("ext", [".bin", ".dat", ".raw", ".sc", ".shellcode"])
def test_tiny_raw_buffer_is_not_shellcode(ext):
    # Below the 16-byte floor: cannot be meaningful shellcode even with a raw extension.
    assert ShellcodeAnalyzer.is_likely_shellcode(b"\x00" * 8, "x" + ext) is False
    assert ShellcodeAnalyzer.is_likely_shellcode(b"", "x" + ext) is False


# --- Genuine shellcode is still detected ---------------------------------------

def test_nop_sled_is_shellcode():
    assert ShellcodeAnalyzer.is_likely_shellcode(b"\x90" * 20, "x.dat") is True


def test_raw_extension_with_real_body_is_shellcode():
    # >=16 bytes, raw extension, no known container/exe magic, and real byte variety
    # (instructions, not uniform padding) -> treated as raw shellcode.
    assert ShellcodeAnalyzer.is_likely_shellcode(bytes(range(32, 96)), "x.bin") is True


def test_uniform_buffer_with_raw_extension_is_not_shellcode():
    # A single repeated non-NOP byte carries no instructions -> not shellcode.
    assert ShellcodeAnalyzer.is_likely_shellcode(b"\x41" * 4096, "x.bin") is False
    assert ShellcodeAnalyzer.is_likely_shellcode(b"\x00" * 4096, "x.dat") is False
    # A genuine NOP sled is still shellcode.
    assert ShellcodeAnalyzer.is_likely_shellcode(b"\x90" * 64, "x.bin") is True


def test_container_magic_in_raw_extension_is_not_shellcode():
    # A ZIP saved as .bin must not be called shellcode (magic header respected).
    assert ShellcodeAnalyzer.is_likely_shellcode(b"PK\x03\x04" + b"\x00" * 32, "x.bin") is False
