import re
import math
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding, extract_clean_urls
from app.core.logging_config import logger
from PIL import Image, ExifTags

def dms_to_decimal(dms_tuple, ref: str) -> Optional[float]:
    """Convert Degrees/Minutes/Seconds tuple to decimal degrees."""
    try:
        if not dms_tuple or len(dms_tuple) < 3:
            return None
        deg = float(dms_tuple[0])
        minutes = float(dms_tuple[1])
        seconds = float(dms_tuple[2])
        decimal = deg + (minutes / 60.0) + (seconds / 3600.0)
        if ref in ['S', 'W']:
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None

class ImageAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "ImageAnalyzer"

    def analyze(self, file_path: Path, filename: str, mime_type: str) -> AnalyzerResult:
        findings: List[Finding] = []
        urls: Set[str] = set()
        data: Dict[str, Any] = {
            "format": "",
            "dimensions": [0, 0],
            "mode": "",
            "has_exif": False,
            "has_gps": False,
            "gps_coordinates": None,
            "camera_info": {},
            "author_info": {},
            "timestamps": {},
            "has_icc_profile": False,
            "has_xmp": False,
            "has_iptc": False,
            "comments": [],
            "raw_metadata": {},
            "urls": []
        }

        try:
            with Image.open(file_path) as img:
                data["format"] = img.format or ""
                data["dimensions"] = list(img.size)
                data["mode"] = img.mode

                # Check ICC Profile
                if "icc_profile" in img.info:
                    data["has_icc_profile"] = True

                # Check Comments / Text chunks
                if "comment" in img.info:
                    val = img.info["comment"]
                    if isinstance(val, bytes):
                        val = val.decode('utf-8', errors='ignore')
                    data["comments"].append(str(val))

                for k, v in img.info.items():
                    if k.lower() in ["description", "author", "copyright", "title"]:
                        data["author_info"][k] = str(v)

                # Check XMP
                for k in ["XML:com.adobe.xmp", "xmp"]:
                    if k in img.info:
                        data["has_xmp"] = True

                # Extract EXIF
                try:
                    exif_data = img.getexif()
                    if exif_data:
                        data["has_exif"] = True
                        for tag_id, value in exif_data.items():
                            tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                            # Ignore raw binary bytes in readable display
                            if isinstance(value, bytes):
                                display_val = f"<Binary data: {len(value)} bytes>"
                            else:
                                display_val = str(value)

                            data["raw_metadata"][tag_name] = display_val

                            # Filter specific fields
                            if tag_name in ["Make", "Model", "Software", "LensModel", "BodySerialNumber"]:
                                data["camera_info"][tag_name] = display_val
                            elif tag_name in ["Artist", "Copyright", "UserComment"]:
                                data["author_info"][tag_name] = display_val
                            elif tag_name in ["DateTime", "DateTimeOriginal", "DateTimeDigitized"]:
                                data["timestamps"][tag_name] = display_val

                        # Check GPS IFD
                        gps_ifd = exif_data.get_ifd(0x8825) if hasattr(exif_data, 'get_ifd') else None
                        if gps_ifd:
                            gps_tags = {}
                            for g_id, g_val in gps_ifd.items():
                                g_name = ExifTags.GPSTAGS.get(g_id, str(g_id))
                                gps_tags[g_name] = g_val

                            lat_dms = gps_tags.get("GPSLatitude")
                            lat_ref = gps_tags.get("GPSLatitudeRef", "N")
                            lon_dms = gps_tags.get("GPSLongitude")
                            lon_ref = gps_tags.get("GPSLongitudeRef", "E")

                            lat = dms_to_decimal(lat_dms, lat_ref)
                            lon = dms_to_decimal(lon_dms, lon_ref)

                            if lat is not None and lon is not None:
                                data["has_gps"] = True
                                from app.network.geo_resolver import geo_resolver
                                geo = geo_resolver.resolve_coordinates(lat, lon)
                                data["gps_coordinates"] = {
                                    "latitude": lat,
                                    "longitude": lon,
                                    "readable": f"{lat:.6f}, {lon:.6f}",
                                    "city": geo.get("city", "Unknown City"),
                                    "country": geo.get("country", "Unknown Country"),
                                    "location_name": geo.get("display_name", f"{lat:.6f}, {lon:.6f}")
                                }
                except Exception as e:
                    logger.debug(f"Error reading EXIF data: {e}")

                # Extract URLs from img.info, comments, author_info, and raw_metadata
                for k, v in img.info.items():
                    if isinstance(v, (str, bytes)):
                        text_val = v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else str(v)
                        urls.update(extract_clean_urls(text_val))

                for c in data["comments"]:
                    urls.update(extract_clean_urls(c))

                for v in data["author_info"].values():
                    urls.update(extract_clean_urls(v))

                for v in data["raw_metadata"].values():
                    urls.update(extract_clean_urls(v))

                data["urls"] = list(urls)

                # =============================================================
                # In-Depth Image Forensics 1: Steganography, Bitplane & Channel Analysis
                # =============================================================
                try:
                    if img.mode in ["RGB", "RGBA"]:
                        w, h = img.size
                        step = max(1, int((w * h) / 20000))
                        pixels = list(img.getdata())[::step]
                        
                        r_lsb, g_lsb, b_lsb = [], [], []
                        r_plane1, g_plane1, b_plane1 = [], [], []
                        transitions = 0
                        total_pairs = 0

                        prev_px = None
                        for px in pixels:
                            if isinstance(px, (tuple, list)) and len(px) >= 3:
                                r, g, b = px[0], px[1], px[2]
                                r_lsb.append(r & 1)
                                g_lsb.append(g & 1)
                                b_lsb.append(b & 1)
                                r_plane1.append((r >> 1) & 1)
                                g_plane1.append((g >> 1) & 1)
                                b_plane1.append((b >> 1) & 1)

                                if prev_px is not None:
                                    total_pairs += 3
                                    if (r & 1) != (prev_px[0] & 1):
                                        transitions += 1
                                    if (g & 1) != (prev_px[1] & 1):
                                        transitions += 1
                                    if (b & 1) != (prev_px[2] & 1):
                                        transitions += 1
                                prev_px = px

                        def _calc_bit_entropy(bits: List[int]) -> float:
                            if not bits:
                                return 0.0
                            ones = sum(bits)
                            total = len(bits)
                            p1 = ones / total
                            p0 = 1.0 - p1
                            if p0 <= 0 or p1 <= 0:
                                return 0.0
                            return round(-(p0 * math.log2(p0) + p1 * math.log2(p1)), 4)

                        all_lsb = r_lsb + g_lsb + b_lsb
                        overall_lsb_entropy = _calc_bit_entropy(all_lsb)
                        r_ent = _calc_bit_entropy(r_lsb)
                        g_ent = _calc_bit_entropy(g_lsb)
                        b_ent = _calc_bit_entropy(b_lsb)

                        plane1_entropy = _calc_bit_entropy(r_plane1 + g_plane1 + b_plane1)
                        entropy_jump = round(overall_lsb_entropy - plane1_entropy, 4)

                        transition_rate = round(transitions / total_pairs, 4) if total_pairs > 0 else 0.0

                        # Chi-Square test on overall LSB
                        total_bits = len(all_lsb)
                        ones_count = sum(all_lsb)
                        expected = total_bits / 2.0
                        chi_sq = (((ones_count - expected) ** 2) / expected + (((total_bits - ones_count) - expected) ** 2) / expected) if expected > 0 else 0.0

                        # Strong indicator: LSB entropy near 1.0, transition rate near 0.5, and noticeable drop from bitplane 0 to 1
                        is_suspicious_stego = (
                            total_bits > 1500 and
                            overall_lsb_entropy >= 0.997 and
                            0.47 <= transition_rate <= 0.53 and
                            (entropy_jump >= 0.08 or (r_ent >= 0.998 and g_ent >= 0.998 and b_ent >= 0.998))
                        )

                        stego_info = {
                            "sampled_pixels": len(pixels),
                            "sampled_bits": total_bits,
                            "overall_lsb_entropy": overall_lsb_entropy,
                            "channel_entropy": {
                                "red": r_ent,
                                "green": g_ent,
                                "blue": b_ent
                            },
                            "bitplane_analysis": {
                                "plane0_lsb_entropy": overall_lsb_entropy,
                                "plane1_entropy": plane1_entropy,
                                "entropy_jump": entropy_jump
                            },
                            "sample_pair_transition_rate": transition_rate,
                            "chi_square": round(chi_sq, 2),
                            "stego_suspicious": is_suspicious_stego,
                            "confidence": "HIGH" if is_suspicious_stego and entropy_jump >= 0.12 else ("MEDIUM" if is_suspicious_stego else "LOW")
                        }
                        data["steganography"] = stego_info
                        if is_suspicious_stego:
                            findings.append(Finding(
                                category="active_content",
                                severity="high",
                                title=f"Steganographic Payload Indicator Detected (Entropy: {overall_lsb_entropy}, Transition: {transition_rate})",
                                description=(
                                    f"Least Significant Bit (LSB) bitplane across RGB channels exhibits extreme cryptographic randomness ({overall_lsb_entropy}/1.000) "
                                    f"with an adjacent pixel transition rate of {transition_rate * 100:.1f}%. "
                                    f"Bitplane 0 randomness deviates sharply from Bitplane 1 (Delta: +{entropy_jump}), "
                                    "strongly characteristic of concealed payload insertion (e.g. Steghide, OpenStego, cloaked shellcode)."
                                ),
                                details=stego_info
                            ))
                except Exception as stego_err:
                    logger.debug(f"Steganography analysis note: {stego_err}")

                # =============================================================
                # In-Depth Image Forensics 4: Error Level Analysis (ELA) for JPEG
                # =============================================================
                if data["format"] == "JPEG":
                    try:
                        import io
                        rgb_img = img.convert("RGB")
                        buf = io.BytesIO()
                        rgb_img.save(buf, format="JPEG", quality=90)
                        buf.seek(0)
                        with Image.open(buf) as re_img:
                            orig_bytes = list(rgb_img.getdata())
                            re_bytes = list(re_img.getdata())
                            diffs = []
                            # Sample diffs
                            sample_step = max(1, len(orig_bytes) // 10000)
                            for idx in range(0, len(orig_bytes), sample_step):
                                o = orig_bytes[idx]
                                r = re_bytes[idx]
                                d = (abs(o[0] - r[0]) + abs(o[1] - r[1]) + abs(o[2] - r[2])) // 3
                                diffs.append(d)

                            if diffs:
                                avg_diff = round(sum(diffs) / len(diffs), 2)
                                max_diff = max(diffs)
                                has_tampering = max_diff > 45 and (max_diff / (avg_diff + 0.1)) > 4.0

                                ela_info = {
                                    "avg_error_level": avg_diff,
                                    "max_error_level": max_diff,
                                    "potential_splicing_detected": has_tampering
                                }
                                data["error_level_analysis"] = ela_info
                                if has_tampering:
                                    findings.append(Finding(
                                        category="metadata",
                                        severity="medium",
                                        title=f"Error Level Analysis (ELA) Compression Discrepancy (Max Diff: {max_diff})",
                                        description="High-contrast compression error variance detected across image blocks, indicating possible digital photo tampering or spliced content.",
                                        details=ela_info
                                    ))
                    except Exception as ela_err:
                        logger.debug(f"ELA analysis note: {ela_err}")

        except Exception as e:
            return AnalyzerResult(
                analyzer_name=self.name,
                success=False,
                error_message=f"Failed to open image: {e}",
                findings=[Finding(
                    category="structure",
                    severity="high",
                    title="Malformed Image File",
                    description=f"Pillow failed to decode image structure: {e}"
                )],
                data=data
            )

        # =====================================================================
        # In-Depth Image Forensics 2: Appended Overlay / Polyglot Detection
        # =====================================================================
        try:
            raw_bytes = file_path.read_bytes()
            overlay_offset = None
            fmt = data.get("format", "").upper()

            if fmt in ["JPEG", "JPG"]:
                eoi_idx = raw_bytes.rfind(b"\xFF\xD9")
                if eoi_idx != -1 and eoi_idx + 2 < len(raw_bytes):
                    overlay_offset = eoi_idx + 2
            elif fmt == "PNG":
                iend_idx = raw_bytes.rfind(b"IEND\xae\x42\x60\x82")
                if iend_idx != -1 and iend_idx + 8 < len(raw_bytes):
                    overlay_offset = iend_idx + 8
            elif fmt == "GIF":
                term_idx = raw_bytes.rfind(b"\x3B")
                if term_idx != -1 and term_idx + 1 < len(raw_bytes):
                    overlay_offset = term_idx + 1
            elif fmt == "WEBP" and raw_bytes.startswith(b"RIFF") and len(raw_bytes) >= 12:
                # RIFF header: 4 bytes "RIFF", 4 bytes length, 4 bytes "WEBP"
                riff_len = struct.unpack("<I", raw_bytes[4:8])[0] + 8
                if riff_len < len(raw_bytes):
                    overlay_offset = riff_len

            if overlay_offset and overlay_offset < len(raw_bytes):
                overlay_data = raw_bytes[overlay_offset:]
                overlay_size = len(overlay_data)
                if overlay_size > 16:
                    # Shannon entropy of overlay bytes
                    ov_entropy = 0.0
                    ov_counts = [0] * 256
                    for b in overlay_data:
                        ov_counts[b] += 1
                    for c in ov_counts:
                        if c > 0:
                            p = c / overlay_size
                            ov_entropy -= p * math.log2(p)
                    ov_entropy = round(ov_entropy, 3)

                    polyglot_type = "Raw Appended Stream"
                    sev = "medium"
                    if overlay_data.startswith(b"PK\x03\x04"):
                        polyglot_type = "Embedded ZIP Archive Polyglot"
                        sev = "critical"
                    elif overlay_data.startswith(b"MZ"):
                        polyglot_type = "Embedded Windows PE Executable"
                        sev = "critical"
                    elif overlay_data.startswith(b"\x7fELF"):
                        polyglot_type = "Embedded Linux ELF Binary"
                        sev = "critical"
                    elif overlay_data.startswith(b"7z\xBC\xAF\x27\x1C"):
                        polyglot_type = "Embedded 7-Zip Archive"
                        sev = "critical"
                    elif overlay_data.startswith(b"Rar!\x1A\x07"):
                        polyglot_type = "Embedded RAR Archive"
                        sev = "critical"
                    elif overlay_data.startswith(b"\x1F\x8B"):
                        polyglot_type = "Embedded GZIP Compressed Stream"
                        sev = "high"
                    elif overlay_data.startswith(b"%PDF-"):
                        polyglot_type = "Embedded Polyglot PDF Document"
                        sev = "critical"
                    elif b"<script" in overlay_data.lower() or b"powershell" in overlay_data.lower() or b"#!/bin/" in overlay_data:
                        polyglot_type = "Embedded Dropper Script / Shellcode"
                        sev = "critical"
                    elif ov_entropy >= 7.2 and overlay_size > 128:
                        polyglot_type = f"High-Entropy Encrypted / Packed Stream ({ov_entropy}/8.0)"
                        sev = "high"

                    pct = round((overlay_size / len(raw_bytes)) * 100, 1)
                    preview_hex = overlay_data[:32].hex()
                    preview_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in overlay_data[:32])

                    data["overlay"] = {
                        "has_overlay": True,
                        "offset": hex(overlay_offset),
                        "offset_dec": overlay_offset,
                        "size": overlay_size,
                        "percent_of_file": pct,
                        "entropy": ov_entropy,
                        "type": polyglot_type,
                        "preview_hex": preview_hex,
                        "preview_ascii": preview_ascii,
                        "is_dangerous": (sev == "critical")
                    }
                    findings.append(Finding(
                        category="structure",
                        severity=sev,
                        title=f"Appended Image Overlay Payload ({polyglot_type})",
                        description=(
                            f"Image contains {overlay_size} bytes ({pct}% of file, Entropy: {ov_entropy}) appended beyond legitimate EOF marker at offset {hex(overlay_offset)}. "
                            f"Signature: {polyglot_type}. Image overlay polyglots are routinely weaponized to stealthily deliver droppers, encrypted shells, or archives."
                        ),
                        details=data["overlay"]
                    ))
        except Exception as ov_err:
            logger.debug(f"Image overlay scan note: {ov_err}")

        # =====================================================================
        # In-Depth Image Forensics 3: Chunk Structure & Parser Exploit Auditing (PNG/WebP)
        # =====================================================================
        try:
            raw_bytes = file_path.read_bytes()
            if raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                chunks = []
                idx = 8
                has_malformed_chunk = False
                while idx + 8 <= len(raw_bytes):
                    c_len = struct.unpack(">I", raw_bytes[idx : idx + 4])[0]
                    c_type = raw_bytes[idx + 4 : idx + 8].decode('latin-1', errors='ignore')
                    if idx + 12 + c_len > len(raw_bytes):
                        has_malformed_chunk = True
                        break
                    chunks.append({"type": c_type, "length": c_len})
                    idx += 12 + c_len # length + type + data + crc

                data["png_chunks"] = chunks
                if has_malformed_chunk:
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title="Malformed PNG Chunk Structure Detected",
                        description="PNG chunk length exceeds total file bounds, indicative of parser exploit or memory buffer overflow attempts.",
                        details={"chunks": chunks[:10]}
                    ))
            elif raw_bytes.startswith(b"RIFF") and b"WEBP" in raw_bytes[:16]:
                # WebP buffer check
                data["webp_chunks"] = ["RIFF", "WEBP"]
                if len(raw_bytes) < 32:
                    findings.append(Finding(
                        category="structure",
                        severity="high",
                        title="Truncated WebP Header",
                        description="WebP image file header is truncated or malformed."
                    ))
                else:
                    # Check for CVE-2023-4863 libwebp Lossless VP8L Chunk Buffer Overflow
                    vp8l_idx = raw_bytes.find(b"VP8L")
                    if vp8l_idx != -1 and vp8l_idx + 8 <= len(raw_bytes):
                        vp8l_len = struct.unpack("<I", raw_bytes[vp8l_idx + 4 : vp8l_idx + 8])[0]
                        if vp8l_idx + 8 + vp8l_len > len(raw_bytes) + 1:
                            findings.append(Finding(
                                category="exploit",
                                severity="critical",
                                title="libwebp Lossless Chunk Overflow Indicator (CVE-2023-4863)",
                                description=(
                                    f"WebP file contains a VP8L lossless compression chunk with declared size {vp8l_len} bytes "
                                    "exceeding container bounds. Exploited in libwebp heap buffer overflow zero-days (CVE-2023-4863)."
                                ),
                                details={"chunk": "VP8L", "length": vp8l_len, "cve": "CVE-2023-4863", "mitre_technique": "T1055"}
                            ))

            # SVG / XML Image Security Auditing & ImageTragick (CVE-2016-3714)
            is_svg = raw_bytes.strip().startswith(b"<svg") or b"<svg" in raw_bytes[:1024] or file_path.suffix.lower() == ".svg"
            if is_svg or b"image/svg+xml" in raw_bytes[:256]:
                svg_text = raw_bytes.decode('latin-1', errors='ignore')

                # ImageTragick command injection
                if re.search(r'(?i)(?:fill|image)\s+["\']?url\([^\)]*\|[^\)]*\)', svg_text) or \
                   re.search(r'(?i)\|.*?(?:/bin/|cmd\.exe|powershell)', svg_text):
                    findings.append(Finding(
                        category="exploit",
                        severity="critical",
                        title="ImageTragick Command Injection Exploit (CVE-2016-3714)",
                        description=(
                            "Image contains pipe character '|' or shell invocation directives within URL specifications. "
                            "Exploits ImageMagick / GraphicsMagick (CVE-2016-3714) to achieve arbitrary command execution."
                        ),
                        details={"cve": "CVE-2016-3714", "mitre_technique": "T1059"}
                    ))

                # SVG XXE Injection
                if re.search(r'(?i)<!ENTITY[^>]+SYSTEM', svg_text) or re.search(r'(?i)<!DOCTYPE[^>]*\[', svg_text):
                    findings.append(Finding(
                        category="exploit",
                        severity="critical",
                        title="SVG XML External Entity (XXE) Injection",
                        description="SVG vector graphics image contains external entity definitions capable of file exfiltration or SSRF.",
                        details={"mitre_technique": "T1190"}
                    ))

                # SVG Embedded JavaScript / Active Content
                if re.search(r'(?i)<script\b', svg_text) or re.search(r'(?i)\bon[a-z]+\s*=', svg_text) or re.search(r'(?i)href=["\']javascript:', svg_text):
                    findings.append(Finding(
                        category="active_content",
                        severity="critical",
                        title="Active JavaScript / Script Elements in SVG Graphic",
                        description="SVG image contains interactive <script> tags or inline event handlers executing client-side scripts.",
                        details={"mitre_technique": "T1059.007"}
                    ))

            # Check for Web Shell / Script code hidden in image (Polyglot Web Shell)
            if re.search(rb'(?i)<\?php|\bbase64_decode\s*\(|\beval\s*\(|<\%@\s*page|system\s*\(\s*\$_', raw_bytes):
                findings.append(Finding(
                    category="malware",
                    severity="critical",
                    title="Web Shell Script Payload Embedded in Image (Image Polyglot)",
                    description=(
                        "Image contains server-side script execution syntax (PHP/ASPX/eval/system). "
                        "Attackers disguise web shells as images to bypass file upload filters and achieve remote command execution."
                    ),
                    details={"mitre_technique": "T1505.003"}
                ))
        except Exception as chk_err:
            logger.debug(f"Chunk audit note: {chk_err}")

        # Generate Findings
        if data["has_gps"]:
            coords = data["gps_coordinates"]
            city = coords.get("city")
            country = coords.get("country")
            loc_label = f" ({city}, {country})" if city and city != "Unknown City" else ""
            findings.append(Finding(
                category="metadata",
                severity="high",
                title=f"GPS Geographic Coordinates Exposed{loc_label}",
                description=(
                    f"Precise physical location coordinates ({coords['readable']}{loc_label}) were found embedded in the image EXIF. "
                    "Sharing this file reveals the exact geographical location where the photograph was taken."
                ),
                details=coords
            ))

        if data["camera_info"]:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title="Camera Hardware / Software Fingerprint Found",
                description="Image contains camera make/model or editing software fingerprints.",
                details=data["camera_info"]
            ))

        if data["author_info"]:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title="Author / Copyright Information Present",
                description="Image contains personal author, creator, or copyright markers.",
                details=data["author_info"]
            ))

        if data["comments"]:
            findings.append(Finding(
                category="metadata",
                severity="low",
                title="Embedded Text Comments Present",
                description="Image contains text comments or annotation chunks.",
                details={"comments": data["comments"]}
            ))

        # QR Code & Quishing Detection
        try:
            from app.analyzers.qr_scanner import QRScanner
            qr_results = QRScanner.scan_image_file(file_path)
            if qr_results:
                data["qr_codes"] = qr_results
                findings.extend(QRScanner.generate_findings(qr_results, filename))
                for qr in qr_results:
                    if qr.get("url"):
                        urls.add(qr["url"])
        except Exception as qr_err:
            logger.debug(f"Image QR scan note: {qr_err}")

        if urls:
            findings.append(Finding(
                category="url",
                severity="medium" if len(urls) > 5 else "low",
                title=f"{len(urls)} External URL(s) Discovered in Image Metadata",
                description=f"Discovered {len(urls)} external web links embedded within image metadata, comments, or EXIF tags.",
                details={"urls": list(urls)[:20]}
            ))

        data["urls"] = list(urls)

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
