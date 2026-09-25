from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from app.analyzers.base import BaseAnalyzer, AnalyzerResult, Finding
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
            "raw_metadata": {}
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
                                data["gps_coordinates"] = {
                                    "latitude": lat,
                                    "longitude": lon,
                                    "readable": f"{lat:.6f}, {lon:.6f}"
                                }
                except Exception as e:
                    logger.debug(f"Error reading EXIF data: {e}")

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

        # Generate Findings
        if data["has_gps"]:
            coords = data["gps_coordinates"]
            findings.append(Finding(
                category="metadata",
                severity="high",
                title="GPS Geographic Coordinates Exposed",
                description=(
                    f"Precise physical location coordinates ({coords['readable']}) were found embedded in the image EXIF. "
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

        return AnalyzerResult(
            analyzer_name=self.name,
            success=True,
            findings=findings,
            data=data
        )
