import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import olefile

from app.core.logging_config import logger

class DidierOledumpAnalyzer:
    """
    Didier Stevens oledump-style stream analyzer for OLE / Compound Document files
    and OpenXML embedded OLE storages (vbaProject.bin, oleObject*.bin).
    Detects macro streams (M/m), Excel 4.0 (XLM) macro sheets, and DDE links.
    """

    @classmethod
    def analyze_file(cls, file_path: Path) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "is_ole": False,
            "streams": [],
            "has_macros": False,
            "macro_streams_count": 0,
            "has_xlm_macros": False,
            "xlm_details": [],
            "has_dde": False,
            "dde_links": [],
            "oledump_summary": ""
        }

        try:
            # Check if standalone OLE file
            if olefile.isOleFile(str(file_path)):
                cls._analyze_ole_stream(file_path, result)
            # Or OpenXML archive containing embedded OLE binaries
            elif zipfile.is_zipfile(str(file_path)):
                cls._analyze_zip_ole_parts(file_path, result)
        except Exception as e:
            logger.debug(f"Didier oledump inspection error on {file_path.name}: {e}")

        # Generate formatted oledump-like summary table
        result["oledump_summary"] = cls._generate_summary_table(result)
        return result

    @classmethod
    def _analyze_ole_stream(cls, file_path: Path, result: Dict[str, Any]) -> None:
        result["is_ole"] = True
        try:
            with olefile.OleFileIO(str(file_path)) as ole:
                stream_list = ole.listdir(streams=True, storages=False)
                for idx, stream_path in enumerate(stream_list, start=1):
                    stream_name = "/".join(stream_path)
                    try:
                        size = ole.get_size(stream_path)
                        data = ole.openstream(stream_path).read()
                    except Exception:
                        size = 0
                        data = b""

                    indicator, has_macro, has_xlm, has_dde = cls._inspect_stream_bytes(stream_name, data)
                    if has_macro:
                        result["has_macros"] = True
                        result["macro_streams_count"] += 1
                    if has_xlm:
                        result["has_xlm_macros"] = True
                        result["xlm_details"].append(f"Stream {idx} ({stream_name}): Excel 4.0 macro tokens detected")
                    if has_dde:
                        result["has_dde"] = True
                        cls._extract_dde_strings(data, result["dde_links"])

                    result["streams"].append({
                        "id": idx,
                        "name": stream_name,
                        "size": size,
                        "indicator": indicator,
                        "has_macro": has_macro,
                        "has_xlm": has_xlm,
                        "has_dde": has_dde
                    })
        except Exception as e:
            logger.debug(f"Error reading OLE streams with olefile: {e}")

    @classmethod
    def _analyze_zip_ole_parts(cls, file_path: Path, result: Dict[str, Any]) -> None:
        try:
            with zipfile.ZipFile(str(file_path), "r") as zf:
                ole_parts = [n for n in zf.namelist() if n.endswith((".bin", ".ole")) or "vba" in n.lower()]
                if not ole_parts:
                    return

                idx = 1
                for part_name in ole_parts:
                    try:
                        part_bytes = zf.read(part_name)
                    except Exception:
                        continue

                    if olefile.isOleFile(part_bytes):
                        result["is_ole"] = True
                        try:
                            with olefile.OleFileIO(part_bytes) as ole:
                                for stream_path in ole.listdir(streams=True, storages=False):
                                    sub_name = f"{part_name}::{'/'.join(stream_path)}"
                                    try:
                                        s_size = ole.get_size(stream_path)
                                        s_data = ole.openstream(stream_path).read()
                                    except Exception:
                                        s_size = 0
                                        s_data = b""

                                    indicator, has_macro, has_xlm, has_dde = cls._inspect_stream_bytes(sub_name, s_data)
                                    if has_macro:
                                        result["has_macros"] = True
                                        result["macro_streams_count"] += 1
                                    if has_xlm:
                                        result["has_xlm_macros"] = True
                                        result["xlm_details"].append(f"Stream {idx} ({sub_name}): Excel 4.0 macro tokens")
                                    if has_dde:
                                        result["has_dde"] = True
                                        cls._extract_dde_strings(s_data, result["dde_links"])

                                    result["streams"].append({
                                        "id": idx,
                                        "name": sub_name,
                                        "size": s_size,
                                        "indicator": indicator,
                                        "has_macro": has_macro,
                                        "has_xlm": has_xlm,
                                        "has_dde": has_dde
                                    })
                                    idx += 1
                        except Exception as e:
                            logger.debug(f"Error parsing embedded OLE part {part_name}: {e}")
                    else:
                        indicator, has_macro, has_xlm, has_dde = cls._inspect_stream_bytes(part_name, part_bytes)
                        if has_macro:
                            result["has_macros"] = True
                            result["macro_streams_count"] += 1
                        if has_xlm:
                            result["has_xlm_macros"] = True
                        if has_dde:
                            result["has_dde"] = True
                            cls._extract_dde_strings(part_bytes, result["dde_links"])

                        result["streams"].append({
                            "id": idx,
                            "name": part_name,
                            "size": len(part_bytes),
                            "indicator": indicator,
                            "has_macro": has_macro,
                            "has_xlm": has_xlm,
                            "has_dde": has_dde
                        })
                        idx += 1
        except Exception as e:
            logger.debug(f"Error parsing zip OLE members: {e}")

    @classmethod
    def _inspect_stream_bytes(cls, stream_name: str, data: bytes) -> tuple:
        indicator = " "
        has_macro = False
        has_xlm = False
        has_dde = False

        name_lower = stream_name.lower()

        # Check VBA Macro indicator (Didier Stevens M / m notation)
        if "vba/" in name_lower or name_lower.endswith(("/vba", "thisdocument", "thisworkbook")):
            if len(data) > 64 and (b"Attribut" in data or b"Sub " in data or b"Function " in data or b"\x01\x16" in data):
                indicator = "M"
                has_macro = True
            else:
                indicator = "m"
                has_macro = False
        elif b"vba" in name_lower.encode():
            indicator = "m"

        # Check Excel 4.0 / XLM Macros
        # BoundSheet8 record (0x0085) with SheetType = 0x01 (Excel 4.0 Macro Sheet) or formulas
        if b"\x85\x00" in data or b"Auto_Open" in data or "workbook" in stream_name.lower():
            if re.search(rb'(?i)(=EXEC|=CALL|=REGISTER|=HALT|Excel 4\.0|Auto_Open)', data):
                indicator = "X" if indicator == " " else f"{indicator}X"
                has_xlm = True

        # Check DDE (Dynamic Data Exchange) links
        if re.search(rb'(?i)(?:\x00DDE\x00|\x00DDEAUTO\x00|DDEAUTO|=DDE\(|=DDEAUTO\()', data):
            indicator = "D" if indicator == " " else f"{indicator}D"
            has_dde = True

        return indicator.strip() or "-", has_macro, has_xlm, has_dde

    @classmethod
    def _extract_dde_strings(cls, data: bytes, dde_list: List[str]) -> None:
        try:
            matches = re.findall(rb'(?i)(?:=DDE(?:AUTO)?\([^\)]+\)|(?:\x00DDE(?:AUTO)?\x00[^\x00]+))', data)
            for m in matches:
                clean = m.decode('ascii', errors='ignore').strip()
                if clean and clean not in dde_list:
                    dde_list.append(clean)
        except Exception:
            pass

    @classmethod
    def _generate_summary_table(cls, result: Dict[str, Any]) -> str:
        if not result["streams"]:
            return "No OLE streams found in document."

        lines = [
            "oledump.py Analysis Output:",
            "Idx | Ind | Size (Bytes) | Stream Path",
            "----+-----+--------------+-------------------------------------------"
        ]
        for s in result["streams"]:
            lines.append(f"{s['id']:>3} | {s['indicator']:<3} | {s['size']:>12} | {s['name']}")

        summary_note = []
        if result["has_macros"]:
            summary_note.append(f"[*] VBA Macros Present ({result['macro_streams_count']} code stream(s))")
        if result["has_xlm_macros"]:
            summary_note.append("[!] Excel 4.0 (XLM) Macro Execution Detected")
        if result["has_dde"]:
            summary_note.append("[!] Office DDE (Dynamic Data Exchange) External Command Links Detected")

        if summary_note:
            lines.append("")
            lines.extend(summary_note)

        return "\n".join(lines)
