"""
Cross-References (XREFs) Engine for FileSanitizer Binary Forensics.

Extracts two-way Code and Data cross-references (caller <-> callee, data read/write,
string references, and API invocations) from disassembled machine instructions.
Enables reverse engineers to track execution flow, data dependencies, and parameter passing.
"""

import re
from typing import Dict, Any, List, Optional, Set, Tuple


class XrefEngine:
    """
    Analyzes disassembly instructions and symbol tables to construct complete
    bidirectional cross-references (XREFs).
    """

    CALL_MNEMONICS = {"call"}
    JUMP_MNEMONICS = {
        "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
        "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno"
    }

    @classmethod
    def generate_xrefs(
        cls,
        instructions: List[Dict[str, Any]],
        entry_point: str = "0x401000",
        known_strings: Optional[List[Dict[str, Any]]] = None,
        imported_apis: Optional[List[Dict[str, Any]]] = None,
        exported_symbols: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Parses instructions and builds complete XREFs map.
        """
        if not instructions:
            return {
                "total_xrefs": 0,
                "code_xrefs_count": 0,
                "data_xrefs_count": 0,
                "string_xrefs_count": 0,
                "target_to_xrefs": {},
                "source_to_outgoing": {},
                "hotspots": []
            }

        # Build address and string lookup maps
        addr_to_inst = {inst.get("address", ""): inst for inst in instructions}
        
        string_map: Dict[str, str] = {}
        if known_strings:
            for s in known_strings:
                val = s.get("value") or s.get("string") or ""
                off = s.get("offset") or s.get("rva") or s.get("address")
                if off and val:
                    string_map[str(off).lower()] = val
                    if not str(off).startswith("0x"):
                        try:
                            string_map[f"0x{int(off):x}"] = val
                        except Exception:
                            pass

        api_names: Set[str] = set()
        if imported_apis:
            for imp in imported_apis:
                name = imp.get("name") or imp.get("api")
                if name:
                    api_names.add(name.lower())

        target_to_incoming: Dict[str, List[Dict[str, Any]]] = {}
        source_to_outgoing: Dict[str, List[Dict[str, Any]]] = {}

        def _add_incoming(target_key: str, entry: Dict[str, Any]):
            clean_key = target_key.strip().lower()
            if not clean_key:
                return
            if clean_key not in target_to_incoming:
                target_to_incoming[clean_key] = []
            target_to_incoming[clean_key].append(entry)

        def _add_outgoing(src_key: str, entry: Dict[str, Any]):
            clean_key = src_key.strip().lower()
            if not clean_key:
                return
            if clean_key not in source_to_outgoing:
                source_to_outgoing[clean_key] = []
            source_to_outgoing[clean_key].append(entry)

        # Track active enclosing function scope
        current_function = "entry_point"
        code_count = 0
        data_count = 0
        string_count = 0

        # Regex patterns for operand extraction
        hex_addr_regex = re.compile(r"0x[0-9a-fA-F]+")
        mem_ref_regex = re.compile(r"\[([^\]]+)\]")

        for idx, inst in enumerate(instructions):
            addr = inst.get("address", f"0x{idx:x}")
            mnem = inst.get("mnemonic", "").lower()
            op_str = inst.get("op_str", "")
            raw_inst = f"{mnem} {op_str}".strip()

            # Identify function boundary prologues: push rbp / mov rbp, rsp or sub rsp
            if mnem == "push" and ("ebp" in op_str or "rbp" in op_str) and idx > 0:
                current_function = f"sub_{addr.replace('0x', '')}"

            # 1. Code XREFs: Calls
            if mnem in cls.CALL_MNEMONICS:
                target = op_str.replace("[", "").replace("]", "").replace("dword ptr ", "").replace("qword ptr ", "").strip()
                ref_type = "API_CALL" if target.lower() in api_names else "CODE_CALL"
                entry = {
                    "from_address": addr,
                    "from_function": current_function,
                    "target": target,
                    "instruction": raw_inst,
                    "ref_type": ref_type,
                    "direction": "incoming",
                    "description": f"Function call from {current_function} at {addr}"
                }
                _add_incoming(target, entry)
                _add_incoming(addr, entry)
                _add_outgoing(current_function, {**entry, "direction": "outgoing"})
                code_count += 1
                continue

            # 2. Code XREFs: Jumps
            if mnem in cls.JUMP_MNEMONICS:
                target = op_str.strip()
                ref_type = "UNCONDITIONAL_JUMP" if mnem == "jmp" else "CONDITIONAL_JUMP"
                entry = {
                    "from_address": addr,
                    "from_function": current_function,
                    "target": target,
                    "instruction": raw_inst,
                    "ref_type": ref_type,
                    "direction": "incoming",
                    "description": f"Branch jump ({mnem.upper()}) from {current_function} at {addr}"
                }
                _add_incoming(target, entry)
                _add_outgoing(current_function, {**entry, "direction": "outgoing"})
                code_count += 1
                continue

            # 3. Data References: Memory reads / writes (LEA, MOV, PUSH)
            mem_matches = mem_ref_regex.findall(op_str)
            hex_matches = hex_addr_regex.findall(op_str)

            # Check string references
            matched_string = None
            for h in hex_matches:
                hl = h.lower()
                if hl in string_map:
                    matched_string = (h, string_map[hl])
                    break

            if matched_string:
                str_addr, str_val = matched_string
                entry = {
                    "from_address": addr,
                    "from_function": current_function,
                    "target": str_val,
                    "target_address": str_addr,
                    "instruction": raw_inst,
                    "ref_type": "STRING_REF",
                    "direction": "incoming",
                    "description": f"String reference: \"{str_val[:32]}\" from {current_function}"
                }
                _add_incoming(str_val, entry)
                _add_incoming(str_addr, entry)
                _add_outgoing(current_function, {**entry, "direction": "outgoing"})
                string_count += 1
                data_count += 1
                continue

            # Check general data references
            if mem_matches or (mnem in ["lea", "mov"] and hex_matches):
                ref_type = "DATA_WRITE" if mnem == "mov" and op_str.startswith("[") else "DATA_READ"
                target_sym = mem_matches[0] if mem_matches else hex_matches[0]
                entry = {
                    "from_address": addr,
                    "from_function": current_function,
                    "target": target_sym,
                    "instruction": raw_inst,
                    "ref_type": ref_type,
                    "direction": "incoming",
                    "description": f"Memory {ref_type.lower().replace('_', ' ')}: {target_sym} at {addr}"
                }
                _add_incoming(target_sym, entry)
                _add_outgoing(current_function, {**entry, "direction": "outgoing"})
                data_count += 1

        # Calculate hotspots (symbols with high incoming references)
        hotspots = []
        for target, entries in target_to_incoming.items():
            if len(entries) >= 2:
                hotspots.append({
                    "target": target,
                    "references_count": len(entries),
                    "callers": list({e["from_function"] for e in entries})
                })
        hotspots.sort(key=lambda x: x["references_count"], reverse=True)

        return {
            "total_xrefs": code_count + data_count,
            "code_xrefs_count": code_count,
            "data_xrefs_count": data_count,
            "string_xrefs_count": string_count,
            "target_to_xrefs": target_to_incoming,
            "source_to_outgoing": source_to_outgoing,
            "hotspots": hotspots[:15]
        }
