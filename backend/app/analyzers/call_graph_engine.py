"""
Function Call Graph Engine for FileSanitizer Binary Analysis.

Generates hierarchical directed call graphs mapping execution flow,
inter-procedural function calls, Win32/POSIX API leaf invocations,
and dynamically resolved API calls.
"""

from typing import Dict, Any, List, Optional, Set, Tuple


class CallGraphEngine:
    """
    Constructs node and edge topologies for visual call hierarchies.
    """

    CRITICAL_RISK_APIS = {
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "writeprocessmemory", "createremotethread", "queueuserapc", "ntmapviewofsection",
        "ntunmapviewofsection", "ntcreatethreadex", "urldownloadtofilea", "urldownloadtofilew"
    }

    HIGH_RISK_APIS = {
        "createprocessa", "createprocessw", "isdebuggerpresent", "checkremotedebuggerpresent",
        "internetopena", "internetopenurla", "loadlibrarya", "loadlibraryw", "getprocaddress",
        "winexec", "shellexecutea", "regsetvalueexa"
    }

    @classmethod
    def generate_call_graph(
        cls,
        instructions: List[Dict[str, Any]],
        entry_point: str = "0x401000",
        imported_apis: Optional[List[Dict[str, Any]]] = None,
        exported_symbols: Optional[List[Dict[str, Any]]] = None,
        api_hashing_matches: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Builds a comprehensive function call graph graph topology.
        """
        nodes: Dict[str, Dict[str, Any]] = {}
        edges_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        # 1. Establish Root Entry Point node
        ep_clean = entry_point.lower()
        root_id = f"func_{ep_clean.replace('0x', '')}"
        nodes[root_id] = {
            "id": root_id,
            "label": "entry_point",
            "address": entry_point,
            "node_type": "ENTRY_POINT",
            "risk": "info",
            "instruction_count": 0,
            "suspicious_flags": [],
            "is_root": True,
            "in_degree": 0,
            "out_degree": 0
        }

        # 2. Known imported APIs lookup
        api_lookup: Dict[str, Dict[str, Any]] = {}
        if imported_apis:
            for imp in imported_apis:
                name = imp.get("name") or imp.get("api")
                if name:
                    api_lookup[name.lower()] = imp

        # 3. Known exported symbols lookup
        export_lookup: Dict[str, Dict[str, Any]] = {}
        if exported_symbols:
            for exp in exported_symbols:
                name = exp.get("name")
                if name:
                    export_lookup[name.lower()] = exp

        # 4. Partition instructions into functions
        current_func_id = root_id
        func_inst_counts: Dict[str, int] = {root_id: 0}

        for idx, inst in enumerate(instructions):
            addr = inst.get("address", "")
            mnem = inst.get("mnemonic", "").lower()
            op_str = inst.get("op_str", "").strip()

            # Identify function boundaries
            if mnem == "push" and ("ebp" in op_str or "rbp" in op_str) and idx > 0:
                clean_addr = addr.replace("0x", "").lower()
                current_func_id = f"func_{clean_addr}"
                if current_func_id not in nodes:
                    nodes[current_func_id] = {
                        "id": current_func_id,
                        "label": f"sub_{clean_addr}",
                        "address": addr,
                        "node_type": "INTERNAL",
                        "risk": "info",
                        "instruction_count": 0,
                        "suspicious_flags": [],
                        "is_root": False,
                        "in_degree": 0,
                        "out_degree": 0
                    }
                    func_inst_counts[current_func_id] = 0

            func_inst_counts[current_func_id] = func_inst_counts.get(current_func_id, 0) + 1

            # Check calls
            if mnem == "call":
                target = op_str.replace("[", "").replace("]", "").replace("dword ptr ", "").replace("qword ptr ", "").strip()
                target_lower = target.lower()

                # Determine target node type
                target_id = ""
                node_type = "INTERNAL"
                risk = "info"
                flags = []

                if target_lower in api_lookup:
                    node_type = "IMPORT_API"
                    target_id = f"api_{target_lower}"
                    if target_lower in cls.CRITICAL_RISK_APIS:
                        risk = "critical"
                        flags.append("High-Risk Process Injection / RWX API")
                    elif target_lower in cls.HIGH_RISK_APIS:
                        risk = "high"
                        flags.append("Suspicious Evasion / Execution API")
                elif target_lower in export_lookup:
                    node_type = "EXPORT"
                    target_id = f"exp_{target_lower}"
                elif target.startswith("0x") or target.replace("sub_", "").isalnum():
                    node_type = "INTERNAL"
                    target_id = f"func_{target.replace('0x', '').replace('sub_', '').lower()}"
                else:
                    node_type = "INTERNAL"
                    target_id = f"func_{target_lower}"

                # Add target node if not exists
                if target_id not in nodes:
                    nodes[target_id] = {
                        "id": target_id,
                        "label": target,
                        "address": target if target.startswith("0x") else "N/A",
                        "node_type": node_type,
                        "risk": risk,
                        "instruction_count": 0,
                        "suspicious_flags": flags,
                        "is_root": False,
                        "in_degree": 0,
                        "out_degree": 0
                    }

                # If calling high risk API, escalate caller function risk
                if risk in ["critical", "high"] and nodes[current_func_id]["risk"] != "critical":
                    nodes[current_func_id]["risk"] = risk
                    nodes[current_func_id]["suspicious_flags"].append(f"Invocates {target}")

                # Record edge
                edge_key = (current_func_id, target_id, "CALL")
                if edge_key not in edges_map:
                    edges_map[edge_key] = {
                        "id": f"edge_{len(edges_map) + 1}",
                        "source": current_func_id,
                        "target": target_id,
                        "call_type": "CALL",
                        "instruction_address": addr,
                        "count": 1
                    }
                else:
                    edges_map[edge_key]["count"] += 1

        # 5. Connect API Hashing matches as dynamic resolved nodes
        if api_hashing_matches:
            for match in api_hashing_matches:
                api_name = match.get("resolved_api", "UnknownAPI")
                algo = match.get("algorithm", "HASH")
                node_id = f"hash_{api_name.lower()}"
                severity = match.get("severity", "high")
                
                if node_id not in nodes:
                    nodes[node_id] = {
                        "id": node_id,
                        "label": f"{api_name} (Resolved {algo})",
                        "address": match.get("address", "dynamic"),
                        "node_type": "RESOLVED_HASH",
                        "risk": severity,
                        "instruction_count": 1,
                        "suspicious_flags": [f"Dynamically resolved via {algo} hash {match.get('hash_hex')}"],
                        "is_root": False,
                        "in_degree": 0,
                        "out_degree": 0
                    }

                # Link from entry point or nearest caller
                caller_id = root_id
                edge_key = (caller_id, node_id, "DYNAMIC_RESOLVE")
                if edge_key not in edges_map:
                    edges_map[edge_key] = {
                        "id": f"edge_{len(edges_map) + 1}",
                        "source": caller_id,
                        "target": node_id,
                        "call_type": "DYNAMIC_RESOLVE",
                        "instruction_address": match.get("address", "N/A"),
                        "count": 1
                    }

        # Update instruction counts and degrees
        for fid, count in func_inst_counts.items():
            if fid in nodes:
                nodes[fid]["instruction_count"] = count

        edges_list = list(edges_map.values())
        for e in edges_list:
            src = e["source"]
            tgt = e["target"]
            if src in nodes:
                nodes[src]["out_degree"] += 1
            if tgt in nodes:
                nodes[tgt]["in_degree"] += 1

        # Check recursion
        has_recursion = any(e["source"] == e["target"] for e in edges_list)

        return {
            "nodes": list(nodes.values()),
            "edges": edges_list,
            "metrics": {
                "total_functions": len(nodes),
                "total_calls": len(edges_list),
                "has_recursion": has_recursion,
                "high_risk_nodes_count": sum(1 for n in nodes.values() if n["risk"] in ["critical", "high"])
            }
        }
