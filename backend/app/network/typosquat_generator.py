"""
Typosquatting, Homoglyph & Lookalike Domain Generator.
Generates permutations (omission, repetition, transposition, keyboard replacement,
IDN homoglyphs, and phishing affixes) and checks for active resolving registrations.
Aids brand protection and phishing threat intelligence.
"""

import socket
import concurrent.futures
from typing import Dict, Any, List, Set, Optional, Tuple


KEYBOARD_ADJACENT = {
    "q": "wa", "w": "qase", "e": "wsdr", "r": "edft", "t": "rfgy", "y": "tghu", "u": "yhji", "i": "ujko", "o": "iklp", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm", "l": "kop",
    "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk"
}

CYRILLIC_HOMOGLYPHS = {
    "a": "\u0430",  # Cyrillic small letter a
    "c": "\u0441",  # Cyrillic small letter es
    "e": "\u0435",  # Cyrillic small letter ie
    "i": "\u0456",  # Cyrillic small letter byelorussian-ukrainian i
    "j": "\u0458",  # Cyrillic small letter je
    "o": "\u043e",  # Cyrillic small letter o
    "p": "\u0440",  # Cyrillic small letter er
    "s": "\u0455",  # Cyrillic small letter dze
    "x": "\u0445",  # Cyrillic small letter ha
    "y": "\u0443",  # Cyrillic small letter u
}


class TyposquattingGenerator:
    """
    Generates domain permutations and checks for active resolving lookalikes.
    """

    @classmethod
    def analyze(cls, domain: str, max_check: int = 18, timeout_s: float = 1.5) -> Dict[str, Any]:
        """
        Generates lookalike variants and checks whether they resolve to active IP addresses.
        """
        clean_domain = domain.strip().lower().rstrip(".")
        if "." not in clean_domain:
            return {"tested": False, "target": clean_domain, "variants": []}

        parts = clean_domain.split(".", 1)
        name, tld = parts[0], parts[1]

        candidates: List[Tuple[str, str, Optional[str]]] = []  # (variant, technique, punycode)
        seen: Set[str] = {clean_domain}

        def _add(cand: str, tech: str):
            if cand not in seen and len(cand) > 3:
                seen.add(cand)
                puny = None
                try:
                    puny = cand.encode("idna").decode("ascii")
                    if puny == cand:
                        puny = None
                except Exception:
                    pass
                candidates.append((cand, tech, puny))

        # 1. Homoglyphs (Cyrillic lookalikes)
        for i, char in enumerate(name):
            if char in CYRILLIC_HOMOGLYPHS:
                h_char = CYRILLIC_HOMOGLYPHS[char]
                homo_name = name[:i] + h_char + name[i+1:]
                _add(f"{homo_name}.{tld}", "IDN Homoglyph")
                break

        # 2. Omissions
        for i in range(len(name)):
            omitted = name[:i] + name[i+1:]
            if len(omitted) >= 3:
                _add(f"{omitted}.{tld}", "Omission (Missing Char)")
            if len(candidates) >= 5:
                break

        # 3. Transpositions
        for i in range(len(name) - 1):
            transposed = name[:i] + name[i+1] + name[i] + name[i+2:]
            _add(f"{transposed}.{tld}", "Transposition (Swapped Chars)")
            if len(candidates) >= 8:
                break

        # 4. Repetitions
        for i in range(len(name)):
            repeated = name[:i] + name[i] + name[i:]
            _add(f"{repeated}.{tld}", "Repetition (Double Char)")
            if len(candidates) >= 11:
                break

        # 5. Keyboard Adjacent Replacement
        for i, char in enumerate(name):
            if char in KEYBOARD_ADJACENT:
                adj = KEYBOARD_ADJACENT[char][0]
                replaced = name[:i] + adj + name[i+1:]
                _add(f"{replaced}.{tld}", "Replacement (Adjacent Key)")
                break

        # 6. Common Phishing Prefixes / Affixes
        _add(f"login-{name}.{tld}", "Phishing Prefix (login-)")
        _add(f"{name}-security.{tld}", "Phishing Affix (-security)")
        _add(f"{name}-verify.{tld}", "Phishing Affix (-verify)")

        # 7. TLD Swaps
        for alt_tld in ["org", "net", "info", "xyz", "co"]:
            if alt_tld != tld:
                _add(f"{name}.{alt_tld}", "TLD Substitution")
                if len(candidates) >= max_check:
                    break

        selected_candidates = candidates[:max_check]

        # Concurrently resolve DNS for candidates
        results: List[Dict[str, Any]] = []
        active_count = 0

        def _resolve_candidate(cand_tuple):
            cand_domain, technique, puny = cand_tuple
            lookup_target = puny if puny else cand_domain
            resolves = False
            ips: List[str] = []
            try:
                # Set a tight timeout
                addr = socket.gethostbyname(lookup_target)
                resolves = True
                ips.append(addr)
            except Exception:
                resolves = False

            return {
                "domain": cand_domain,
                "punycode": puny,
                "technique": technique,
                "resolves": resolves,
                "ips": ips,
                "is_active_threat": resolves
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            resolved_items = list(executor.map(_resolve_candidate, selected_candidates))

        for item in resolved_items:
            if item["resolves"]:
                active_count += 1
            results.append(item)

        # Sort so active/resolving candidates appear first
        results.sort(key=lambda x: (not x["resolves"], x["technique"]))

        return {
            "tested": True,
            "target": clean_domain,
            "total_generated": len(results),
            "active_registered_count": active_count,
            "lookalikes": results,
            "has_live_impersonators": active_count > 0
        }
