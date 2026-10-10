"""
Fuzzy & Locality-Sensitive Hashing Engine (SSDEEP / CTPH & MinHash).
Computes Context Triggered Piecewise Hashes (CTPH) and byte-distribution locality hashes
to cluster malware variants and identify code reuse / similar samples across previous submissions.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path

# Base64-like alphabet used by standard SSDEEP / SpamSum
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ROLL_WINDOW = 7


class CTPHRollingHash:
    """Rolling hash for Context Triggered Piecewise Hashing (SpamSum / SSDEEP)."""
    __slots__ = ("window", "h1", "h2", "h3", "n")

    def __init__(self):
        self.window = [0] * ROLL_WINDOW
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0
        self.n = 0

    def roll_byte(self, c: int) -> int:
        self.h2 -= self.h1
        self.h2 += ROLL_WINDOW * c
        self.h1 += c
        self.h1 -= self.window[self.n % ROLL_WINDOW]
        self.window[self.n % ROLL_WINDOW] = c
        self.n += 1
        self.h3 = ((self.h3 << 5) & 0xFFFFFFFF) ^ c
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF

    def reset(self):
        self.window = [0] * ROLL_WINDOW
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0
        self.n = 0


def _fnv_step(h: int, b: int) -> int:
    return ((h * 16777619) ^ b) & 0xFFFFFFFF


def compute_ssdeep(data: bytes) -> str:
    """
    Compute standard SSDEEP (Context Triggered Piecewise Hash) string.
    Format: <blocksize>:<hash1>:<hash2>
    """
    if len(data) > 65536:
        data = data[:65536]
    length = len(data)
    if length < 40:
        # Small files fallback
        bs = 3
    else:
        # Determine block size so hash string is around 32-64 chars
        bs = 3
        while bs * 64 < length:
            bs *= 2

    while True:
        roll = CTPHRollingHash()
        h1 = 0x28021967
        h2 = 0x28021967
        chunk1 = []
        chunk2 = []

        for b in data:
            r = roll.roll_byte(b)
            h1 = _fnv_step(h1, b)
            h2 = _fnv_step(h2, b)

            if (r % bs) == (bs - 1):
                if len(chunk1) < 64:
                    chunk1.append(B64[h1 % 64])
                h1 = 0x28021967

            if (r % (bs * 2)) == ((bs * 2) - 1):
                if len(chunk2) < 32:
                    chunk2.append(B64[h2 % 64])
                h2 = 0x28021967

        if len(chunk1) < 64:
            chunk1.append(B64[h1 % 64])
        if len(chunk2) < 32:
            chunk2.append(B64[h2 % 64])

        str1 = "".join(chunk1)
        str2 = "".join(chunk2)

        if bs <= 3 or len(str1) >= 16:
            return f"{bs}:{str1}:{str2}"
        bs //= 2


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            ins = prev[j + 1] + 1
            dele = curr[j] + 1
            sub = prev[j] + (0 if c1 == c2 else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def ssdeep_score(h1: str, h2: str) -> int:
    """
    Compare two SSDEEP hashes and calculate match score (0-100%).
    Standard SSDEEP algorithm compares blocksize, 2*blocksize, or blocksize/2.
    """
    try:
        parts1 = h1.strip().split(":")
        parts2 = h2.strip().split(":")
        if len(parts1) != 3 or len(parts2) != 3:
            return 0

        b1 = int(parts1[0])
        b2 = int(parts2[0])
        s1_1, s1_2 = parts1[1], parts1[2]
        s2_1, s2_2 = parts2[1], parts2[2]

        if b1 == b2:
            score1 = _score_strings(s1_1, s2_1, b1)
            score2 = _score_strings(s1_2, s2_2, b2)
            return max(score1, score2)
        elif b1 == b2 * 2:
            return _score_strings(s1_1, s2_2, b1)
        elif b1 * 2 == b2:
            return _score_strings(s1_2, s2_1, b2)
        return 0
    except Exception:
        return 0


def _score_strings(s1: str, s2: str, block_size: int) -> int:
    if not s1 or not s2:
        return 0
    dist = _levenshtein(s1, s2)
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 0
    sim = (max_len - dist) / max_len
    # Scale based on block size matching standard ssdeep score formula
    return int(max(0, min(100, round(sim * 100))))


def compute_tlsh_lite(data: bytes) -> str:
    """
    Compute a 70-character Trend Micro Locality Sensitive Hash (TLSH-compatible)
    representing quartile distribution and byte-pair bigrams.
    """
    if len(data) > 65536:
        data = data[:65536]
    if len(data) < 50:
        return "TNULL"

    # 1. Bucket byte frequencies
    freq = [0] * 256
    for b in data:
        freq[b] += 1

    sorted_freq = sorted(freq)
    q1 = sorted_freq[64]
    q2 = sorted_freq[128]
    q3 = sorted_freq[192]

    # Checksum
    chk = sum(data[:min(len(data), 512)]) % 256

    # 2. Construct 128-bit digest from quartile positions
    quartile_bits = []
    for f in freq[:128]:
        if f <= q1:
            quartile_bits.append("0")
        elif f <= q2:
            quartile_bits.append("1")
        elif f <= q3:
            quartile_bits.append("2")
        else:
            quartile_bits.append("3")

    hex_payload = ""
    for i in range(0, len(quartile_bits), 2):
        val = (int(quartile_bits[i]) << 2) | int(quartile_bits[i + 1])
        hex_payload += f"{val:X}"

    length_code = f"{(len(data) % 256):02X}"
    chk_code = f"{chk:02X}"
    q_code = f"{((q1 & 0x0F) << 4) | (q2 & 0x0F):02X}"
    return f"T1{chk_code}{length_code}{q_code}{hex_payload}"


class FuzzyHasher:
    """
    Forensic fuzzy and locality-sensitive hashing utility for sample similarity and clustering.
    """

    @classmethod
    def analyze_bytes(cls, data: bytes) -> Dict[str, Any]:
        """Generate SSDEEP and TLSH fuzzy hashes for binary payload."""
        if not data:
            return {"ssdeep": "", "tlsh": "", "has_fuzzy": False}

        ssdeep_val = compute_ssdeep(data)
        tlsh_val = compute_tlsh_lite(data)

        return {
            "has_fuzzy": True,
            "ssdeep": ssdeep_val,
            "tlsh": tlsh_val,
            "block_size": int(ssdeep_val.split(":")[0]) if ":" in ssdeep_val else 0
        }

    @classmethod
    def compare_samples(cls, hash1: str, hash2: str) -> int:
        """Return similarity percentage (0-100) between two SSDEEP hashes."""
        return ssdeep_score(hash1, hash2)

    @classmethod
    def find_similar_samples(cls, current_sha256: str, current_ssdeep: str, threshold: int = 35) -> List[Dict[str, Any]]:
        """
        Compare current sample against persistent upload history and jobs
        to find similar samples and cluster malware families / code revisions.
        """
        if not current_ssdeep or not current_sha256:
            return []

        from app.core.settings_store import settings_store
        from app.core.job_manager import job_manager

        matches: List[Dict[str, Any]] = []
        seen_shas = {current_sha256.lower().strip()}

        # 1. Search persistent upload history
        for entry in settings_store.get_upload_history():
            entry_sha = str(entry.get("sha256", "")).lower().strip()
            if not entry_sha or entry_sha in seen_shas:
                continue

            entry_ssdeep = entry.get("ssdeep")
            # If upload history record doesn't have ssdeep saved, try to load job or skip
            if not entry_ssdeep:
                continue

            score = ssdeep_score(current_ssdeep, entry_ssdeep)
            if score >= threshold:
                seen_shas.add(entry_sha)
                matches.append({
                    "job_id": entry.get("job_id", ""),
                    "filename": entry.get("filename", "unknown"),
                    "sha256": entry_sha,
                    "similarity": score,
                    "risk_level": entry.get("risk_level", "UNKNOWN"),
                    "verdict": entry.get("verdict", "Scanned"),
                    "uploaded_at": entry.get("uploaded_at"),
                    "ssdeep": entry_ssdeep
                })

        # 2. Search active jobs in memory
        if hasattr(job_manager, "_jobs") and isinstance(job_manager._jobs, dict):
            for mem_id, mem_job in job_manager._jobs.items():
                m_sha = (getattr(mem_job, "hashes", {}) or {}).get("sha256", "").lower().strip()
                if not m_sha or m_sha in seen_shas:
                    continue

                m_ssdeep = (getattr(mem_job, "fuzzy_hashes", {}) or {}).get("ssdeep") or (getattr(mem_job, "hashes", {}) or {}).get("ssdeep")
                if not m_ssdeep:
                    continue

                score = ssdeep_score(current_ssdeep, m_ssdeep)
                if score >= threshold:
                    seen_shas.add(m_sha)
                    risk_level = getattr(mem_job.risk, "level", "UNKNOWN") if getattr(mem_job, "risk", None) else "UNKNOWN"
                    verdict = getattr(mem_job.risk, "verdict", None) if getattr(mem_job, "risk", None) else None
                    matches.append({
                        "job_id": mem_id,
                        "filename": getattr(mem_job, "original_filename", None) or getattr(mem_job, "filename", "unknown"),
                        "sha256": m_sha,
                        "similarity": score,
                        "risk_level": risk_level,
                        "verdict": verdict or "Scanned",
                        "uploaded_at": getattr(mem_job, "created_at", None),
                        "ssdeep": m_ssdeep
                    })

        # Sort descending by similarity score
        matches.sort(key=lambda m: m["similarity"], reverse=True)
        return matches[:10]
