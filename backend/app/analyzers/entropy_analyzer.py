import math
from typing import Dict, Any, List, Tuple
from collections import Counter


class EntropyAnalyzer:
    """
    Forensic Shannon Entropy and Byte Distribution Analyzer.
    Provides sliding-window entropy profiles, Chi-square distribution,
    Monte Carlo Pi approximation, and byte frequency distributions to detect
    packed, encrypted, compressed, or steganographic payloads.
    """

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy (0.0 to 8.0) of a byte sequence."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def calculate_sliding_window_entropy(
        data: bytes,
        num_points: int = 64
    ) -> List[Dict[str, Any]]:
        """
        Divide the byte sequence into chunks and calculate the entropy of each block.
        Returns a profile suitable for visual plotting across file offsets.
        """
        if not data:
            return []

        total_len = len(data)
        if total_len <= 512:
            points = 1
            chunk_size = total_len
        else:
            points = min(num_points, max(1, total_len // 512))
            chunk_size = max(1, math.ceil(total_len / points))

        profile: List[Dict[str, Any]] = []
        for i in range(points):
            start = i * chunk_size
            end = min(start + chunk_size, total_len) if i < points - 1 else total_len
            chunk = data[start:end]
            if not chunk:
                break
            ent = EntropyAnalyzer.calculate_shannon_entropy(chunk)

            # Classify chunk nature
            if ent >= 7.1:
                label = "High Entropy (Encrypted / Compressed / Packed)"
                state = "critical"
            elif ent >= 5.8:
                label = "Moderate-High (Obfuscated Code / Native Binary)"
                state = "warning"
            elif ent >= 3.2:
                label = "Medium (Plaintext / Scripts / Markup)"
                state = "clean"
            else:
                label = "Low Entropy (Zero Padding / Sparse Data)"
                state = "sparse"

            profile.append({
                "index": i,
                "offset_start": start,
                "offset_end": end,
                "offset_hex": f"0x{start:06X} - 0x{end:06X}",
                "chunk_size": len(chunk),
                "entropy": ent,
                "label": label,
                "state": state
            })

        return profile

    @staticmethod
    def calculate_chi_square(data: bytes) -> Dict[str, Any]:
        """
        Calculate Chi-Square test for random byte distribution.
        For a completely random uniform byte distribution, each of the 256 byte values
        has expected frequency = len(data) / 256.
        """
        if not data:
            return {"chi_square": 0.0, "is_random_like": False, "interpretation": "Empty data"}

        total = len(data)
        expected = total / 256.0
        counts = Counter(data)

        chi_sq = 0.0
        for byte_val in range(256):
            observed = counts.get(byte_val, 0)
            diff = observed - expected
            chi_sq += (diff * diff) / expected if expected > 0 else 0.0

        chi_sq = round(chi_sq, 2)
        # For 255 degrees of freedom, chi-sq around 255 is uniform/random
        is_random_like = 200.0 <= chi_sq <= 320.0

        if is_random_like:
            interp = "High uniformity (characteristic of strong encryption, AES/ChaCha, or high-ratio compression)"
        elif chi_sq < 200.0:
            interp = "Very low variance (unusual synthetic byte uniformity)"
        else:
            interp = "Non-uniform distribution (characteristic of natural text, executable headers, or structured formats)"

        return {
            "chi_square": chi_sq,
            "expected_per_byte": round(expected, 2),
            "is_random_like": is_random_like,
            "interpretation": interp
        }

    @staticmethod
    def calculate_monte_carlo_pi(data: bytes) -> Dict[str, Any]:
        """
        Estimate Pi using consecutive byte pairs as (X, Y) coordinates in a square.
        Closer to 3.14159265 indicates true pseudo-randomness (encrypted or compressed payload).
        """
        if len(data) < 64:
            return {"pi_estimate": 0.0, "error_percent": 100.0}

        in_circle = 0
        total_points = len(data) // 2
        for i in range(0, total_points * 2, 2):
            x = data[i] / 255.0
            y = data[i + 1] / 255.0
            if (x * x + y * y) <= 1.0:
                in_circle += 1

        if total_points == 0:
            return {"pi_estimate": 0.0, "error_percent": 100.0}

        pi_est = 4.0 * in_circle / total_points
        error = abs(pi_est - math.pi) / math.pi * 100.0

        return {
            "pi_estimate": round(pi_est, 5),
            "error_percent": round(error, 2),
            "is_random": error < 2.5
        }

    @staticmethod
    def analyze_bytes(data: bytes) -> Dict[str, Any]:
        """
        Comprehensive forensic byte & entropy profile.
        """
        if not data:
            return {
                "overall_entropy": 0.0,
                "profile": [],
                "chi_square": {},
                "monte_carlo": {},
                "byte_distribution": {},
                "summary": "No data analyzed"
            }

        overall_entropy = EntropyAnalyzer.calculate_shannon_entropy(data)
        profile = EntropyAnalyzer.calculate_sliding_window_entropy(data, num_points=64)
        chi_sq = EntropyAnalyzer.calculate_chi_square(data)
        monte_carlo = EntropyAnalyzer.calculate_monte_carlo_pi(data)

        # Byte distribution insights
        null_bytes = data.count(b"\x00")
        null_ratio = round(null_bytes / len(data) * 100.0, 2)
        printable_bytes = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        printable_ratio = round(printable_bytes / len(data) * 100.0, 2)

        # High entropy contiguous blocks detection
        high_entropy_blocks = [p for p in profile if p["entropy"] >= 7.1]
        has_high_entropy_payload = len(high_entropy_blocks) > 0 and overall_entropy < 7.1

        return {
            "overall_entropy": overall_entropy,
            "max_entropy": max((p["entropy"] for p in profile), default=overall_entropy),
            "min_entropy": min((p["entropy"] for p in profile), default=overall_entropy),
            "profile": profile,
            "chi_square": chi_sq,
            "monte_carlo": monte_carlo,
            "null_byte_percentage": null_ratio,
            "printable_byte_percentage": printable_ratio,
            "high_entropy_blocks_count": len(high_entropy_blocks),
            "has_embedded_high_entropy_payload": has_high_entropy_payload,
            "verdict": (
                "SUSPICIOUS_HIGH_ENTROPY" if overall_entropy >= 7.1 or has_high_entropy_payload
                else "NORMAL_ENTROPY"
            )
        }
