import os
import math
import sqlite3
import re
import collections


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / total
        ent -= p * math.log2(p)
    return ent


def mean_std(values):
    if not values:
        return 0.0, 1.0
    m = sum(values) / len(values)
    var = sum((x - m) ** 2 for x in values) / len(values)
    std = math.sqrt(var)
    if std == 0:
        std = 1.0
    return m, std


class HeuristicEngine:
    """
    Hybrid heuristic engine:
    - Uses statistics from step1.db (benign samples: label=0)
    - Computes lightweight features from uploaded file
    - Applies rule-based + anomaly-based scoring
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.baseline = self._compute_baseline()

    def _compute_baseline(self):
        """
        Load basic stats from the DB for benign files (label = 0).
        We'll use:
          - size
          - numstrings
          - strings_entropy
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT size, numstrings, strings_entropy
            FROM file_features
            WHERE label = 0 AND size > 0
        """)
        rows = cursor.fetchall()
        conn.close()

        sizes = []
        numstrings = []
        sentropy = []

        for s, ns, se in rows:
            if s is not None:
                sizes.append(float(s))
            if ns is not None:
                numstrings.append(float(ns))
            if se is not None:
                sentropy.append(float(se))

        size_mean, size_std = mean_std(sizes)
        ns_mean, ns_std = mean_std(numstrings)
        se_mean, se_std = mean_std(sentropy)

        return {
            "size_mean": size_mean,
            "size_std": size_std,
            "numstrings_mean": ns_mean,
            "numstrings_std": ns_std,
            "strings_entropy_mean": se_mean,
            "strings_entropy_std": se_std,
        }

    def _extract_file_features(self, file_path: str):
        """
        Extract lightweight features from uploaded file.
        We are NOT re-implementing full EMBER here, just an approximate subset.
        """
        with open(file_path, "rb") as f:
            data = f.read()

        size = len(data)
        entropy = shannon_entropy(data)

        # Build a simple ASCII view for regex scanning
        # Replace non-printables with space
        text = "".join(chr(b) if 32 <= b <= 126 else " " for b in data)

        # Simple strings extraction (printable ASCII, length >= 4)
        strings = re.findall(r"[ -~]{4,}", text)
        numstrings = len(strings)
        if numstrings > 0:
            total_len = sum(len(s) for s in strings)
            avglen = total_len / numstrings
            concatenated = "".join(strings).encode("ascii", errors="ignore")
            strings_entropy = shannon_entropy(concatenated)
        else:
            avglen = 0.0
            strings_entropy = 0.0

        # crude URL, path, registry patterns
        lower_text = text.lower()
        num_urls = len(re.findall(r"https?://", lower_text))
        num_paths = len(re.findall(r"[a-zA-Z]:\\\\", text))  # windows paths like C:\\
        num_registry = lower_text.count("hkey_")

        mz_header = 1 if data[:2] == b"MZ" else 0

        return {
            "size": size,
            "entropy": entropy,
            "numstrings": numstrings,
            "avg_string_length": avglen,
            "strings_entropy": strings_entropy,
            "num_urls": num_urls,
            "num_paths": num_paths,
            "num_registry": num_registry,
            "mz_header": mz_header,
        }

    def _score(self, feats: dict):
        """
        Hybrid scoring:
        - Rule-based (Option A style)
        - + light anomaly-based scoring (Option B lite)
        """

        base = self.baseline
        score = 0.0
        reasons = []

        size = feats["size"]
        entropy = feats["entropy"]
        numstrings = feats["numstrings"]
        sentropy = feats["strings_entropy"]
        num_urls = feats["num_urls"]
        num_paths = feats["num_paths"]
        num_registry = feats["num_registry"]
        mz_header = feats["mz_header"]

        # 1) Simple structural checks (fast rules)

        # 1a) Not a Windows PE executable
        if mz_header == 0:
            reasons.append("File does not start with 'MZ' header (not a typical Windows PE).")
            # not necessarily bad, just note it; no big score

        # 1b) Very small or very large file relative to benign baseline
        if size < base["size_mean"] * 0.05:
            score += 1.0
            reasons.append("File size is much smaller than typical benign files.")
        elif size > base["size_mean"] * 5:
            score += 1.0
            reasons.append("File size is much larger than typical benign files.")

        # 1c) High raw entropy
        if entropy > 7.5:
            score += 2.0
            reasons.append("High file entropy (possible packing/obfuscation).")
        elif entropy > 7.0:
            score += 1.0
            reasons.append("Slightly elevated file entropy.")

        # 1d) Strings presence
        if numstrings == 0:
            score += 2.0
            reasons.append("No printable strings found (suspicious for typical PE files).")
        elif numstrings < base["numstrings_mean"] * 0.1:
            score += 1.0
            reasons.append("Very few printable strings compared to benign baseline.")

        # 1e) Strings entropy (too random)
        if sentropy > base["strings_entropy_mean"] + 1.0:
            score += 1.0
            reasons.append("Strings entropy is higher than typical benign files.")

        # 1f) URLs
        if num_urls > 0:
            score += 1.0
            reasons.append("File contains at least one URL string.")
        if num_urls > 5:
            score += 1.0
            reasons.append("File contains many URL strings (network activity).")

        # 1g) Paths and registry references
        if num_paths > 5:
            score += 1.0
            reasons.append("File references multiple file system paths.")
        if num_registry > 0:
            score += 1.0
            reasons.append("File references Windows registry keys.")

        # 2) Anomaly-based scoring (using Z-scores vs benign baseline)
        # Size Z-score
        if base["size_std"] > 0:
            z_size = (size - base["size_mean"]) / base["size_std"]
            if z_size > 3:
                score += 1.5
                reasons.append("File size is a strong outlier compared to benign files.")
            elif z_size < -3:
                score += 1.0
                reasons.append("File is abnormally small compared to benign files.")

        # Strings count Z-score
        if base["numstrings_std"] > 0 and numstrings > 0:
            z_ns = (numstrings - base["numstrings_mean"]) / base["numstrings_std"]
            if z_ns < -2:
                score += 1.0
                reasons.append("Number of strings is significantly lower than benign baseline.")
            elif z_ns > 3:
                score += 0.5
                reasons.append("Number of strings is unusually high vs benign baseline.")

        # Strings entropy Z-score
        if base["strings_entropy_std"] > 0 and sentropy > 0:
            z_se = (sentropy - base["strings_entropy_mean"]) / base["strings_entropy_std"]
            if z_se > 2.5:
                score += 1.5
                reasons.append("Strings entropy is a strong outlier compared to benign files.")

        # Final label
        if score <= 2:
            label = "Safe"
        elif score <= 5:
            label = "Suspicious"
        else:
            label = "Malicious"

        return score, label, reasons

    def analyze_file(self, file_path: str):
        """
        Main API: given a file path, returns a dict:
        {
           'score': float,
           'label': 'Safe'/'Suspicious'/'Malicious',
           'reasons': [...],
           'features': {...}
        }
        """
        feats = self._extract_file_features(file_path)
        score, label, reasons = self._score(feats)
        return {
            "score": round(score, 2),
            "label": label,
            "reasons": reasons,
            "features": feats,
        }
