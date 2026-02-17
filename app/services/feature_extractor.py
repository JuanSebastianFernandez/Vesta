import math
import os
import re
import logging
from collections import Counter
from typing import Dict

logger = logging.getLogger("app")


FEATURE_NAMES_ORDER: list[str] = [
    "SectionsMeanEntropy",
    "ResourcesMaxEntropy",
    "SectionsMeanVirtualsize",
    "SizeOfStackCommit",
    "MajorOSVersion",
    "ResourcesMeanEntropy",
    "Name",
    "SectionsMinRawsize",
    "MinorSubsystemVersion",
    "LoaderFlags",
    "ImportsNbDLL",
    "ImageBase",
]


DEFAULT_MINOR_SUBSYSTEM_VERSION = 1.0


_BLOCK_COMMENTS_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENTS_RE = re.compile(r"//.*?$|#.*?$", re.MULTILINE)
_TRIPLE_QUOTED_STRINGS_RE = re.compile(r"('{3}[\s\S]*?'{3}|\"{3}[\s\S]*?\"{3})")
_SINGLE_DOUBLE_BACKTICK_STRINGS_RE = re.compile(
    r"('([^'\\]|\\.)*'|\"([^\"\\]|\\.)*\"|`([^`\\]|\\.)*`)",
    re.DOTALL,
)


def clean_source_code(source_code: str) -> str:
    """
    Remove comments and string literals to reduce keyword-count noise.
    """
    cleaned = _BLOCK_COMMENTS_RE.sub(" ", source_code)
    cleaned = _TRIPLE_QUOTED_STRINGS_RE.sub(" ", cleaned)
    cleaned = _SINGLE_DOUBLE_BACKTICK_STRINGS_RE.sub(" ", cleaned)
    cleaned = _LINE_COMMENTS_RE.sub(" ", cleaned)
    return cleaned


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return float(entropy)


def _count_keyword(cleaned_code: str, keyword: str) -> float:
    pattern = rf"\b{re.escape(keyword)}\b"
    return float(len(re.findall(pattern, cleaned_code, flags=re.IGNORECASE)))


def _max_block_entropy(cleaned_code: str) -> float:
    if not cleaned_code.strip():
        return 0.0

    # Split by multiple blank lines to approximate logical blocks.
    blocks = [block for block in re.split(r"\n\s*\n+", cleaned_code) if block.strip()]
    if not blocks:
        return _shannon_entropy(cleaned_code)

    return float(max(_shannon_entropy(block) for block in blocks))


def _default_vector(file_name: str = "") -> Dict[str, float]:
    safe_file_name = os.path.basename(file_name) if file_name else ""
    return {
        "SectionsMeanEntropy": 0.0,
        "ResourcesMaxEntropy": 0.0,
        "SectionsMeanVirtualsize": 0.0,
        "SizeOfStackCommit": 0.0,
        "MajorOSVersion": 0.0,
        "ResourcesMeanEntropy": 0.0,
        "Name": float(len(safe_file_name)),
        "SectionsMinRawsize": 0.0,
        "MinorSubsystemVersion": DEFAULT_MINOR_SUBSYSTEM_VERSION,
        "LoaderFlags": 0.0,
        "ImportsNbDLL": 0.0,
        "ImageBase": 0.0,
    }


def _sanitize_vector(vector: Dict[str, float], file_name: str = "") -> Dict[str, float]:
    defaults = _default_vector(file_name=file_name)
    sanitized: Dict[str, float] = {}

    for feature_name in FEATURE_NAMES_ORDER:
        raw_value = vector.get(feature_name, defaults[feature_name])
        try:
            value = float(raw_value)
            if not math.isfinite(value):
                value = defaults[feature_name]
        except (TypeError, ValueError):
            value = defaults[feature_name]
        sanitized[feature_name] = value

    return sanitized


def extract_feature_vector(source_code: str, file_name: str = "") -> Dict[str, float]:
    """
    Build the 12-feature proxy vector required by VESTA.

    Contract:
    - Input: `source_code` (raw text), optional `file_name`.
    - Output: dict with exactly the keys in FEATURE_NAMES_ORDER and numeric values.
    - Fallback behavior: returns a safe default vector for empty/invalid source.
    """
    if not isinstance(source_code, str):
        logger.warning("Invalid source_code type for feature extraction; default vector returned.")
        return _default_vector(file_name=file_name)

    cleaned_code = clean_source_code(source_code)
    safe_file_name = os.path.basename(file_name) if file_name else ""
    cleaned_size = float(len(cleaned_code))

    if not cleaned_code.strip():
        return _default_vector(file_name=safe_file_name)

    vector = {
        # Entropy of cleaned file.
        "SectionsMeanEntropy": _shannon_entropy(cleaned_code),
        # Entropy of the most complex logical block.
        "ResourcesMaxEntropy": _max_block_entropy(cleaned_code),
        # Total cleaned code size.
        "SectionsMeanVirtualsize": cleaned_size,
        # Count of keyword: class.
        "SizeOfStackCommit": _count_keyword(cleaned_code, "class"),
        # Count of keyword: import.
        "MajorOSVersion": _count_keyword(cleaned_code, "import"),
        # Redundant entropy by design from requirements.
        "ResourcesMeanEntropy": _shannon_entropy(cleaned_code),
        # Filename length.
        "Name": float(len(safe_file_name)),
        # Min(cleaned_size, 1024).
        "SectionsMinRawsize": float(min(len(cleaned_code), 1024)),
        # Constant placeholder.
        "MinorSubsystemVersion": DEFAULT_MINOR_SUBSYSTEM_VERSION,
        # Count of keyword: static.
        "LoaderFlags": _count_keyword(cleaned_code, "static"),
        # Count of keyword: package.
        "ImportsNbDLL": _count_keyword(cleaned_code, "package"),
        # Count of keyword: void.
        "ImageBase": _count_keyword(cleaned_code, "void"),
    }

    return _sanitize_vector(vector, file_name=safe_file_name)
