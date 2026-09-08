"""Local semantic injection detection — feature extraction, model, and scoring.

Everything runs in-process with zero network access: the classifier is a
compact logistic-regression model over hashed character/word n-gram features,
shipped as ``semantic_model.json`` next to this module and trained by
``tools/train_semantic_model.py`` over ``app/semantic_corpus.py``.

Decision policy (mirrors the response-side DLP modes):

* ``off``     — the classifier is skipped entirely.
* ``monitor`` — scores at/above the threshold stay allowed but are flagged as
  suspected (visible in ``/api/v1/analyze`` output and audit logs).
* ``enforce`` — scores at/above the threshold block the request (403).

Configuration (read lazily per call, same pattern as the DLP engine):

* ``SHADOW_AGENT_SEMANTIC_MODE``      — off | monitor | enforce (default enforce)
* ``SHADOW_AGENT_SEMANTIC_THRESHOLD`` — override the artifact threshold (0.5–0.99)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("shadow_agent.semantic")

SEMANTIC_MODES = ("off", "monitor", "enforce")
DEFAULT_SEMANTIC_MODE = "enforce"
MODEL_FILENAME = "semantic_model.json"

# Feature extraction must stay byte-identical between training and inference:
# the trainer imports these constants/functions from this module.
FEATURE_BUCKETS = 2**17
WORD_NGRAM_SIZES = (1, 2)
CHAR_NGRAM_SIZES = (3, 4)
MAX_TOKEN_CHARS = 24
MAX_SCAN_CHARS = 5000

_TOKEN_RE = re.compile(
    r"[0-9a-z\u00c0-\u024f\u0370-\u04ff\u0e00-\u0e7f\u1e00-\u1eff"
    r"\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af]+"
)
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class SemanticModel:
    """Sparse logistic-regression model over hashed n-gram features."""

    bias: float
    weights: dict[int, float]
    threshold: float
    version: int
    trained_at: str
    feature_buckets: int
    train_metrics: dict[str, Any]


_MODEL_LOCK = threading.Lock()
_MODEL_CACHE: SemanticModel | None = None
_MODEL_LOADED = False


def _model_path() -> Path:
    return Path(__file__).resolve().parent / MODEL_FILENAME


def _load_model() -> SemanticModel | None:
    """Load the shipped model artifact once; degrade to None when unusable."""

    global _MODEL_CACHE, _MODEL_LOADED

    if _MODEL_LOADED:
        return _MODEL_CACHE

    with _MODEL_LOCK:
        if _MODEL_LOADED:
            return _MODEL_CACHE

        path = _model_path()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            indices = raw["feature_indices"]
            values = raw["feature_weights"]
            if len(indices) != len(values):
                raise ValueError("feature index/weight length mismatch")
            buckets = int(raw["config"]["feature_buckets"])
            if buckets != FEATURE_BUCKETS:
                raise ValueError(
                    f"model expects {buckets} buckets, runtime uses {FEATURE_BUCKETS}"
                )
            _MODEL_CACHE = SemanticModel(
                bias=float(raw["bias"]),
                weights={
                    int(index): float(weight)
                    for index, weight in zip(indices, values)
                    if float(weight) != 0.0
                },
                threshold=float(raw["threshold"]),
                version=int(raw.get("version", 1)),
                trained_at=str(raw.get("trained_at", "")),
                feature_buckets=buckets,
                train_metrics=dict(raw.get("train_metrics", {})),
            )
        except FileNotFoundError:
            logger.warning(
                "Semantic model artifact %s not found — semantic detection disabled. "
                "Run tools/train_semantic_model.py to regenerate it.",
                path,
            )
            _MODEL_CACHE = None
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            logger.warning(
                "Semantic model artifact %s is invalid (%s) — semantic detection disabled.",
                path,
                error,
            )
            _MODEL_CACHE = None

        _MODEL_LOADED = True
        return _MODEL_CACHE


def _stable_feature_hash(feature: str) -> int:
    """Deterministic across processes (unlike built-in hash for str)."""

    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % FEATURE_BUCKETS


def extract_features(text: str) -> dict[int, float]:
    """Hashed n-gram features, L2-normalized binary presence vector.

    Word unigrams/bigrams capture phrase structure for spaced languages;
    character n-grams (within tokens) cover CJK text, transliteration, and
    leetspeak/homoglyph obfuscation. Shared verbatim by the trainer.
    """

    normalized = _WHITESPACE_RE.sub(" ", text.lower())[:MAX_SCAN_CHARS]
    if not normalized:
        return {}

    feature_names: set[str] = set()
    previous_token: str | None = None
    for token in _TOKEN_RE.findall(normalized):
        capped = token[:MAX_TOKEN_CHARS]
        feature_names.add(f"w:{capped}")
        if previous_token is not None:
            feature_names.add(f"b:{previous_token}|{capped}")
        previous_token = capped
        for size in CHAR_NGRAM_SIZES:
            for start in range(len(capped) - size + 1):
                feature_names.add(f"c{size}:{capped[start:start + size]}")

    if not feature_names:
        return {}

    scale = 1.0 / math.sqrt(len(feature_names))
    return {_stable_feature_hash(name): scale for name in feature_names}


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponent = math.exp(-value)
        return 1.0 / (1.0 + exponent)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


# Logit used as the prior for out-of-vocabulary text. Unseen traffic is far
# more likely to be benign than an attack, so a fully unmatched text scores
# ~0.2 instead of drifting toward sigmoid(bias).
OOD_PRIOR_LOGIT = -1.2


def score_features(
    weights: dict[int, float],
    bias: float,
    features: dict[int, float],
) -> float:
    """Coverage-aware logistic score.

    When most of a text's features were never seen in training (out-of-corpus
    phrasing, another language), the raw logit is mostly noise: it is shrunk
    toward the benign-leaning prior proportionally to the unseen fraction.
    In-corpus texts keep their full score, so training-separation is preserved.
    """

    if not features:
        return _sigmoid(bias)

    logit = bias
    matched = 0
    for bucket, value in features.items():
        weight = weights.get(bucket)
        if weight is not None:
            logit += weight * value
            matched += 1

    coverage = matched / len(features)
    adjusted = coverage * logit + (1.0 - coverage) * OOD_PRIOR_LOGIT
    return _sigmoid(adjusted)


def score_text(text: str) -> float:
    """Injection probability in [0, 1]; 0.0 when no model or empty input."""

    model = _load_model()
    if model is None or not text or not text.strip():
        return 0.0

    features = extract_features(text)
    if not features:
        return 0.0

    return score_features(model.weights, model.bias, features)


def semantic_mode() -> str:
    """Current semantic-detection mode (lazy env read, validated)."""

    raw = os.getenv("SHADOW_AGENT_SEMANTIC_MODE", "").strip().lower()
    if raw in SEMANTIC_MODES:
        return raw
    if raw:
        logger.warning(
            "Invalid SHADOW_AGENT_SEMANTIC_MODE %r — falling back to %r.",
            raw,
            DEFAULT_SEMANTIC_MODE,
        )
    return DEFAULT_SEMANTIC_MODE


def semantic_threshold() -> float:
    """Effective blocking threshold: env override, else the artifact value."""

    raw = os.getenv("SHADOW_AGENT_SEMANTIC_THRESHOLD", "").strip()
    if raw:
        try:
            override = float(raw)
        except ValueError:
            logger.warning("Invalid SHADOW_AGENT_SEMANTIC_THRESHOLD %r — ignored.", raw)
        else:
            if 0.5 <= override <= 0.99:
                return override
            logger.warning(
                "SHADOW_AGENT_SEMANTIC_THRESHOLD %r outside 0.5–0.99 — ignored.", raw
            )

    model = _load_model()
    if model is not None and 0.5 <= model.threshold <= 0.99:
        return model.threshold
    return 0.85


def semantic_ml_check(text: str) -> dict[str, Any] | None:
    """Score ``text`` with the local classifier.

    Returns ``None`` when the layer is disabled or unavailable. Otherwise a
    payload consumed by ``security_engine.semantic_intent_check``:

    * ``block``   — True when the score is at/above the threshold in enforce mode
    * ``score``   — calibrated injection probability
    * ``mode`` / ``threshold`` / ``model_version`` — decision context
    """

    mode = semantic_mode()
    if mode == "off":
        return None

    model = _load_model()
    if model is None or not text or not text.strip():
        return None

    score = score_text(text)
    threshold = semantic_threshold()
    at_threshold = score >= threshold

    return {
        "block": mode == "enforce" and at_threshold,
        "suspected": at_threshold,
        "score": round(score, 4),
        "mode": mode,
        "threshold": round(threshold, 4),
        "model_version": model.version,
    }


def semantic_status() -> dict[str, Any]:
    """Runtime status for the admin console and launch checks."""

    model = _load_model()
    return {
        "mode": semantic_mode(),
        "available_modes": list(SEMANTIC_MODES),
        "threshold": semantic_threshold(),
        "model_loaded": model is not None,
        "model_version": model.version if model else None,
        "trained_at": model.trained_at if model else None,
        "train_metrics": model.train_metrics if model else None,
        "max_scan_chars": MAX_SCAN_CHARS,
    }


def reset_model_cache() -> None:
    """Test hook: force the next call to reload the artifact from disk."""

    global _MODEL_CACHE, _MODEL_LOADED

    with _MODEL_LOCK:
        _MODEL_CACHE = None
        _MODEL_LOADED = False
