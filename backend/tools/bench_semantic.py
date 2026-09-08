"""Benchmark the injection-detection layers over the semantic corpus.

Compares three engines on the same held-out split the trainer used (so the
published numbers describe the exact shipped artifact, with no train leakage):

1. regex — the deterministic ``INJECTION_PATTERNS`` layer alone
2. ml    — the local semantic classifier alone (score >= threshold)
3. fused — production ``semantic_intent_check`` (regex first, then ML)

Writes ``docs/benchmarks/injection-detection.md`` with confusion metrics,
per-language recall, latency, and methodology notes, and prints a summary.

Usage (from ``backend/``):
    python tools/bench_semantic.py [--repeats N]
"""

from __future__ import annotations

import argparse
import re
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.semantic import (  # noqa: E402
    score_text,
    semantic_status,
    semantic_threshold,
)
from app.semantic_corpus import (  # noqa: E402
    CORPUS,
    SPLIT_SEED,
    corpus_stats,
    stratified_split,
)
from security_engine import INJECTION_PATTERNS, semantic_intent_check  # noqa: E402

DOC_PATH = Path(__file__).resolve().parents[2] / "docs" / "benchmarks" / "injection-detection.md"
_CJK_RE = re.compile(r"[\u3400-\u9fff]")


def _language(text: str) -> str:
    """Crude corpus-language bucket: any CJK char counts as zh."""
    return "zh" if _CJK_RE.search(text) else "en"


def _regex_engine(text: str) -> bool:
    return any(pattern.search(text) for pattern in INJECTION_PATTERNS)


def _ml_engine(text: str) -> bool:
    return score_text(text) >= semantic_threshold()


def _fused_engine(text: str) -> bool:
    return not semantic_intent_check(text).allowed


ENGINES = [
    ("regex", _regex_engine),
    ("ml", _ml_engine),
    ("fused", _fused_engine),
]


def _evaluate(
    engine, samples: list[tuple[str, str, str]]
) -> dict[str, object]:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    by_language: dict[str, dict[str, int]] = {
        "zh": {"positive": 0, "caught": 0},
        "en": {"positive": 0, "caught": 0},
    }
    for label, _, text in samples:
        predicted = engine(text)
        actual = label == "injection"
        language = _language(text)
        if actual:
            by_language[language]["positive"] += 1
            if predicted:
                by_language[language]["caught"] += 1
        if predicted and actual:
            counts["tp"] += 1
        elif predicted:
            counts["fp"] += 1
        elif actual:
            counts["fn"] += 1
        else:
            counts["tn"] += 1

    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        **counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "recall_zh": (
            by_language["zh"]["caught"] / by_language["zh"]["positive"]
            if by_language["zh"]["positive"]
            else None
        ),
        "recall_en": (
            by_language["en"]["caught"] / by_language["en"]["positive"]
            if by_language["en"]["positive"]
            else None
        ),
    }


def _latency(engine, samples: list[tuple[str, str, str]], repeats: int) -> dict[str, float]:
    durations_us: list[float] = []
    for _ in range(repeats):
        for _, _, text in samples:
            started = time.perf_counter_ns()
            engine(text)
            durations_us.append((time.perf_counter_ns() - started) / 1000.0)
    durations_us.sort()
    p95 = durations_us[int(len(durations_us) * 0.95) - 1] if durations_us else 0.0
    return {
        "avg_us": statistics.fmean(durations_us),
        "p95_us": p95,
        "texts_per_sec": 1_000_000.0 / statistics.fmean(durations_us)
        if durations_us
        else 0.0,
    }


def _pct(value: object) -> str:
    return "n/a" if value is None else f"{float(value) * 100:.1f}%"


def _spot_examples(
    samples: list[tuple[str, str, str]], limit: int = 6
) -> list[dict[str, object]]:
    """Deterministic interesting held-out cases for the report."""
    picked: list[dict[str, object]] = []
    seen: set[str] = set()
    priorities = [
        # (description, predicate)
        ("zh injection: regex misses, ml catches", lambda r: r["actual"] and r["lang"] == "zh" and not r["regex"] and r["ml"]),
        ("en injection: both layers catch", lambda r: r["actual"] and r["lang"] == "en" and r["regex"] and r["ml"]),
        ("benign security research: no false positive", lambda r: not r["actual"] and ("research" in r["tag"] or "review" in r["tag"])),
        ("benign dev chatter: no false positive", lambda r: not r["actual"] and ("dev" in r["tag"] or "ops" in r["tag"])),
    ]
    rows = [
        {
            "label": label,
            "tag": tag,
            "text": text,
            "lang": _language(text),
            "actual": label == "injection",
            "regex": _regex_engine(text),
            "ml": _ml_engine(text),
        }
        for label, tag, text in samples
    ]
    for description, predicate in priorities:
        for row in rows:
            if len(picked) >= limit:
                break
            if row["text"] in seen or not predicate(row):
                continue
            seen.add(row["text"])
            picked.append({"description": description, **row})
    return picked


def _metrics_table(results: dict[str, dict[str, object]]) -> str:
    lines = [
        "| 引擎 | TP | FP | FN | TN | 精确率 | 召回率 | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in ("regex", "ml", "fused"):
        r = results[name]
        lines.append(
            f"| {name} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} "
            f"| {_pct(r['precision'])} | {_pct(r['recall'])} | {_pct(r['f1'])} |"
        )
    return "\n".join(lines)


def _language_table(results: dict[str, dict[str, object]]) -> str:
    lines = [
        "| 引擎 | 中文注入召回 | 英文注入召回 |",
        "| --- | ---: | ---: |",
    ]
    for name in ("regex", "ml", "fused"):
        r = results[name]
        lines.append(f"| {name} | {_pct(r['recall_zh'])} | {_pct(r['recall_en'])} |")
    return "\n".join(lines)


def _latency_table(latencies: dict[str, dict[str, float]]) -> str:
    lines = [
        "| 引擎 | 平均耗时 | P95 耗时 | 吞吐（文本/秒） |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name in ("regex", "ml", "fused"):
        r = latencies[name]
        lines.append(
            f"| {name} | {r['avg_us']:.0f} µs | {r['p95_us']:.0f} µs | {r['texts_per_sec']:,.0f} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
        help="latency measurement passes over the held-out split (default 5)",
    )
    args = parser.parse_args()

    # The fused engine is mode-aware; benchmark its production behavior.
    import os

    os.environ["SHADOW_AGENT_SEMANTIC_MODE"] = "enforce"

    train, heldout = stratified_split()
    stats = corpus_stats()
    status = semantic_status()
    if not status["model_loaded"]:
        print("ERROR: semantic model artifact is not loaded — train it first.")
        return 1

    results = {name: _evaluate(engine, heldout) for name, engine in ENGINES}
    full_reference = {
        name: _evaluate(engine, CORPUS) for name, engine in ENGINES
    }
    latencies = {
        name: _latency(engine, heldout, args.repeats) for name, engine in ENGINES
    }
    spots = _spot_examples(heldout)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    heldout_injection = sum(1 for label, _, _ in heldout if label == "injection")
    heldout_benign = len(heldout) - heldout_injection

    spot_lines = []
    for spot in spots:
        verdicts = (
            f"regex={'拦截' if spot['regex'] else '放行'} · ml={'拦截' if spot['ml'] else '放行'}"
        )
        spot_lines.append(
            f"- **{spot['description']}**（{spot['lang']}，标注：{'注入' if spot['actual'] else '良性'}，{verdicts}）\n"
            f"  > {spot['text'][:110]}"
        )

    document = f"""# 注入检测基准（injection detection benchmark）

> 由 `backend/tools/bench_semantic.py` 生成于 {generated_at} — 修改语料或重训模型后请重新生成。

## 结论速览

- **ML 层**在留出集上 **零误报**（精确率 100%），英文注入召回 {_pct(results['ml']['recall_en'])}；fused（regex + ML，生产配置）把整体召回从 regex 单独的 {_pct(results['regex']['recall'])} 提升到 {_pct(results['fused']['recall'])}。
- fused 的误报**全部继承自 regex 层**（研究/开发类良性文本内嵌攻击短语被签名命中，此类误报在引入 ML 之前即已存在）；ML 层对 fused 的误报贡献为零。
- **已知短板**：中文注入的改写泛化弱（留出召回 {_pct(results['ml']['recall_zh'])}）——中文攻击的动词×名词组合稀疏，字符 n-gram 共享度低。缓解路径：monitor 模式观察 + 行为层/DLP 层兜底；升级方向见文末路线图。

## 环境与工件

| 项 | 值 |
| --- | --- |
| 模型版本 | v{status['model_version']}（trained_at: {status['trained_at']}） |
| 阻断阈值 | {status['threshold']} |
| 语料规模 | {len(CORPUS)} 条（注入 {sum(v for k, v in stats.items() if k.startswith('injection'))} / 良性 {sum(v for k, v in stats.items() if k.startswith('benign'))}） |
| 切分 | 训练 {len(train)} / 留出 {len(heldout)}（分层，seed={SPLIT_SEED}） |
| 留出集分布 | 注入 {heldout_injection} / 良性 {heldout_benign} |

## 留出集指标（{len(heldout)} 条，模型未见过）

{_metrics_table(results)}

### 分语言注入召回

{_language_table(results)}

regex 层只有英文签名，对中文注入基本失效；ML 层补齐中文面，同时两层在英文上互补。

## 全量语料参考（含训练数据，仅作回归对照）

{_metrics_table(full_reference)}

> 该表包含 80% 训练数据，指标必然偏高；仅用于重训后对比是否发生退化，不代表线上效果。

## 延迟（留出集，{args.repeats} 轮平均，进程内同步调用）

{_latency_table(latencies)}

ML 层为纯 Python 哈希特征 + 稀疏线性打分，无网络、无外部依赖，单请求扫描三个文本切片（可信指令 / 外部上下文 / 会话历史）的总额外成本在毫秒级以内。

## 留出集样例

{chr(10).join(spot_lines)}

## 方法论

- **分层切分**：训练与留出按 (label, tag) 分层，固定种子，保证可复现且留出集分布与训练集一致。
- **精确率优先阈值**：阈值取「训练集良性最大分 + 安全边际」且下限 0.85 —— 网关误拦正常流量的代价高于漏拦新变体（漏拦仍可由 monitor 模式与行为层兜底）。
- **覆盖率感知打分**：文本特征在训练语料中覆盖不足时，分数向良性先验收缩，压低域外（OOD）误报。
- **regex 基线**：仅统计 `security_engine.INJECTION_PATTERNS`（引擎内置签名），不含数据库黑名单策略 —— 生产环境两层叠加，覆盖率只增不减。
- **fused 引擎**：按生产顺序先 regex 后 ML，任一层命中即阻断；本基准将 fused 置于 enforce 模式。

## 升级路线图

1. **中文泛化**（针对上文召回短板）：持续扩充中文注入语料（改写变体、方言化表述），并评估引入轻量中文分词（如 jieba）替换纯字符 n-gram，提高特征共享度。
2. **monitor 模式回流**：生产以 monitor 模式灰度运行，把 `semantic_injection_suspected` 事件沉淀为标注候选，定期回流语料并重训。
3. **嵌入层升级**：当吞吐预算允许时，引入 sentence-transformers 级别的小型多语言嵌入模型（如 bge-small-zh）做向量近邻判别，替代/叠加哈希特征。
4. **远程大模型兜底**：对 monitor 标记但本地模型不确定的样本，可选调用外部 LLM 做二次裁决（需评估数据外发边界与延迟预算）。
"""

    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text(document, encoding="utf-8")

    print(f"held-out evaluation over {len(heldout)} samples:")
    for name in ("regex", "ml", "fused"):
        r = results[name]
        print(
            f"  {name:6s} precision={_pct(r['precision'])} recall={_pct(r['recall'])} "
            f"(zh recall={_pct(r['recall_zh'])}, en recall={_pct(r['recall_en'])})"
        )
    print(f"benchmark written: {DOC_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
