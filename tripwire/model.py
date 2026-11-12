"""Per identity Isolation Forests.

Training uses scikit-learn. Scoring does not: the trees are exported to plain JSON and walked
in pure Python, so the Lambda package stays tiny (no numpy, no scipy, no sklearn).
tests/test_model.py checks the exported scorer against sklearn's score_samples.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence

EULER = 0.5772156649015329
GLOBAL = "__global__"
MIN_HISTORY = 50  # identities with less history fall back to the global model


def avg_path(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + EULER) - 2.0 * (n - 1.0) / n


class ExportedForest:
    def __init__(self, d: dict):
        self.psi = d["psi"]
        self.trees = d["trees"]
        self.threshold = d.get("threshold")
        self._denom = len(self.trees) * avg_path(self.psi)

    def score(self, x: Sequence[float]) -> float:
        """Anomaly score in (0, 1]. Same value as -IsolationForest.score_samples."""
        depth = 0.0
        for t in self.trees:
            f, th, left, right, n = t["f"], t["th"], t["l"], t["r"], t["n"]
            node, d = 0, 0
            while left[node] != -1:
                node = left[node] if x[f[node]] <= th[node] else right[node]
                d += 1
            depth += d + avg_path(n[node])
        return 2.0 ** (-depth / self._denom)

    def to_dict(self) -> dict:
        return {"psi": self.psi, "trees": self.trees, "threshold": self.threshold}


def export_sklearn(forest) -> dict:
    trees = []
    for est, feats in zip(forest.estimators_, forest.estimators_features_):
        tr = est.tree_
        trees.append({
            # map back to original column ids in case sklearn sub-selected features
            "f": [int(feats[i]) if i >= 0 else -1 for i in tr.feature],
            "th": [float(v) for v in tr.threshold],
            "l": [int(v) for v in tr.children_left],
            "r": [int(v) for v in tr.children_right],
            "n": [int(v) for v in tr.n_node_samples],
        })
    return {"psi": int(forest.max_samples_), "trees": trees}


def train(X_by_id: Dict[str, List[List[float]]], n_trees: int = 100, sample: int = 256,
          fp_budget: float = 0.003, seed: int = 0) -> Dict[str, dict]:
    """One forest per identity plus a global fallback.

    Each identity gets its own threshold: the (1 - fp_budget) quantile of its own training
    scores. The threshold never sees attack data.
    """
    from sklearn.ensemble import IsolationForest  # training only

    models: Dict[str, dict] = {}
    pooled: List[List[float]] = []
    for i, (ident, X) in enumerate(sorted(X_by_id.items())):
        pooled.extend(X)
        if len(X) < MIN_HISTORY:
            continue
        models[ident] = _fit(IsolationForest, X, n_trees, sample, fp_budget, seed + i)
    models[GLOBAL] = _fit(IsolationForest, pooled, n_trees, sample, fp_budget, seed + 9999)
    return models


def _fit(cls, X, n_trees, sample, fp_budget, seed) -> dict:
    f = cls(n_estimators=n_trees, max_samples=min(sample, len(X)), random_state=seed).fit(X)
    d = export_sklearn(f)
    scores = sorted(-f.score_samples(X))
    k = min(len(scores) - 1, int(math.ceil((1 - fp_budget) * len(scores))) - 1)
    d["threshold"] = float(scores[max(0, k)])
    return d


class Detector:
    def __init__(self, models: Dict[str, dict]):
        self.forests = {k: ExportedForest(v) for k, v in models.items()}

    def forest_for(self, identity: str) -> ExportedForest:
        return self.forests.get(identity) or self.forests[GLOBAL]

    def score(self, identity: str, x: Sequence[float]) -> float:
        return self.forest_for(identity).score(x)

    def is_anomalous(self, identity: str, x: Sequence[float], threshold: Optional[float] = None) -> bool:
        f = self.forest_for(identity)
        return f.score(x) > (f.threshold if threshold is None else threshold)
