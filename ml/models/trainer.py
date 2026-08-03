"""XGBoost + RandomForest soft-voting ensemble pipeline."""
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

ARTIFACT_DIR = Path(__file__).parent / "artifacts"


def build_pipeline() -> Pipeline:
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=42,
        n_jobs=-1,
    )
    ensemble = VotingClassifier(
        estimators=[("xgb", xgb), ("rf", rf)],
        voting="soft",
    )
    return Pipeline([("scaler", StandardScaler()), ("model", ensemble)])


def train(X: np.ndarray, y: np.ndarray) -> Pipeline:
    pipeline = build_pipeline()
    pipeline.fit(X, y)
    return pipeline


def save_model(pipeline: Pipeline, name: str = "phishguard_model.joblib") -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    path = ARTIFACT_DIR / name
    joblib.dump(pipeline, path)
    return path


def load_model(name: str = "phishguard_model.joblib") -> Pipeline:
    return joblib.load(ARTIFACT_DIR / name)
