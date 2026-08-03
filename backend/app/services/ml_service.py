import joblib
import numpy as np
from pathlib import Path

from app.config import settings


class MLService:
    _model = None

    @classmethod
    def load(cls) -> None:
        path = Path(settings.ml_model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found at {path}. Run: python ml/train.py"
            )
        cls._model = joblib.load(path)

    @classmethod
    def predict(cls, feature_vector: np.ndarray) -> float:
        if cls._model is None:
            cls.load()
        prob: float = cls._model.predict_proba(feature_vector.reshape(1, -1))[0][1]
        return round(float(prob), 4)

    @classmethod
    def is_loaded(cls) -> bool:
        return cls._model is not None
