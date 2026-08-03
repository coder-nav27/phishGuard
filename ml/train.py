"""
PhishGuard ML training pipeline entry point.

Usage (from repo root):
    python ml/train.py

Dataset priority:
    1. labeled_urls.csv in ml/data/raw/ — columns: url,label (1=phishing, 0=legit)
       Features are extracted from each URL via URLFeatureExtractor, so the model
       trains on exactly the same 30 features it sees at inference time.
    2. Synthetic fallback — vectors drawn from distributions matching FEATURE_ORDER.

NOTE: The UCI ARFF dataset was removed because its pre-extracted features (favicon,
iframe, page-rank, etc.) do not match our lexical URLFeatureExtractor output,
causing feature mismatch at inference time.
"""
import json
import logging
import sys
from pathlib import Path

import numpy as np
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ml.features.extractor import URLFeatureExtractor  # noqa: E402
from ml.models.trainer import train, save_model  # noqa: E402
from ml.models.evaluator import evaluate  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent / "data" / "raw"
PROCESSED_DIR = Path(__file__).parent / "data" / "processed"


def load_url_csv(path: Path) -> tuple[np.ndarray, np.ndarray] | tuple[None, None]:
    """Extract features from a labeled URL CSV (columns: url, label)."""
    import csv

    extractor = URLFeatureExtractor()
    X_rows, y_rows = [], []
    skipped = 0
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            url = row.get("url", "").strip()
            label = row.get("label", "").strip()
            if not url or label not in ("0", "1"):
                skipped += 1
                continue
            if not url.startswith(("http://", "https://")):
                url = "http://" + url
            try:
                feats = extractor.extract(url)
                X_rows.append(extractor.to_vector(feats))
                y_rows.append(int(label))
            except Exception:
                skipped += 1

    if not X_rows:
        return None, None
    if skipped:
        log.info(f"Skipped {skipped} malformed rows.")
    return np.array(X_rows, dtype=float), np.array(y_rows)


def generate_synthetic_data(n: int = 12_000) -> tuple[np.ndarray, np.ndarray]:
    """
    Synthetic feature vectors calibrated to FEATURE_ORDER distributions.
    Legitimate: varied-depth HTTPS URLs, low entropy, no risky signals.
    Phishing: long HTTP URLs, high entropy, suspicious keywords, risky TLDs.
    Per-feature std used so binary features stay near {0,1} and continuous
    features get realistic variance.
    """
    log.info("Generating synthetic training data…")
    rng = np.random.default_rng(42)
    half = n // 2

    # Feature order matches FEATURE_ORDER in extractor.py exactly:
    # url_length, domain_length, subdomain_count, has_ip, uses_https,
    # dot_count, hyphen_count, at_sign_count, special_char_count, digit_ratio,
    # entropy, suspicious_keywords, is_url_shortener, tld_risk, path_depth,
    # query_param_count, has_encoded_chars, double_slash_in_path, has_port,
    # is_punycode, tilde_in_path, hex_in_domain, redirect_double_slash,
    # domain_digit_count, url_shortener_flag, brand_count,
    # num_dots_in_path, query_length, fragment_present, multi_subdomain
    legit_means = [40,  12, 0,   0,   1,   3,  0,   0,   1,   0.05, 3.5, 0,   0,   0,   2,  1,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,  15,  0,   0  ]
    phish_means = [95,  28, 2,   0.3, 0.2, 7,  2,   0.5, 7,   0.25, 4.8, 3,   0.2, 0.4, 3,  2,   0.6, 0.3, 0.2, 0.1, 0.1, 0.2, 0.3, 4,   0.2, 0.8, 2,  30,  0.1, 0.6]
    # Per-feature std — binary/rate features get small std; continuous get larger
    legit_std  = [15,   5, 0.3, 0.1, 0.1, 1,  0.3, 0.1, 1,   0.05, 0.4, 0.2, 0.1, 0.1, 1.5,0.8, 0.1, 0.05,0.05,0.05,0.05,0.05,0.05,1,   0.1, 0.2, 0.8,10,  0.05,0.2 ]
    phish_std  = [25,   8, 1,   0.3, 0.3, 2,  1,   0.3, 3,   0.1,  0.5, 1,   0.3, 0.4, 1.5,1,   0.3, 0.2, 0.2, 0.2, 0.2, 0.3, 0.3, 2,   0.3, 0.4, 1,  15,  0.2, 0.4 ]

    legit_X = rng.normal(loc=legit_means, scale=legit_std, size=(half, 30)).clip(0)
    phish_X = rng.normal(loc=phish_means, scale=phish_std, size=(half, 30)).clip(0)

    X = np.vstack([legit_X, phish_X])
    y = np.concatenate([np.zeros(half), np.ones(half)])
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def main() -> None:
    log.info("=== PhishGuard ML Training Pipeline ===")

    X, y = None, None
    csv_path = DATA_DIR / "labeled_urls.csv"
    if csv_path.exists():
        log.info(f"Found labeled URL CSV at {csv_path} — extracting features…")
        try:
            X, y = load_url_csv(csv_path)
            if X is not None:
                log.info(f"URL CSV loaded: {len(y):,} samples, {X.shape[1]} features")
            else:
                log.warning("CSV had no valid rows. Falling back to synthetic data.")
        except Exception as exc:
            log.warning(f"CSV load error ({exc}). Falling back to synthetic data.")

    if X is None:
        X, y = generate_synthetic_data()
        log.info(f"Synthetic data: {len(y):,} samples, {X.shape[1]} features")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    log.info(f"Train: {len(y_train):,}  |  Test: {len(y_test):,}")

    log.info("Training XGBoost + RandomForest ensemble…")
    pipeline = train(X_train, y_train)

    metrics = evaluate(pipeline, X_test, y_test)

    if metrics["accuracy"] < 0.95:
        log.warning(f"Accuracy {metrics['accuracy']:.2%} is below the 95% target!")
    else:
        log.info(f"Target met: accuracy = {metrics['accuracy']:.2%}")

    model_path = save_model(pipeline)
    log.info(f"Model saved → {model_path}")

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    metrics_path = PROCESSED_DIR / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    log.info(f"Metrics saved → {metrics_path}")


if __name__ == "__main__":
    main()
