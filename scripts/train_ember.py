"""Train an EMBER-style LightGBM model from PE feature vectors."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import joblib
import lightgbm as lgb
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from ml.feature_extractor import FEATURE_DIMENSION, PEFeatureExtractor

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "models", "ember_lgbm.pkl"))


def generate_synthetic_dataset(samples: int = 2000) -> tuple:
    extractor = PEFeatureExtractor()
    X = np.random.rand(samples, FEATURE_DIMENSION).astype(np.float32)
    y = np.random.choice([0, 1], size=(samples,), p=[0.8, 0.2])
    return X, y


def main() -> int:
    parser = argparse.ArgumentParser(description="Train EMBER-style LightGBM model for NovaSentinel.")
    parser.add_argument("--output", default=MODEL_PATH, help="Output model path")
    parser.add_argument("--samples", type=int, default=2000, help="Number of synthetic training samples")
    parser.add_argument("--test-size", type=float, default=0.2, help="Holdout test size")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    X, y = generate_synthetic_dataset(args.samples)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=args.test_size, random_state=42)

    model = lgb.LGBMClassifier(
        n_estimators=100,
        learning_rate=0.1,
        num_leaves=31,
        objective="binary",
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    logger.info("Training complete. Validation F1: %.3f", report["1"]["f1-score"])

    joblib.dump(model, args.output)
    print(f"Saved EMBER model to {args.output}")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    raise SystemExit(main())
