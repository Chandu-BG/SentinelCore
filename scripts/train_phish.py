"""Train a phishing URL LightGBM model for NovaSentinel."""

from __future__ import annotations

import argparse
import logging
import os
import random
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

from ml.phish_model import URLFeatureExtractor

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, "models", "phish_lgbm.pkl"))


def sample_url_data(count: int = 2000) -> tuple:
    malicious_templates = [
        "http://{domain}/login.php?user={user}",
        "https://secure-{domain}.com/{path}",
        "http://{domain}/verify?account={user}",
        "https://{domain}/update/password",
        "http://{domain}/auth?token={token}",
    ]
    safe_templates = [
        "https://{domain}/about",
        "https://{domain}/{path}",
        "http://{domain}/blog/{post}",
        "https://{domain}/products/{product}",
        "http://{domain}/contact",
    ]
    domains = ["example.com", "microsoft.com", "github.com", "openai.com", "nova-sentinel.io"]
    users = ["alice", "bob", "carol", "dave"]
    paths = ["home", "download", "docs", "products", "news"]

    X = []
    y = []
    for _ in range(count):
        if random.random() < 0.4:
            template = random.choice(malicious_templates)
            domain = random.choice(domains)
            path = random.choice(paths)
            user = random.choice(users)
            token = os.urandom(4).hex()
            url = template.format(domain=domain, path=path, user=user, token=token)
            label = 1
        else:
            template = random.choice(safe_templates)
            domain = random.choice(domains)
            path = random.choice(paths)
            post = random.choice(paths)
            product = random.choice(paths)
            url = template.format(domain=domain, path=path, post=post, product=product)
            label = 0

        features = URLFeatureExtractor.extract(url)
        if features is None:
            continue
        X.append(features)
        y.append(label)

    if len(X) == 0:
        raise RuntimeError("Failed to generate any URL features.")

    X_array = np.stack(X).astype(np.float32)
    y_array = np.array(y, dtype=np.int32)
    return X_array, y_array


def main() -> int:
    parser = argparse.ArgumentParser(description="Train phishing URL LightGBM model for NovaSentinel.")
    parser.add_argument("--output", default=MODEL_PATH, help="Output model path")
    parser.add_argument("--samples", type=int, default=2000, help="Number of sample URLs")
    parser.add_argument("--test-size", type=float, default=0.2, help="Holdout test size")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    X, y = sample_url_data(args.samples)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=args.test_size, random_state=42)

    model = lgb.LGBMClassifier(
        n_estimators=120,
        learning_rate=0.08,
        num_leaves=31,
        objective="binary",
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)
    logger.info("Training complete. Validation F1: %.3f", report["1"]["f1-score"])

    joblib.dump(model, args.output)
    print(f"Saved phishing model to {args.output}")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    raise SystemExit(main())
