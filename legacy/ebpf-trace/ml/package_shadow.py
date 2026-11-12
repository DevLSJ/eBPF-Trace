"""Package an existing, deployment-owned benchmark model for the shadow runner.

Never marks development benchmark metrics as independent production validation.
"""

import argparse
import hashlib
import json
from pathlib import Path

import joblib
import sklearn

from collector.feature_schema import CONTEXT_FEATURES


def package(source, destination, model_id):
    bundle = joblib.load(source)  # Explicit local administrator CLI; not an upload handler.
    if bundle["features"] != CONTEXT_FEATURES:
        raise ValueError("Only the 25-feature schema-2 contract can be packaged")
    directory = Path(destination)
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("Choose a new empty version directory; artifacts are immutable")
    artifact = directory / "model.pkl"
    joblib.dump(bundle["model"], artifact)
    manifest = {
        "id": model_id,
        "artifact": artifact.name,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "schema_version": 2,
        "sklearn_version": sklearn.__version__,
        "features": CONTEXT_FEATURES,
        "threshold": bundle["threshold"],
        "source": Path(source).name,
        "independent_validation": {
            "independent": False,
            "operator_reviewed": False,
            "attack_types": [],
            "missing_attack_types": [],
            "f1": None,
            "fpr": None,
        },
        "limitations": [
            "Development benchmark; independent validation is required before promotion"
        ],
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("destination")
    parser.add_argument("--id", required=True)
    args = parser.parse_args()
    result = package(args.source, args.destination, args.id)
    print(json.dumps({"id": result["id"], "sha256": result["sha256"], "stage": "offline"}))
