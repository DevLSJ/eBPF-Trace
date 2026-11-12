from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_analyze_roundtrip():
    body = {
        "commit": {"repoFullName": "owner/repo", "sha": "a" * 40, "message": "x"},
        "files": [{"filename": "src/a.js", "additions": 3, "deletions": 1}],
        "diff": "diff --git a/src/a.js b/src/a.js\n+hello",
        "options": {"forceLlm": False},
    }
    r = client.post("/analyze", json=body)
    assert r.status_code == 200
    d = r.json()
    assert d["riskLevel"] == "LOW"
    assert d["llm"]["status"] == "SKIPPED_GATE"
    assert d["preprocess"]["analyzedBytes"] > 0
    # camelCase 응답 확인
    assert "matchedRules" in d["static"]
