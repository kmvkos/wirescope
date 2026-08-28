from pathlib import Path

from tests.helpers import http_request


ROOT = Path(__file__).resolve().parents[1]


def test_root_loads_versioned_evidence_gap_assets_in_safe_order(api_context):
    app, _jobs, _evidence, _environment = api_context
    response = http_request(app, "GET", "/", auth=False)
    assert response.status_code == 200
    assert "/static/global_analysis_gaps.css?v=20260828-ui32" in response.text
    assert "/static/global_analysis_gaps.js?v=20260828-ui32" in response.text
    assert response.text.index("global_analysis.js") < response.text.index("global_analysis_gaps.js")
    assert response.text.index("global_analysis_gaps.js") < response.text.index("product_coherence.js")


def test_evidence_gap_ui_copy_exposes_reason_collection_and_safe_conclusion():
    script = (ROOT / "frontend/global_analysis_gaps.js").read_text(encoding="utf-8")
    assert "Что ещё нужно подтвердить" in script
    assert "Что уже есть" in script
    assert "Чего не хватает" in script
    assert "Как добрать данные" in script
    assert "Пока корректно утверждать" in script
    assert "textContent" in script
    assert "innerHTML" not in script
