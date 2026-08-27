from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_correlated_assessment_is_the_user_facing_name() -> None:
    source = (ROOT / "frontend" / "global_analysis.js").read_text(encoding="utf-8")

    assert "Корреляция результатов" in source
    assert "CORRELATED ASSESSMENT" in source
    assert "GLOBAL CORRELATION ANALYSIS" not in source
    assert '>Глобальный анализ<' not in source


def test_global_analysis_identifiers_remain_for_api_compatibility() -> None:
    source = (ROOT / "frontend" / "global_analysis.js").read_text(encoding="utf-8")

    assert "/global-analysis" in source
    assert "WireScopeGlobalAnalysis" in source
