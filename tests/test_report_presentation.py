from reports.html_v2 import render_html
from tests.test_report_builder import sample_report


def test_modern_html_report_is_russian_readable_and_escapes_network_copy():
    html = render_html(sample_report())

    assert 'lang="ru"' in html
    assert "Результат аудита" in html
    assert "Обнаруженные проблемы" in html
    assert "Что обнаружено" in html
    assert "Почему это важно" in html
    assert "Что рекомендуется сделать" in html
    assert "План действий" in html
    assert "Устройства" in html
    assert "Обнаруженные службы" in html
    assert "Технические данные" in html
    assert "ВЫСОКАЯ" not in html  # HTML uses normal-case Russian badges.
    assert "Высокая" in html
    assert "Стандартный" in html
    assert "Сервер" in html

    # Finding titles are network/rule-derived content and must stay escaped.
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "secret-tool-output" not in html


def test_modern_html_report_has_print_and_mobile_layouts():
    html = render_html(sample_report())

    assert "@media print" in html
    assert "@media(max-width:520px)" in html
    assert 'class="toc"' in html
    assert 'id="executive-summary"' in html
    assert 'id="technical"' in html
