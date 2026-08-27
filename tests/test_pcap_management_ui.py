from pathlib import Path

from tests.helpers import http_request


ROOT = Path(__file__).resolve().parents[1]


def test_root_loads_versioned_pcap_management_script(api_context):
    app, _jobs, _evidence, _environment = api_context
    response = http_request(app, "GET", "/", auth=False)
    assert response.status_code == 200
    assert "/static/pcap_management.js?v=20260827-ui30" in response.text
    assert response.text.index("traffic_analysis.js") < response.text.index("pcap_management.js")


def test_pcap_management_ui_hides_manually_deleted_rows_but_preserves_history():
    script = (ROOT / "frontend/pcap_management.js").read_text(encoding="utf-8")
    assert 'request("DELETE", `/captures/${encodeURIComponent(jobId)}/pcap`)' in script
    assert "Запись исчезнет из списка сохранённых PCAP" in script
    assert "История захвата и уже рассчитанные анализы останутся" in script
    assert "Повторно анализировать этот захват без файла PCAP будет нельзя" in script
    assert "row.remove()" in script
    assert "Сохранённых PCAP нет" in script
    assert 'download.hidden = !session.pcap_url' in script
    assert 'analyze.hidden = true' in script
    assert "PCAP удалён. История записи и уже готовые анализы сохранены." in script
    assert "PCAP недоступен" in script
    assert 'me.role' not in script or 'currentRole' in script