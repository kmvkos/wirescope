from pathlib import Path


FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def test_runtime_stop_handlers_do_not_navigate_to_audit_confirm_screen():
    runtime = (FRONTEND / "progress_runtime.js").read_text(encoding="utf-8")

    assert 'document.getElementById("listen-stop-button")' in runtime
    assert 'confirmModal(t("listen.stopTitle"), t("listen.stopBody"))' in runtime
    assert 'event.stopImmediatePropagation()' in runtime
    assert 'document.getElementById("stop-audit-button")' in runtime
    assert 'await api("POST", `/api/jobs/${state.jobId}/cancel`)' in runtime
    assert 'await showSummary()' not in runtime
    assert 'Останавливаем Nmap' in runtime


def test_manual_scope_overrides_automatic_interface_prefix():
    runtime = (FRONTEND / "progress_runtime.js").read_text(encoding="utf-8")

    assert 'const manual = parseTargets(state.draft.extras || "")' in runtime
    assert 'const source = manual.length ? manual : (state.draft.proposed || [])' in runtime
    assert 'window.combinedTargets = function combinedTargetsOperatorScope()' in runtime


def test_runtime_treats_naive_iso_timestamps_as_utc():
    runtime = (FRONTEND / "progress_runtime.js").read_text(encoding="utf-8")

    assert 'return `${text}Z`' in runtime
    assert 'window.parseTime = function parseWireScopeTime(value)' in runtime


def test_progress_has_operator_readable_step_details_and_live_nmap_line():
    runtime = (FRONTEND / "progress_runtime.js").read_text(encoding="utf-8")

    assert 'полный диапазон 1–65535 быстрым sweep' in runtime
    assert 'только на найденных открытых TCP-портах' in runtime
    assert 'Nmap: TCP top-1000' in runtime
    assert 'progress-live-result' in runtime
    assert 'Nmap: ожидаем первую статистику процесса' in runtime
    assert 'tshark разбирает сохранённые пакеты' in runtime
    assert 'Пассивные датчики анализируют протоколы' in runtime
    assert 'Применяем правила findings' in runtime
    assert 'Формируем понятный отчёт' in runtime
