import sys

from providers.tools import (
    CancellationToken,
    ToolCommand,
    ToolErrorCode,
    ToolRunner,
)


def test_tool_runner_returns_structured_success():
    runner = ToolRunner()

    result = runner.run(
        ToolCommand(
            tool=sys.executable,
            args=["-c", "print('ready')"],
        )
    )

    assert result.success is True
    assert result.exit_code == 0
    assert result.stdout.strip() == "ready"
    assert result.stderr == ""
    assert result.error is None
    assert result.started_at <= result.finished_at
    assert result.duration_seconds >= 0
    assert runner.invocation_count(sys.executable) == 1


def test_tool_runner_preserves_non_zero_stderr():
    result = ToolRunner().run(
        ToolCommand(
            tool=sys.executable,
            args=[
                "-c",
                "import sys; print('bad input', file=sys.stderr); sys.exit(7)",
            ],
        )
    )

    assert result.success is False
    assert result.exit_code == 7
    assert "bad input" in result.stderr
    assert result.error is not None
    assert result.error.code == ToolErrorCode.NON_ZERO_EXIT


def test_tool_runner_classifies_missing_binary():
    result = ToolRunner().run(
        ToolCommand(tool="/definitely/missing/wirescope-tool")
    )

    assert result.success is False
    assert result.exit_code is None
    assert result.error is not None
    assert result.error.code == ToolErrorCode.MISSING_BINARY


def test_tool_runner_classifies_timeout():
    result = ToolRunner().run(
        ToolCommand(
            tool=sys.executable,
            args=["-c", "import time; time.sleep(10)"],
            timeout_seconds=0.05,
        )
    )

    assert result.success is False
    assert result.timed_out is True
    assert result.error is not None
    assert result.error.code == ToolErrorCode.TIMEOUT


def test_tool_runner_supports_cancellation():
    token = CancellationToken()
    token.cancel()

    result = ToolRunner().run(
        ToolCommand(
            tool=sys.executable,
            args=["-c", "import time; time.sleep(10)"],
        ),
        cancellation_token=token,
    )

    assert result.success is False
    assert result.cancelled is True
    assert result.error is not None
    assert result.error.code == ToolErrorCode.CANCELLED


def test_tool_runner_redacts_sensitive_arguments():
    result = ToolRunner().run(
        ToolCommand(
            tool=sys.executable,
            args=["-c", "print('ok')", "secret-value"],
            sensitive_arg_indexes={3},
        )
    )

    assert result.success is True
    assert result.command[-1] == "<redacted>"
    assert "secret-value" not in result.command


def test_tool_runner_can_stream_stdout_to_reference(tmp_path):
    output_path = tmp_path / "tool-output.jsonl"

    result = ToolRunner().run(
        ToolCommand(
            tool=sys.executable,
            args=["-c", "print('{\"packet\": 1}')"],
            stdout_path=output_path,
        )
    )

    assert result.success is True
    assert result.stdout == ""
    assert result.stdout_reference == str(output_path)
    assert output_path.read_text().strip() == '{"packet": 1}'


def test_tool_runner_classifies_start_permission_error(monkeypatch):
    def deny(*_args, **_kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr("providers.tools.subprocess.Popen", deny)

    result = ToolRunner().run(ToolCommand(tool="dumpcap"))

    assert result.success is False
    assert result.error is not None
    assert result.error.code == ToolErrorCode.PERMISSION_DENIED
