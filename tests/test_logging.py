import json
import logging

from config.logging import JsonFormatter, bind_log_context


def test_structured_log_context_propagates_audit_and_job_ids():
    record = logging.LogRecord(
        name="wirescope.passive.capture",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="capture started",
        args=(),
        exc_info=None,
    )

    with bind_log_context(audit_id="audit-1", job_id="job-1"):
        payload = json.loads(JsonFormatter().format(record))

    assert payload["component"] == "wirescope.passive.capture"
    assert payload["audit_id"] == "audit-1"
    assert payload["job_id"] == "job-1"
