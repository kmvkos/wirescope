import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone


_executor = ThreadPoolExecutor(max_workers=2)

_jobs = {}
_lock = threading.Lock()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def create_job(job_type, target, function, *args, **kwargs):

    job_id = str(uuid.uuid4())

    job = {
        "id": job_id,
        "type": job_type,
        "target": target,

        "status": "queued",

        "created_at": utc_now(),
        "started_at": None,
        "finished_at": None,

        "progress": 0,

        "result": None,
        "error": None
    }

    with _lock:
        _jobs[job_id] = job

    _executor.submit(
        _run_job,
        job_id,
        function,
        args,
        kwargs
    )

    return job_id


def _run_job(
    job_id,
    function,
    args,
    kwargs
):

    update_job(
        job_id,
        status="running",
        started_at=utc_now(),
        progress=1
    )

    try:

        result = function(
            *args,
            **kwargs
        )

        update_job(
            job_id,
            status="completed",
            finished_at=utc_now(),
            progress=100,
            result=result
        )

    except Exception as exc:

        update_job(
            job_id,
            status="failed",
            finished_at=utc_now(),
            progress=100,
            error=str(exc)
        )


def update_job(job_id, **values):

    with _lock:

        job = _jobs.get(job_id)

        if not job:
            return False

        job.update(values)

    return True


def get_job(job_id):

    with _lock:

        job = _jobs.get(job_id)

        if not job:
            return None

        # Копию, чтобы внешний код
        # не менял внутренний объект.
        return dict(job)


def list_jobs():

    with _lock:
        return [
            dict(job)
            for job in _jobs.values()
        ]
