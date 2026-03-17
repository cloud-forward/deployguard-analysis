import logging

from fastapi.testclient import TestClient

from app.main import app


def test_request_logging_generates_request_id_and_logs_normal_response(caplog):
    with caplog.at_level(logging.INFO, logger="deployguard.request"):
        with TestClient(app) as client:
            response = client.get("/")

    assert response.status_code == 200
    assert response.headers["X-Request-ID"]

    records = [record for record in caplog.records if record.name == "deployguard.request"]
    assert records
    record = records[-1]
    assert record.method == "GET"
    assert record.path == "/"
    assert record.status_code == 200
    assert record.request_id == response.headers["X-Request-ID"]
    assert record.duration_ms >= 0


def test_request_logging_propagates_request_id_and_logs_unhandled_exception(caplog):
    async def boom():
        raise RuntimeError("boom")

    app.add_api_route("/_test/request-logging-error", boom, methods=["GET"])

    try:
        with caplog.at_level(logging.INFO, logger="deployguard.request"):
            with TestClient(app, raise_server_exceptions=False) as client:
                response = client.get("/_test/request-logging-error", headers={"X-Request-ID": "req-123"})

        assert response.status_code == 500

        records = [record for record in caplog.records if record.name == "deployguard.request"]
        assert records
        record = records[-1]
        assert record.method == "GET"
        assert record.path == "/_test/request-logging-error"
        assert record.status_code == 500
        assert record.request_id == "req-123"
        assert record.duration_ms >= 0
    finally:
        app.router.routes.pop()
