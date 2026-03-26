import asyncio
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch, MagicMock

import pytest

from cogniwall.audit import AuditClient


class TestAuditClientRecord:
    def test_record_enqueues_event(self):
        client = AuditClient(endpoint="http://localhost:9999/api/events")
        event = {"event_id": "abc", "status": "approved"}
        client.record(event)
        assert len(client._queue) == 1
        assert client._queue[0] == event

    def test_record_drops_oldest_when_full(self):
        client = AuditClient(
            endpoint="http://localhost:9999/api/events",
            max_queue_size=2,
        )
        client.record({"event_id": "1"})
        client.record({"event_id": "2"})
        client.record({"event_id": "3"})
        assert len(client._queue) == 2
        assert client._queue[0]["event_id"] == "2"
        assert client._queue[1]["event_id"] == "3"


class TestAuditClientFlush:
    def test_flush_sends_batch(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                body = json.loads(self.rfile.read(length))
                received.extend(body)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"accepted": 2}')

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()

        client = AuditClient(
            endpoint=f"http://127.0.0.1:{port}/api/events",
            flush_mode="async",
            batch_size=10,
        )
        client.record({"event_id": "a", "status": "approved"})
        client.record({"event_id": "b", "status": "blocked"})
        client._flush_sync()

        thread.join(timeout=5)
        server.server_close()
        assert len(received) == 2
        assert received[0]["event_id"] == "a"
        assert len(client._queue) == 0

    def test_flush_respects_batch_size(self):
        client = AuditClient(
            endpoint="http://localhost:9999/api/events",
            batch_size=2,
        )
        for i in range(5):
            client.record({"event_id": str(i)})

        with patch.object(client, "_post") as mock_post:
            mock_post.return_value = True
            client._flush_sync()

        assert mock_post.call_count == 1
        sent = json.loads(mock_post.call_args[0][0])
        assert len(sent) == 2
        assert len(client._queue) == 3


class TestAuditClientSyncMode:
    def test_sync_mode_posts_immediately(self):
        client = AuditClient(
            endpoint="http://localhost:9999/api/events",
            flush_mode="sync",
        )
        with patch.object(client, "_post") as mock_post:
            mock_post.return_value = True
            client.record({"event_id": "x", "status": "blocked"})

        mock_post.assert_called_once()
        assert len(client._queue) == 0


class TestAuditClientApiKey:
    def test_api_key_sent_in_header(self):
        received_headers = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received_headers["X-CogniWall-Key"] = self.headers.get("X-CogniWall-Key")
                length = int(self.headers["Content-Length"])
                self.rfile.read(length)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"accepted": 1}')

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        port = server.server_address[1]
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()

        client = AuditClient(
            endpoint=f"http://127.0.0.1:{port}/api/events",
            api_key="test-key-123",
        )
        client.record({"event_id": "a"})
        client._flush_sync()

        thread.join(timeout=5)
        server.server_close()
        assert received_headers["X-CogniWall-Key"] == "test-key-123"


class TestAuditClientFailureHandling:
    def test_failed_post_logs_warning(self, caplog):
        client = AuditClient(endpoint="http://127.0.0.1:1/api/events")
        client.record({"event_id": "a"})
        with caplog.at_level(logging.WARNING, logger="cogniwall.audit"):
            client._flush_sync()
        assert len(client._queue) == 0  # events are discarded, not re-queued
        assert len(caplog.records) > 0

    def test_failed_sync_post_does_not_raise(self):
        client = AuditClient(
            endpoint="http://127.0.0.1:1/api/events",
            flush_mode="sync",
        )
        client.record({"event_id": "a"})


class TestAuditClientFromConfig:
    def test_from_config_all_params(self):
        client = AuditClient.from_config({
            "endpoint": "http://localhost:3000/api/events",
            "api_key": "my-key",
            "include_payload": True,
            "flush_mode": "sync",
            "flush_interval": 10.0,
            "batch_size": 100,
        })
        assert client.endpoint == "http://localhost:3000/api/events"
        assert client.api_key == "my-key"
        assert client.include_payload is True
        assert client.flush_mode == "sync"
        assert client.flush_interval == 10.0
        assert client.batch_size == 100

    def test_from_config_defaults(self):
        client = AuditClient.from_config({
            "endpoint": "http://localhost:3000/api/events",
        })
        assert client.api_key is None
        assert client.include_payload is False
        assert client.flush_mode == "async"
        assert client.flush_interval == 5.0
        assert client.batch_size == 50

    def test_from_config_api_key_env(self):
        with patch.dict("os.environ", {"MY_KEY": "env-key-value"}):
            client = AuditClient.from_config({
                "endpoint": "http://localhost:3000/api/events",
                "api_key_env": "MY_KEY",
            })
        assert client.api_key == "env-key-value"
