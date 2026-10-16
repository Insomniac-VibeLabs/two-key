"""#6: judge connections are pooled per origin and reused across threads and quorum rounds."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from two_key.judges import transport


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"          # keep-alive
    connections: list = []
    close_next = False
    status_next = 200

    def setup(self):
        super().setup()
        type(self).connections.append(self.client_address)

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps({"ok": True}).encode()
        cls = type(self)
        status, cls.status_next = cls.status_next, 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cls.close_next:
            cls.close_next = False
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Reuse(unittest.TestCase):
    def setUp(self):
        Handler.connections = []
        Handler.close_next, Handler.status_next = False, 200
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/chat"
        transport.reset_pool()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(transport.reset_pool)

    def call_in_thread(self):
        out = {}
        thread = threading.Thread(target=lambda: out.update(r=transport.pooled_transport(self.url, {}, {"q": 1}, 5)))
        thread.start()
        thread.join(10)
        return out.get("r")

    def test_a_second_round_on_another_thread_reuses_the_connection(self):
        self.assertEqual(self.call_in_thread(), {"ok": True})
        self.assertEqual(self.call_in_thread(), {"ok": True})
        self.assertEqual(len(Handler.connections), 1)

    def test_connection_close_is_not_pooled(self):
        Handler.close_next = True
        self.call_in_thread()
        self.call_in_thread()
        self.assertEqual(len(Handler.connections), 2)

    def test_an_error_status_closes_the_connection(self):
        Handler.status_next = 400
        with self.assertRaises(Exception):
            transport.pooled_transport(self.url, {}, {"q": 1}, 5)
        self.call_in_thread()
        self.assertEqual(len(Handler.connections), 2)

    def test_parallel_requests_get_their_own_connections(self):
        barrier = threading.Barrier(3)
        results = []

        def run():
            barrier.wait()
            results.append(transport.pooled_transport(self.url, {}, {"q": 1}, 5))
        threads = [threading.Thread(target=run) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(results, [{"ok": True}] * 3)
        self.assertLessEqual(len(Handler.connections), 3)
        before = len(Handler.connections)
        self.call_in_thread()
        self.assertEqual(len(Handler.connections), before)     # an idle one was reused


if __name__ == "__main__":
    unittest.main(verbosity=2)
