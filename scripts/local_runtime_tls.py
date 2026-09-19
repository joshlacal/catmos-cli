#!/usr/bin/env python3
"""Local qualification TLS terminator. No credentials or message bodies are logged."""
import http.client
import http.server
import json
import ssl
import sys

certificate, private_key, raw_port, upstream_port, hosts_file = sys.argv[1:]
allowed_hosts = set(json.load(open(hosts_file, encoding="utf-8")))

class Handler(http.server.BaseHTTPRequestHandler):
    def handle_method(self):
        host = self.headers.get("Host", "").split(":", 1)[0].lower()
        if host not in allowed_hosts or not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 16 * 1024 * 1024 or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            body = self.rfile.read(length)
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in {"connection", "proxy-authorization", "transfer-encoding"}}
            conn = http.client.HTTPConnection("127.0.0.1", int(upstream_port), timeout=45)
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse()
            if response.getheader("x-catmos-fixture-drop-response") == "1":
                # Upstream has committed; deliberately lose the entire response
                # before any downstream status/body, exercising ambiguous HTTP.
                conn.close()
                self.close_connection = True
                self.connection.close()
                return
            data = response.read(32 * 1024 * 1024 + 1)
            if len(data) > 32 * 1024 * 1024:
                self.send_error(502)
                return
            self.send_response(response.status)
            self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            conn.close()
        except (OSError, ValueError, http.client.HTTPException):
            self.send_error(502)

    do_GET = handle_method
    do_POST = handle_method

    def log_message(self, *_args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", int(raw_port)), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, private_key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(json.dumps({"port": server.server_port}), flush=True)
server.serve_forever()
