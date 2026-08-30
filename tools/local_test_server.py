"""
TRACE — Local Test Server
============================
A minimal HTTP server for manually exercising TRACE against a
known, controllable target during development. Not part of the
TRACE scanning engine itself — this is a dev/testing utility only.

Run:
    python3 tools/local_test_server.py

Then in another terminal:
    python3 trace.py
    Enter target: 127.0.0.1:8000
"""

from http.server import HTTPServer, BaseHTTPRequestHandler

HOST = "127.0.0.1"
PORT = 8000


class TraceTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>TRACE Local Server</h1>")
            self.wfile.write(b"<p>Server is working!</p>")
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>404 Not Found</h1>")


def main():
    server = HTTPServer((HOST, PORT), TraceTestHandler)
    print(f"TRACE local server running on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
