import os
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


class ProxyHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if parsed.path != "/download":
            self.send_error(404, "Not Found")
            return

        qs = urllib.parse.parse_qs(parsed.query)
        url = qs.get("url", [None])[0]
        filename = qs.get("filename", [None])[0]
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            self.send_error(400, "Invalid or missing url")
            return

        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                # Derive filename
                cd = resp.headers.get("Content-Disposition")
                if not filename:
                    if cd and "filename=" in cd:
                        filename = cd.split("filename=")[-1].strip().strip('"')
                    else:
                        path_name = os.path.basename(urllib.parse.urlparse(url).path)
                        filename = path_name or "download.bin"

                content_type = resp.headers.get("Content-Type") or "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Disposition", f"attachment; filename=\"{filename}\"")
                # If upstream provides length, forward it
                clen = resp.headers.get("Content-Length")
                if clen:
                    self.send_header("Content-Length", clen)
                # CORS
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

                # Stream data in chunks
                chunk_size = 64 * 1024
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception as e:
            self.send_error(502, f"Upstream error: {e}")


def run(host="0.0.0.0", port=5180):
    httpd = HTTPServer((host, port), ProxyHandler)
    print(f"[proxy] listening on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = 5180
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run(port=port)