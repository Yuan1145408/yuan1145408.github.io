from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

class UTF8Handler(SimpleHTTPRequestHandler):
    # 确保文本类资源都带上 charset=utf-8，避免中文被浏览器误判编码
    extensions_map = SimpleHTTPRequestHandler.extensions_map.copy()
    extensions_map.update({
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8',
        '.txt': 'text/plain; charset=utf-8',
        '.svg': 'image/svg+xml; charset=utf-8',
    })

if __name__ == '__main__':
    port = 5600
    httpd = ThreadingHTTPServer(('', port), UTF8Handler)
    print(f"Serving HTTP on 0.0.0.0 port {port} (http://localhost:{port}/) ...")
    httpd.serve_forever()