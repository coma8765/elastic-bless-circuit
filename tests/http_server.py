from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
