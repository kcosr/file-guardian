#!/usr/bin/env python3
"""Disposable authenticated smart-HTTP Git server for live acceptance."""

from __future__ import annotations

import argparse
import base64
import http.server
import os
import ssl
import subprocess
import urllib.parse


MAX_REQUEST_BYTES = 64 * 1024 * 1024


class GitHandler(http.server.BaseHTTPRequestHandler):
    git_root: str
    backend: str

    def _authorized(self) -> bool:
        expected = "Basic " + base64.b64encode(
            f"{os.environ['FG_GIT_HTTP_USER']}:{os.environ['FG_GIT_HTTP_PASSWORD']}".encode()
        ).decode()
        if self.headers.get("Authorization") == expected:
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="file-guardian-acceptance"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _serve_git(self) -> None:
        if not self._authorized():
            return
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_REQUEST_BYTES:
            self.send_error(413)
            return
        request_body = self.rfile.read(length) if length else b""
        environment = {
            "GIT_PROJECT_ROOT": self.git_root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": "*",
            "PATH_INFO": parsed.path,
            "QUERY_STRING": parsed.query,
            "REQUEST_METHOD": self.command,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(length),
            "REMOTE_USER": os.environ["FG_GIT_HTTP_USER"],
            "REMOTE_ADDR": self.client_address[0],
            "SERVER_PROTOCOL": self.protocol_version,
            "SERVER_NAME": self.server.server_name,
            "SERVER_PORT": str(self.server.server_port),
        }
        result = subprocess.run(
            [self.backend],
            input=request_body,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            self.send_error(500)
            return
        header_block, separator, response_body = result.stdout.partition(b"\r\n\r\n")
        if not separator:
            header_block, separator, response_body = result.stdout.partition(b"\n\n")
        if not separator:
            self.send_error(500)
            return
        status = 200
        headers: list[tuple[str, str]] = []
        for raw_line in header_block.splitlines():
            name, delimiter, value = raw_line.decode("latin-1").partition(":")
            if not delimiter:
                self.send_error(500)
                return
            if name.lower() == "status":
                status = int(value.strip().split(" ", 1)[0])
            else:
                headers.append((name.strip(), value.strip()))
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self) -> None:  # noqa: N802 - inherited HTTP API
        self._serve_git()

    def do_POST(self) -> None:  # noqa: N802 - inherited HTTP API
        self._serve_git()

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-root", required=True)
    parser.add_argument("--backend", default="/usr/lib/git-core/git-http-backend")
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    GitHandler.git_root = args.git_root
    GitHandler.backend = args.backend
    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), GitHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.certificate, args.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
