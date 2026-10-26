"""Serve the 0xMP web client over HTTP and open it in the browser.

Double-clicking index.html (file://) does NOT work: browsers block ES
module imports (oxmp.js) from file:// origins under the CORS policy.
Serving this folder over http:// fixes that.

Usage:  python clients/web/run_web.py [--port 8000] [--no-browser]
Stop:   Ctrl+C
"""
from __future__ import annotations

import argparse
import http.server
import threading
import webbrowser
from functools import partial
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    directory = Path(__file__).resolve().parent
    handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"0xMP web client: {url}  (Ctrl+C to stop)")
    print("Note: the 0xMP server (python -m server.main) must also be running.")
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
