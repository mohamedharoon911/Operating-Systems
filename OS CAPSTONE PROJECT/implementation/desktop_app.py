"""
OSentinel Standalone Desktop Application
Launches FastAPI backend in a background thread and opens a native OS Desktop GUI Window after verifying server readiness.
"""
import sys
import os
import time
import socket
import threading
import uvicorn

from server import app

def is_port_open(host="127.0.0.1", port=8000) -> bool:
    """Checks if port 8000 is open and accepting socket connections."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except Exception:
        return False

def start_backend():
    """Runs FastAPI backend on 127.0.0.1:8000 silently in background thread."""
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="error")

if __name__ == "__main__":
    # 1. Start backend server in daemon thread if not already running
    if not is_port_open():
        backend_thread = threading.Thread(target=start_backend, daemon=True)
        backend_thread.start()

        # Poll socket until server is active and accepting connections
        start_time = time.time()
        while not is_port_open():
            time.sleep(0.2)
            if time.time() - start_time > 10.0:
                break

    # 2. Launch Native OS Desktop GUI Window ONLY after server is ready
    try:
        import webview
        window = webview.create_window(
            title="OSentinel — Autonomous OS Process Protection",
            url="http://127.0.0.1:8000",
            width=1280,
            height=850,
            resizable=True,
            min_size=(1024, 700)
        )
        webview.start()
    except Exception as e:
        import webbrowser
        webbrowser.open("http://127.0.0.1:8000")
