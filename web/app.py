import os
import sys
import threading

ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

sys.path.insert(0, ROOT)

from flask import Flask, render_template, jsonify  # type: ignore
from flask_socketio import SocketIO  # type: ignore

from hypersensor.stats import get_dashboard_data
from hypersensor.capture import start_capture

app = Flask(__name__)

socketio = SocketIO(
    app,
    cors_allowed_origins="*"
)

capture_started = False


def start_ids():

    global capture_started

    if not capture_started:

        capture_started = True

        threading.Thread(
            target=start_capture,
            daemon=True
        ).start()


@app.route("/")
def dashboard():

    start_ids()

    return render_template(
        "dashboard.html"
    )


@app.route("/api/dashboard")
def api_dashboard():

    return jsonify(
        get_dashboard_data()
    )
@socketio.on("request_update")
def handle_update():

    from hypersensor.stats import get_dashboard_data

    socketio.emit(
        "dashboard_update",
        get_dashboard_data()
    )

if __name__ == "__main__":

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )