from flask import (
    Flask, Response, render_template,
    request, jsonify, send_from_directory
)
import threading
import queue
from pathlib import Path

from scan import scan
from log import StreamToQueue

app = Flask(__name__)

log_queue = queue.Queue()

BASE_DIR = Path(__file__).parent.parent
RESULTS_DIR = BASE_DIR / 'results'

RESULTS_DIR.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {'json', 'txt', 'log', 'xml'}


def log_writer(message: str):
    log_queue.put(message)


def event_stream():
    while True:
        msg = log_queue.get()
        yield f"data: {msg}\n\n"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/start_scan', methods=['POST'])
def start_scan():
    url = request.form.get('url')
    port = request.form.get('port', type=int)
    use_https = request.form.get('https') == 'true'
    wwagr = request.form.get('wwagr', type=int, default=3)

    subdomswordlist = request.form.get('subdomswordlist') or '../wordlists/subdomain-list.txt'
    dirswordlist = request.form.get('dirswordlist') or '../wordlists/directory-list.txt'

    if not url:
        return jsonify({"error": "URL is required"}), 400

    def run_scan_with_redirect():
        from contextlib import redirect_stdout
        with redirect_stdout(StreamToQueue(log_queue)):
            scan(
                url,
                port=port,
                tls=use_https,
                wwagr=wwagr,
                subdomswordlist=subdomswordlist,
                dirswordlist=dirswordlist
            )

    threading.Thread(target=run_scan_with_redirect, daemon=True).start()

    return jsonify({
        "status": "scan_started",
        "url": url,
        "status_url": "/stream_logs"
    })


@app.route('/results')
def show_results():
    print(f"Looking for files in: {RESULTS_DIR}")

    result_files = []
    for file_path in RESULTS_DIR.rglob('*'):
        if file_path.is_file() and file_path.suffix[1:].lower() in ALLOWED_EXTENSIONS:
            rel_path = str(file_path.relative_to(RESULTS_DIR))
            result_files.append({
                "name": file_path.name,
                "path": rel_path,
                "size": file_path.stat().st_size,
                "type": file_path.suffix[1:].lower()
            })
            print(f"Found file: {rel_path}")

    if not result_files:
        print("No result files found!")

    return render_template('results.html', files=result_files)


@app.route('/results/<path:filename>')
def get_result(filename):
    file_ext = Path(filename).suffix[1:].lower()
    mimetype = {
        'json': 'application/json',
        'txt': 'text/plain',
        'log': 'text/plain',
        'xml': 'application/xml'
    }.get(file_ext, 'application/octet-stream')

    return send_from_directory(RESULTS_DIR, filename, mimetype=mimetype)


@app.route('/stream_logs')
def stream_logs():
    def event_stream():
        while True:
            msg = log_queue.get()
            yield f"data: {msg}\n\n"

    return Response(event_stream(), mimetype='text/event-stream')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
