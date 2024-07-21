import argparse
import curses
import json
import threading
import getpass
import textwrap
import time
import os
import queue
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_and_decompress(data:str, password:str) -> str:
    # Check if the encrypted data contains the expected segments
    if ':' not in data:
        print("Encrypted data format error: Expected segments not found.")
        return
    salt, iv, data = map(bytes.fromhex, data.split(':'))
    #print("Salt:", salt)
    #print("IV:", iv)
    #print("Data:", data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    # Decompress using gzip
    with gzip.GzipFile(fileobj=io.BytesIO(decrypted), mode='rb') as gzip_file:
        decompressed = gzip_file.read()
    
    return decompressed.decode('utf-8')

def should_include_event(event, program_id=None, run_id=None):
    event_program_id = str(event.get('programId', ''))
    event_run_id = str(event.get('runId', ''))
    return (program_id is None or event_program_id == str(program_id)) and \
           (run_id is None or event_run_id == str(run_id))

# Define this at the module level, outside of any function
level_color = {
    'error': 2,
    'warn': 3,
    'info': 4,
    'http': 5,
    'verbose': 6,
    'debug': 7,
    'silly': 8
}


class LogReader:
    def __init__(self, file_path, cleartext, password, program_id, run_id):
        self.file_path = file_path
        self.cleartext = cleartext
        self.password = password
        self.program_id = program_id
        self.run_id = run_id
        self.file_size = os.path.getsize(file_path)
        self.position = self.file_size
        self.lock = threading.Lock()
        self.event_queue = queue.Queue()
        self.stop_event = threading.Event()

    def start_reading(self):
        self.thread = threading.Thread(target=self._read_file)
        self.thread.start()

    def stop_reading(self):
        self.stop_event.set()
        self.thread.join()

    def _read_file(self):
        with open(self.file_path, 'rb') as file:
            while not self.stop_event.is_set():
                file.seek(0, os.SEEK_END)
                if file.tell() > self.file_size:
                    file.seek(self.file_size)
                    new_data = file.read()
                    self._process_new_data(new_data)
                    self.file_size = file.tell()
                time.sleep(0.1)

    def _process_new_data(self, data):
        lines = data.decode('utf-8').split('\n')
        for line in lines:
            if line.strip():
                event = self.process_line(line)
                if event:
                    self.event_queue.put(event)

    def process_line(self, line):
        if not self.cleartext:
            try:
                decrypted_data = decrypt_and_decompress(line.strip(), self.password)
                event = json.loads(decrypted_data)
            except Exception as e:
                print(f"Failed to decrypt and decompress log file: {e}")
                return None
        else:
            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError as e:
                print(f"Failed to decode line: {e}")
                return None

        if should_include_event(event, self.program_id, self.run_id):
            return event
        return None

    def read_events_backwards(self, num_events):
        events = []
        with self.lock:
            with open(self.file_path, 'rb') as file:
                chunk_size = 4096
                while len(events) < num_events and self.position > 0:
                    chunk_size = min(chunk_size, self.position)
                    self.position -= chunk_size
                    file.seek(self.position)
                    chunk = file.read(chunk_size).decode('utf-8')
                    lines = chunk.split('\n')

                    if self.position != 0:
                        lines = lines[1:]  # Remove partial line if not at file start

                    for line in reversed(lines):
                        if line.strip():
                            event = self.process_line(line)
                            if event:
                                events.append(event)
                                if len(events) == num_events:
                                    break

        return list(reversed(events))

def display_events(stdscr, log_reader):
    height, width = stdscr.getmaxyx()
    event_list = log_reader.read_events_backwards(height)
    current_row = 0
    offset = 0
    new_data_available = False
    new_events_count = 0
    auto_scroll = True

    stdscr.nodelay(True)
    stdscr.timeout(100)

    while True:
        height, width = stdscr.getmaxyx()
        should_redraw = False

        # Check for new events
        while not log_reader.event_queue.empty():
            new_event = log_reader.event_queue.get_nowait()
            if auto_scroll:
                event_list.insert(0, new_event)
                current_row += 1
                offset += 1
                should_redraw = True
            else:
                new_data_available = True
                new_events_count += 1

        key = stdscr.getch()

        if key == -1:
            if should_redraw:
                stdscr.clear()
                draw_events(stdscr, event_list, current_row, offset, height, width, new_data_available, new_events_count)
                stdscr.refresh()
            continue
        elif key in [curses.KEY_UP, ord('w')]:
            if current_row > 0:
                current_row -= 1
                if current_row < offset:
                    offset = current_row
                auto_scroll = False
                should_redraw = True
        elif key in [curses.KEY_DOWN, ord('s')]:
            if current_row < len(event_list) - 1:
                current_row += 1
                if current_row >= offset + height:
                    offset = current_row - height + 1
                should_redraw = True
            elif offset + height >= len(event_list):
                more_events = log_reader.read_events_backwards(height)
                event_list.extend(more_events)
                should_redraw = True
            
            if current_row == len(event_list) - 1:
                auto_scroll = True
        elif key == ord('a'):
            auto_scroll = not auto_scroll
            if auto_scroll and new_data_available:
                while not log_reader.event_queue.empty():
                    new_event = log_reader.event_queue.get_nowait()
                    event_list.insert(0, new_event)
                    current_row += 1
                    offset += 1
                new_data_available = False
                new_events_count = 0
            should_redraw = True
        elif key == curses.KEY_PPAGE:
            current_row = max(0, current_row - height)
            offset = max(0, offset - height)
            auto_scroll = False
            should_redraw = True
        elif key == curses.KEY_NPAGE:
            if current_row + height < len(event_list):
                current_row = min(len(event_list) - 1, current_row + height)
                offset = min(max(0, len(event_list) - height), current_row)
            else:
                more_events = log_reader.read_events_backwards(height)
                event_list.extend(more_events)
                current_row = min(len(event_list) - 1, current_row + height)
                offset = min(max(0, len(event_list) - height), current_row)
            should_redraw = True
        elif key == ord('q'):
            break
        elif key == ord('d'):
            show_event_details(stdscr, event_list, current_row, width, height)
            should_redraw = True

        if should_redraw:
            stdscr.clear()
            draw_events(stdscr, event_list, current_row, offset, height, width, new_data_available, new_events_count)
            stdscr.refresh()

    def draw_events(stdscr, event_list, current_row, offset, height, width, new_data_available, new_events_count):
        for idx in range(offset, min(offset + height, len(event_list))):
            event = event_list[idx]
            level = event.get('level', '').lower()
            color_pair = level_color.get(level, 1)  # Default color if level is not matched

            # Determine if there are additional keys
            expected_keys = {'level', 'message', 'ms', 'timestamp', 'programId', 'runId'}
            connector = '+' if set(event.keys()) - expected_keys else '-'

            timestamp = event.get('timestamp', 'N/A')
            message = event.get('message', 'No message')
            program_id = event.get('programId')
            run_id = event.get('runId')
            display_str = f"{timestamp} {connector}"
            if program_id or run_id:
                display_str += " ["
            if program_id:
                display_str += f"P{program_id}"
            if run_id:
                display_str += f"R{run_id}"
            if program_id or run_id:
                display_str += "]"
            display_str += f" {message}"
            display_str = display_str[:width-1]  # Ensure string does not exceed screen width

            y_pos = idx - offset
            if 0 <= y_pos < height:
                if idx == current_row:
                    stdscr.attron(curses.color_pair(color_pair) | curses.A_REVERSE)
                    stdscr.addstr(y_pos, 0, display_str)
                    stdscr.attroff(curses.color_pair(color_pair) | curses.A_REVERSE)
                else:
                    stdscr.attron(curses.color_pair(color_pair))
                    stdscr.addstr(y_pos, 0, display_str)
                    stdscr.attroff(curses.color_pair(color_pair))

        if new_data_available and new_events_count > 0:
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(height - 1, 0, f"{new_events_count} new log(s) available. Scroll to top to view.")
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

    def show_event_details(stdscr, event_list, current_row, width, height):
        """ Display detailed JSON event data with formatted keys. """
        stdscr.clear()
        details = json.dumps(event_list[current_row], indent=4).replace('\\n', '\n')
        details_lines = details.split('\n')

        wrapped_lines = []
        for line in details_lines:
            wrapped_lines.extend(textwrap.wrap(line, width))

        details_offset = 0
        while True:
            stdscr.clear()
            for i in range(height):
                line_idx = i + details_offset
                if line_idx < len(wrapped_lines):
                    line = wrapped_lines[line_idx]
                    if line.strip().startswith('"') and ':' in line:
                        key, value = line.split(':', 1)
                        stdscr.attron(curses.color_pair(4))  # Verbose for JSON keys, set as light green earlier
                        stdscr.addstr(i, 0, key + ':')
                        stdscr.attroff(curses.color_pair(4))
                        if i < height - 1:
                            stdscr.addstr(value)
                    else:
                        if i < height - 1:
                            stdscr.addstr(i, 0, line)
                else:
                    break

            details_key = stdscr.getch()
            if details_key in [curses.KEY_UP, ord('w')] and details_offset > 0:
                details_offset -= 1
            elif details_key in [curses.KEY_DOWN, ord('s')] and details_offset < len(wrapped_lines) - height:
                details_offset += 1
            elif details_key == curses.KEY_PPAGE:
                details_offset = max(0, details_offset - height)
            elif details_key == curses.KEY_NPAGE:
                details_offset = min(len(wrapped_lines) - height, details_offset + height)
            elif details_key == ord('q') or details_key == ord('d'):
                break

            stdscr.refresh()

def main():
    parser = argparse.ArgumentParser(description="Log Viewer")
    parser.add_argument("--logfile", type=str, required=True, help="Path to the log file")
    parser.add_argument("--cleartext", action="store_true", help="Indicates the log file is in clear text")
    parser.add_argument("--programId", type=str, help="Only show logs for the specified program ID")
    parser.add_argument("--runId", type=str, help="Only show logs for the specified run ID")
    args = parser.parse_args()

    log_file_path = args.logfile
    cleartext = args.cleartext
    program_id = args.programId
    run_id = args.runId
    password = None

    if not cleartext:
        password = getpass.getpass(prompt="Enter support key: ")

    log_reader = LogReader(log_file_path, cleartext, password, program_id, run_id)

    def run_curses(stdscr):
        curses.start_color()
        curses.use_default_colors()
        curses.curs_set(0)
        stdscr.nodelay(True)
        log_reader.start_reading()
        try:
            display_events(stdscr, log_reader)
        finally:
            log_reader.stop_reading()

    curses.wrapper(run_curses)

if __name__ == "__main__":
    main()