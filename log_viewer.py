import argparse
import curses
import json
import threading
import getpass
import textwrap
import time
import gzip
import io
import os
import queue
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging

# Set up basic logging configuration
logging.basicConfig(filename='log_viewer_errors.log', 
                    level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

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

def should_include_event(event, program_id=None, run_id=None):
    try:
        event_program_id = str(event.get('programId', ''))
        event_run_id = str(event.get('runId', ''))
        return (program_id is None or event_program_id == str(program_id)) and \
               (run_id is None or event_run_id == str(run_id))
    except Exception as e:
        logging.error(f"Error while filtering events: {e}")
        return False

def decrypt_and_decompress(data: str, password: str) -> str:
    try:
        # Check if the encrypted data contains the expected segments
        if ':' not in data:
            logging.error(f"Encrypted data format error: Expected segments not found.")
            return None
        salt, iv, data = map(bytes.fromhex, data.split(':'))
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
    except Exception as e:
        logging.error(f"Error during decryption and decompression: {e}")
        return None

def process_line(line, event_queue, cleartext, password, program_id, run_id):
    if not line.strip():
        return  # Ignore empty lines

    try:
        if not cleartext:
            decrypted_data = decrypt_and_decompress(line.strip(), password)
            if not decrypted_data:
                return
            event = json.loads(decrypted_data)
        else:
            event = json.loads(line.strip())

        # Validate that the event is a dictionary with the expected structure
        if not isinstance(event, dict):
            logging.error(f"Unexpected JSON structure: {event}")
            return

        # Optionally, you could check for required keys:
        required_keys = {'level', 'message', 'timestamp'}
        if not required_keys.issubset(event):
            logging.error(f"Missing expected keys in event: {event}")
            return

        if should_include_event(event, program_id, run_id):
            event_queue.put(event)  # Add the event to the queue

    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode line: {e}")
    except Exception as e:
        logging.error(f"Unexpected error processing line: {e}")

def read_last_lines(file_path, n=100):
    try:
        with open(file_path, 'rb') as file:
            file.seek(0, os.SEEK_END)
            end_position = file.tell()
            position = end_position
            lines = []
            while position > 0 and len(lines) < n:
                position -= 1
                file.seek(position)
                if file.read(1) == b'\n':
                    if position != end_position - 1:  # Avoid empty line at the end
                        file.seek(position + 1)
                        lines.append(file.readline().decode('utf-8').strip())
            if position == 0 and end_position > 0:  # Read the first line if it wasn't
                file.seek(0)
                lines.append(file.readline().decode('utf-8').strip())
            return lines[::-1]  # Correct order of lines
    except Exception as e:
        logging.error(f"Error reading last lines from file {file_path}: {e}")
        return []

def parse_log_file(file_path, event_queue, cleartext=False, password=None, program_id=None, run_id=None, lines=1000):
    try:
        # Read the specified number of lines from the end
        lines_to_read = read_last_lines(file_path, lines)
        for line in lines_to_read:
            process_line(line, event_queue, cleartext, password, program_id, run_id)

        # Listen for new lines
        with open(file_path, 'r') as file:  # Open in text mode for ongoing reading
            file.seek(0, os.SEEK_END)  # Start at the end of the file
            while True:
                try:
                    line = file.readline()
                    if line:
                        process_line(line, event_queue, cleartext, password, program_id, run_id)
                    else:
                        time.sleep(0.02)  # Sleep to wait for new lines
                except Exception as e:
                    logging.error(f"Error reading new lines from log file: {e}")
                    time.sleep(1)  # Pause briefly before retrying
    except Exception as e:
        logging.error(f"Error in parse_log_file function: {e}")

def draw_events(stdscr, event_list, current_row, offset, height, width, new_data_available, new_events_count):
    try:
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
            max_message_length = max(0, width - len(display_str) - 1)  # Ensure positive value
            if len(message) > max_message_length:
                message = message[:max_message_length-3] + "..."
            display_str += f" {message}"
            display_str = display_str[:width-1]  # Ensure string does not exceed screen width

            y_pos = idx - offset
            if 0 <= y_pos < height:
                try:
                    if idx == current_row:
                        stdscr.attron(curses.color_pair(color_pair) | curses.A_REVERSE)
                        stdscr.addstr(y_pos, 0, display_str)
                        stdscr.attroff(curses.color_pair(color_pair) | curses.A_REVERSE)
                    else:
                        stdscr.attron(curses.color_pair(color_pair))
                        stdscr.addstr(y_pos, 0, display_str)
                        stdscr.attroff(curses.color_pair(color_pair))
                except curses.error as e:
                    logging.error(f"Error drawing event at index {idx}, position ({y_pos}, 0), width {width}: {e}")

        if new_data_available and new_events_count > 0:
            try:
                stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
                stdscr.addstr(height - 1, 0, f"{new_events_count} new log(s) available. Scroll to top to view.")
                stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            except curses.error as e:
                logging.error(f"Error drawing new data notification: {e}")

    except Exception as e:
        logging.error(f"Unexpected error in draw_events function: {e}")

def display_events(stdscr, event_queue):
    try:
        curses.curs_set(0)
        curses.use_default_colors()
        # Define color pairs for each log level
        curses.init_pair(1, curses.COLOR_WHITE, -1)  # Default
        curses.init_pair(2, curses.COLOR_RED, -1)    # Error
        curses.init_pair(3, curses.COLOR_YELLOW, -1) # Warn
        curses.init_pair(4, curses.COLOR_GREEN, -1)  # Info
        curses.init_pair(5, curses.COLOR_BLUE, -1)   # HTTP
        curses.init_pair(6, curses.COLOR_MAGENTA, -1)# Verbose
        curses.init_pair(7, curses.COLOR_WHITE, -1)  # Debug
        curses.init_pair(8, curses.COLOR_CYAN, -1)   # Silly

        event_list = []
        current_row = 0
        offset = 0
        new_data_available = False
        new_events = []

        stdscr.nodelay(True)
        stdscr.timeout(100)

        # Initial population of event_list
        while not event_queue.empty():
            try:
                event = event_queue.get_nowait()
                event_list.insert(0, event)
                event_queue.task_done()
            except queue.Empty:
                logging.warning("Attempted to get an event from an empty queue.")
            except Exception as e:
                logging.error(f"Unexpected error while retrieving an event from the queue: {e}")

        while True:
            height, width = stdscr.getmaxyx()
            if height <= 0 or width <= 0:
                height, width = 24, 80  # Fallback to a standard terminal size if invalid values are retrieved

            should_redraw = False

            # Check for new events
            while not event_queue.empty():
                try:
                    event = event_queue.get_nowait()
                    new_events.insert(0, event)
                    event_queue.task_done()
                except queue.Empty:
                    logging.warning("Attempted to get an event from an empty queue.")
                except Exception as e:
                    logging.error(f"Unexpected error while retrieving an event from the queue: {e}")

            if new_events and current_row == 0 and offset == 0:
                event_list = new_events + event_list
                new_events = []
                should_redraw = True
            elif new_events:
                new_data_available = True

            key = stdscr.getch()

            if key == -1:
                if should_redraw:
                    stdscr.clear()
                    draw_events(stdscr, event_list, current_row, offset, height, width, new_data_available, len(new_events))
                    stdscr.refresh()
                continue
            elif key in [curses.KEY_UP, ord('w')]:
                if current_row > 0:
                    current_row -= 1
                    if current_row < offset:
                        offset = current_row
                    should_redraw = True
                elif new_events:
                    event_list = new_events + event_list
                    current_row = len(new_events) - 1
                    offset = max(0, current_row - height + 1)
                    new_events = []
                    new_data_available = False
                    should_redraw = True
            elif key in [curses.KEY_DOWN, ord('s')]:
                if current_row < len(event_list) - 1:
                    current_row += 1
                    if current_row >= offset + height:
                        offset = current_row - height + 1
                    should_redraw = True
            elif key == curses.KEY_PPAGE:
                if current_row > 0:
                    current_row = max(0, current_row - height)
                    offset = max(0, offset - height)
                elif new_events:
                    event_list = new_events + event_list
                    current_row = len(new_events) - 1
                    offset = max(0, current_row - height + 1)
                    new_events = []
                    new_data_available = False
                should_redraw = True
            elif key == curses.KEY_NPAGE:
                current_row = min(len(event_list) - 1, current_row + height)
                offset = min(max(0, len(event_list) - height), current_row)
                should_redraw = True
            elif key == ord('q'):
                break
            elif key == ord('d'):
                show_event_details(stdscr, event_list, current_row, width, height)
                should_redraw = True

            if should_redraw or new_data_available:
                stdscr.clear()
                draw_events(stdscr, event_list, current_row, offset, height, width, new_data_available, len(new_events))
                stdscr.refresh()
    except Exception as e:
        logging.error(f"Error in display_events function: {e}")

def show_event_details(stdscr, event_list, current_row, width, height):
    try:
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
    except Exception as e:
        logging.error(f"Error in show_event_details function: {e}")

def main():
    try:
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
            password = getpass.getpass(prompt="Enter support key: ")  # Securely get the password

        event_queue = queue.Queue()
        log_thread = threading.Thread(target=parse_log_file, args=(log_file_path, event_queue, cleartext, password, program_id, run_id))
        log_thread.daemon = True
        log_thread.start()

        def run_curses(stdscr):
            curses.start_color()
            curses.use_default_colors()
            curses.curs_set(0)
            stdscr.nodelay(True)
            display_events(stdscr, event_queue)

        curses.wrapper(run_curses)

    except Exception as e:
        logging.error(f"Error in main function: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.critical(f"Unhandled exception in __main__: {e}")
