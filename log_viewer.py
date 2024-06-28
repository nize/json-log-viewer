import argparse
import curses
import json
import threading
import getpass  # For securely getting the password input
import textwrap
import time
import zlib
import gzip
import io
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def should_include_event(event, program_id=None, run_id=None):
    """ Determine if the event should be included based on programId and runId. """
    return (program_id is None or event.get('programId') == program_id) and \
           (run_id is None or event.get('runId') == run_id)

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

def parse_log_file(file_path, event_list, cleartext=False, password=None, program_id=None, run_id=None):
    # Set the file position to start based on whether you want to see historical data or not
    file_position = 0  # Change this to `os.path.getsize(file_path)` to start at the end
    with open(file_path, 'r') as file:
        file.seek(file_position)
        while True:
            line = file.readline()
            if line:
                if not cleartext:
                    try:
                        decrypted_data = decrypt_and_decompress(line.strip(), password)
                        event = json.loads(decrypted_data)
                    except Exception as e:
                        print(f"Failed to decrypt and decompress log file: {e}")
                        continue
                else:
                    try:
                        event = json.loads(line.strip())
                    except json.JSONDecodeError as e:
                        print(f"Failed to decode line: {e}")
                        continue

                if should_include_event(event, program_id, run_id):
                    event_list.insert(0, event)  # Prepend new event to the list
                    #print(f"Added event: {event}")  # Debug output
            else:
                time.sleep(0.1)  # Reduce CPU usage

def display_events(stdscr, event_list):
    """ Display events in a scrollable list using curses. """
    curses.curs_set(0)
    # Define color pairs for each log level
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)  # Default
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)    # Error
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Warn
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Info
    curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)   # HTTP
    curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK)# Verbose
    curses.init_pair(7, curses.COLOR_BLUE, curses.COLOR_BLACK)   # Debug
    curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_BLACK)  # Silly

    level_color = {
        'error': 2,
        'warn': 3,
        'info': 4,
        'http': 5,
        'verbose': 6,
        'debug': 7,
        'silly': 8
    }

    current_row = 0
    offset = 0

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        for idx in range(offset, min(offset + height, len(event_list))):
            event = event_list[idx]
            level = event.get('level', '').lower()
            color_pair = level_color.get(level, 1)  # Default color if level is not matched

            # Determine if there are additional keys
            expected_keys = {'level', 'message', 'ms', 'timestamp','programId','runId'}
            if set(event.keys()) - expected_keys:
                connector = '+'
            else:
                connector = '-'

            timestamp = event.get('timestamp', 'N/A')
            message = event.get('message', 'No message')
            program_id = event.get('programId')
            run_id = event.get('runId')
            display_str = f"{timestamp} {connector}"
            if program_id:
                display_str += f" Program ID: {program_id}"
            if run_id:
                display_str += f" Run ID: {run_id}"
            display_str += f" {message}"
            display_str = display_str[:width-1]  # Ensure string does not exceed screen width

            if idx == current_row:
                stdscr.attron(curses.color_pair(color_pair) | curses.A_REVERSE)  # Highlight current row with reverse video
                stdscr.addstr(idx - offset, 0, display_str)
                stdscr.attroff(curses.color_pair(color_pair) | curses.A_REVERSE)
            else:
                stdscr.attron(curses.color_pair(color_pair))
                stdscr.addstr(idx - offset, 0, display_str)
                stdscr.attroff(curses.color_pair(color_pair))

        key = stdscr.getch()

        if key in [curses.KEY_UP, ord('w')] and current_row > 0:
            current_row -= 1
            offset = max(0, current_row - height + 1)
        elif key in [curses.KEY_DOWN, ord('s')] and current_row < len(event_list) - 1:
            current_row += 1
            offset = max(0, current_row - height + 1)
        elif key == curses.KEY_PPAGE:
            current_row = max(0, current_row - height)
            offset = max(0, offset - height)
        elif key == curses.KEY_NPAGE:
            current_row = min(len(event_list) - 1, current_row + height)
            offset = min(max(0, len(event_list) - height), offset + height)
        elif key == ord('q'):
            break
        elif key == ord('d'):
            show_event_details(stdscr, event_list, current_row, width, height)

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
                    stdscr.attron(curses.color_pair(6))  # Verbose for JSON keys, set as light green earlier
                    stdscr.addstr(i, 0, key + ':')
                    stdscr.attroff(curses.color_pair(6))
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
        password = getpass.getpass(prompt="Enter password: ")  # Securely get the password

    event_list = []
    log_thread = threading.Thread(target=parse_log_file, args=(log_file_path, event_list, cleartext, password, program_id, run_id))
    log_thread.daemon = True
    log_thread.start()

    curses.wrapper(display_events, event_list)  # Use curses to handle the terminal display

if __name__ == "__main__":
    main()
