import argparse
import curses
import json
import threading
import textwrap
import time

def parse_log_file(file_path, event_list, tail_mode):
    """ Continuously parse the log file and update the event list. """
    with open(file_path, 'r') as file:
        if not tail_mode:
            lines = file.readlines()
            for line in reversed(lines):
                try:
                    event = json.loads(line)
                    event_list.append(event)
                except json.JSONDecodeError:
                    continue
        file.seek(0, 2)  # Move to the end of the file for tail mode
        while True:
            line = file.readline()
            if line:
                try:
                    event = json.loads(line)
                    event_list.insert(0, event)  # Prepend new event
                except json.JSONDecodeError:
                    continue
            else:
                time.sleep(0.1)

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
            expected_keys = {'level', 'message', 'ms', 'timestamp'}
            if set(event.keys()) - expected_keys:
                connector = '+'
            else:
                connector = '-'

            display_str = f"{event.get('timestamp', 'N/A')} {connector} {event.get('message', 'No message')}"
            display_str = display_str[:width-1]  # Ensure string does not exceed screen width

            if idx == current_row:
                stdscr.attron(curses.color_pair(color_pair) | curses.A_REVERSE)  # Highlight current row with reverse video
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
            show_event_details(stdscr, event_list, current_row, width, height)  # Assumes a refactored function for details view

        stdscr.refresh()

def show_event_details(stdscr, event_list, current_row, width, height):
    """ A refactored function to show event details. """
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
                    stdscr.attron(curses.color_pair(6))  # Verbose for JSON keys
                    stdscr.addstr(i, 0, key + ':')
                    stdscr.attroff(curses.color_pair(6))
                    stdscr.addstr(value)
                else:
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

def main():
    parser = argparse.ArgumentParser(description="Log Viewer")
    parser.add_argument("logfile", help="Path to the log file")
    parser.add_argument("--tail", action="store_true", help="Start in tail mode")
    args = parser.parse_args()

    log_file_path = args.logfile
    tail_mode = args.tail
    event_list = []
    log_thread = threading.Thread(target=parse_log_file, args=(log_file_path, event_list, tail_mode))
    log_thread.daemon = True
    log_thread.start()

    curses.wrapper(display_events, event_list)

if __name__ == "__main__":
    main()
