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
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Highlight color
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)  # JSON key color (light green)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)  # JSON value color
    current_row = 0
    offset = 0

    while True:
        stdscr.clear()
        height, width = stdscr.getmaxyx()

        for idx in range(offset, min(offset + height, len(event_list))):
            event = event_list[idx]
            display_str = f"{event.get('timestamp', 'N/A')} - {event.get('message', 'No message')}"
            display_str = display_str[:width-1]

            if idx == current_row:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(idx - offset, 0, display_str)
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(idx - offset, 0, display_str)

        key = stdscr.getch()

        if key in [curses.KEY_UP, ord('w')] and current_row > 0:
            current_row -= 1
            offset = max(0, current_row - height + 1)
        elif key in [curses.KEY_DOWN, ord('s')] and current_row < len(event_list) - 1:
            current_row += 1
            offset = max(0, current_row - height + 1)
        elif key == curses.KEY_PPAGE:  # Page Up
            current_row = max(0, current_row - height)
            offset = max(0, offset - height)
        elif key == curses.KEY_NPAGE:  # Page Down
            current_row = min(len(event_list) - 1, current_row + height)
            offset = min(max(0, len(event_list) - height), offset + height)
        elif key == ord('q'):
            break
        elif key == ord('d'):
            stdscr.clear()
            details = json.dumps(event_list[current_row], indent=4).replace('\\n', '\n')
            details_lines = details.split('\n')

            wrapped_lines = []
            for line in details_lines:
                wrapped_lines.extend(textwrap.wrap(line, width))

            details_offset = 0
            while True:
                for i in range(height):
                    line_idx = i + details_offset
                    if line_idx < len(wrapped_lines):
                        line = wrapped_lines[line_idx]
                        if line.strip().startswith('"') and ':' in line:
                            key, value = line.split(':', 1)
                            stdscr.attron(curses.color_pair(2))
                            stdscr.addstr(i, 0, key + ':')
                            stdscr.attroff(curses.color_pair(2))
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
                elif details_key == curses.KEY_PPAGE:  # Page Up in detail view
                    details_offset = max(0, details_offset - height)
                elif details_key == curses.KEY_NPAGE:  # Page Down in detail view
                    details_offset = min(len(wrapped_lines) - height, details_offset + height)
                elif details_key == ord('q') or details_key == ord('d'):
                    break

                stdscr.clear()

        stdscr.refresh()

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
