## Introduction
View winston log files using json event format in a command line interface

## Expected log format
The log entries could have any format, but a timestamp and a message field are required. Example:
```json
{"timestamp":"2020-01-01T00:00:00.000Z","message":"This is a log message","additionalData":"some data"}
```

## How to use
```bash
python log_viewer.py -f <log_file_path>
```
Use the following keys to navigate the log file:
- 'up arrow' or 'w' to move up
- 'down arrow' or 's' to move down
- 'page up' to move up a page
- 'page down' to move down a page
- 'q' to quit
- 'd' to show the details of the selected log entry

