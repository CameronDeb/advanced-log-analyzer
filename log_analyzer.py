import re
import argparse
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
import statistics # For moving average calculation

# --- Global State (Consider more robust state management for production) ---
# Stores timestamps for different rule checks. Structure:
# state_data[rule_name][group_key] = deque([(timestamp, count)]) # Using deque for efficient windowing
state_data = defaultdict(lambda: defaultdict(deque))
# For volume spike rule, store all timestamps in baseline window
volume_baseline_timestamps = deque()
volume_current_timestamps = deque()


# --- Helper Functions ---

def load_config(config_path):
    """Loads configuration from a JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            # Compile the regex pattern from config
            config['log_pattern_re'] = re.compile(config['log_pattern'])
            print(f"Configuration loaded successfully from {config_path}")
            return config
    except FileNotFoundError:
        print(f"Error: Configuration file not found at '{config_path}'")
        return None
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from config file '{config_path}'.")
        return None
    except re.error as e:
         print(f"Error: Invalid regex pattern in config file: {e}")
         return None
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return None

def parse_log_line(line, regex_pattern):
    """Parses a single log line using the compiled regex pattern from config."""
    match = regex_pattern.match(line)
    if match:
        log_data = match.groupdict()
        try:
            log_data['timestamp'] = datetime.strptime(log_data['timestamp'], '%Y-%m-%d %H:%M:%S')
            return log_data
        except ValueError:
            # print(f"Warning: Invalid timestamp format in line: {line.strip()}")
            return None
    return None # Skip lines that don't match

def update_state_and_check_anomalies(log_entry, config):
    """Updates state based on the log entry and checks all enabled rules."""
    anomalies_found = []
    current_time = log_entry['timestamp']

    # --- Update state for Log Volume Spike Rule ---
    volume_rule = next((rule for rule in config['anomaly_rules'] if rule['name'] == "Log Volume Spike" and rule['enabled']), None)
    if volume_rule:
        baseline_window = timedelta(minutes=volume_rule['baseline_window_minutes'])
        current_window = timedelta(minutes=volume_rule['window_minutes'])

        # Add current timestamp to both deques
        volume_baseline_timestamps.append(current_time)
        volume_current_timestamps.append(current_time)

        # Prune old timestamps from baseline deque
        while volume_baseline_timestamps and current_time - volume_baseline_timestamps[0] > baseline_window:
            volume_baseline_timestamps.popleft()
        # Prune old timestamps from current window deque
        while volume_current_timestamps and current_time - volume_current_timestamps[0] > current_window:
            volume_current_timestamps.popleft()

        # Check volume spike anomaly
        if len(volume_baseline_timestamps) > 10: # Need enough data for a baseline
             baseline_rate = len(volume_baseline_timestamps) / baseline_window.total_seconds()
             current_rate = len(volume_current_timestamps) / current_window.total_seconds()
             # Avoid division by zero and check threshold
             if baseline_rate > 0 and current_rate > (baseline_rate * volume_rule['threshold_factor']):
                  anomaly_msg = (f"Log Volume Spike: Current rate ({current_rate:.2f}/s) is "
                                 f"{current_rate/baseline_rate:.1f}x baseline rate ({baseline_rate:.2f}/s) "
                                 f"over last {current_window}.")
                  anomalies_found.append({"rule": volume_rule['name'], "message": anomaly_msg})


    # --- Check other configured rules ---
    for rule in config['anomaly_rules']:
        if not rule['enabled'] or rule['name'] == "Log Volume Spike": # Skip disabled or volume rule (handled above)
            continue

        # Check if the log entry matches the rule's level and message pattern (if specified)
        level_match = (rule['log_level'] is None or log_entry['level'] == rule['log_level'])
        message_pattern = rule.get('message_pattern')
        message_match = (message_pattern is None or
                         re.search(message_pattern, log_entry['message'], re.IGNORECASE))

        if level_match and message_match:
            rule_name = rule['name']
            window = timedelta(minutes=rule['window_minutes'])
            threshold = rule['threshold']
            group_by_key = log_entry.get(rule['group_by']) if rule['group_by'] else 'overall'

            # Ignore entries where group_by key is irrelevant (e.g., '-' or 'localhost' for IP-based rules)
            if rule['group_by'] == 'ip' and group_by_key in ['-', 'localhost']:
                continue

            # Get the deque for this specific rule and group
            timestamps_deque = state_data[rule_name][group_by_key]

            # Add current timestamp
            timestamps_deque.append(current_time)

            # Prune old timestamps outside the window
            while timestamps_deque and current_time - timestamps_deque[0] > window:
                timestamps_deque.popleft()

            # Check threshold
            if len(timestamps_deque) >= threshold:
                group_info = f" (Group: {group_by_key})" if rule['group_by'] else ""
                anomaly_msg = (f"{rule_name}: Threshold exceeded. "
                               f"{len(timestamps_deque)} events{group_info} "
                               f"in the last {window}.")
                anomalies_found.append({"rule": rule_name, "message": anomaly_msg})
                # Optional: Implement logic to report only once per threshold breach within a cooldown period

    return anomalies_found

# --- Main Processing Logic ---

def process_log_file(filepath, config):
    """Reads and processes the log file line by line using the loaded config."""
    print(f"Processing log file: {filepath}...")
    all_reported_anomalies = set() # Use a set to store unique anomaly messages reported
    line_count = 0
    parse_errors = 0
    last_log_time = None

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line_count += 1
                log_entry = parse_log_line(line, config['log_pattern_re'])

                if log_entry:
                    last_log_time = log_entry['timestamp'] # Keep track of latest timestamp
                    anomalies = update_state_and_check_anomalies(log_entry, config)

                    if anomalies:
                        for anomaly in anomalies:
                             # Create a unique key for the report (rule + message) to avoid duplicates
                             report_key = (anomaly['rule'], anomaly['message'])
                             if report_key not in all_reported_anomalies:
                                 report_str = f"{log_entry['timestamp']} | ANOMALY | {anomaly['message']}"
                                 print(report_str) # Print anomaly as soon as detected
                                 all_reported_anomalies.add(report_key)
                else:
                     # Only count format errors if the line wasn't empty
                     if line.strip():
                         parse_errors += 1

    except FileNotFoundError:
        print(f"Error: Log file not found at '{filepath}'")
        return
    except Exception as e:
        print(f"An unexpected error occurred during processing: {e}")
        # Consider logging the traceback for debugging
        import traceback
        traceback.print_exc()
        return

    print(f"\n--- Processing Summary ---")
    print(f"Total lines processed: {line_count}")
    print(f"Lines skipped (format mismatch/error): {parse_errors}")
    if last_log_time:
         print(f"Latest log entry timestamp: {last_log_time}")
    print(f"Total unique anomalies reported: {len(all_reported_anomalies)}")
    print("------------------------\n")


# --- Script Entry Point ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Log File Anomaly Detector.")
    parser.add_argument("logfile", help="Path to the log file to analyze.")
    parser.add_argument("-c", "--config", default="config.json",
                        help="Path to the configuration file (default: config.json).")

    args = parser.parse_args()

    # Load configuration
    config_data = load_config(args.config)

    if config_data:
        # Start processing
        process_log_file(args.logfile, config_data)
    else:
        print("Exiting due to configuration loading error.")
