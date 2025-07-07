#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import json
import yaml
import math

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def calculate_entropy(data):
    """
    Calculates the Shannon entropy of a string.

    Args:
        data (str): The string to calculate entropy for.

    Returns:
        float: The entropy of the string.
    """
    if not data:
        return 0  # Empty string has no entropy

    entropy = 0
    data_length = len(data)
    frequency_map = {}

    # Calculate character frequencies
    for char in data:
        if char in frequency_map:
            frequency_map[char] += 1
        else:
            frequency_map[char] = 1

    # Calculate entropy based on character frequencies
    for char in frequency_map:
        probability = float(frequency_map[char]) / data_length
        entropy -= probability * math.log(probability, 2)

    return entropy

def check_file_entropy(file_path, threshold=3.0):
    """
    Checks the entropy of string values in a configuration file (JSON or YAML).

    Args:
        file_path (str): The path to the configuration file.
        threshold (float): The entropy threshold to flag values.

    Returns:
        list: A list of tuples, where each tuple contains (key, value, entropy) for values below the threshold.
              Returns an empty list if no low-entropy values are found or if the file type is not supported.
    """
    low_entropy_values = []

    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.json'):
                data = json.load(file)
            elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
                data = yaml.safe_load(file)
            else:
                logging.error(f"Unsupported file type: {file_path}. Supported types are JSON and YAML.")
                return []  # Indicate unsupported file type

        # Recursively traverse the data structure to find string values
        def traverse(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    traverse(value, new_path)
            elif isinstance(obj, list):
                for i, value in enumerate(obj):
                    new_path = f"{path}[{i}]"
                    traverse(value, new_path)
            elif isinstance(obj, str):
                entropy = calculate_entropy(obj)
                if entropy < threshold:
                    low_entropy_values.append((path, obj, entropy))
                    logging.warning(f"Low entropy value found at {path}: Entropy = {entropy}, Value = {obj[:50]}...") # Log first 50 characters

        traverse(data)

    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON file: {file_path}")
    except yaml.YAMLError as e:
        logging.error(f"Failed to decode YAML file: {file_path}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    return low_entropy_values

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Check configuration values for low entropy (potential weak secrets).",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("file_path", help="Path to the configuration file (JSON or YAML).")
    parser.add_argument("-t", "--threshold", type=float, default=3.0,
                        help="Entropy threshold to flag values (default: 3.0).  Values below this threshold will be flagged.\n"
                             "Lower values will result in more sensitive reporting, potentially leading to false positives.\n"
                             "Higher values will be less sensitive and may miss some weak secrets.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")

    return parser

def main():
    """
    Main function to execute the entropy checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    file_path = args.file_path

    # Input validation: Check if file exists
    if not os.path.isfile(file_path):
        logging.error(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)

    # Input validation: Check if file is readable
    if not os.access(file_path, os.R_OK):
        logging.error(f"Error: File '{file_path}' is not readable.")
        sys.exit(1)

    low_entropy_values = check_file_entropy(file_path, args.threshold)

    if low_entropy_values:
        print("Low entropy values found:")
        for path, value, entropy in low_entropy_values:
            print(f"  Path: {path}")
            print(f"  Value: {value[:50]}...") # Print first 50 characters of the value
            print(f"  Entropy: {entropy:.4f}\n")
    else:
        print("No low entropy values found.")

# Usage examples:
# 1. Run the script with a JSON file:
#    python misconfig_configvalueentropychecker.py config.json
#
# 2. Run the script with a YAML file and a custom threshold:
#    python misconfig_configvalueentropychecker.py config.yaml -t 2.5
#
# 3. Run the script with verbose output:
#    python misconfig_configvalueentropychecker.py config.yaml -v

if __name__ == "__main__":
    main()