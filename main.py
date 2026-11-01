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

MIN_MEASURED_LENGTH = 8


class EmptyInputError(ValueError):
    """Raised when the input file holds nothing to measure."""


class UnsupportedFileError(ValueError):
    """Raised when the input file type is not supported."""


def check_file_entropy(file_path, threshold=3.0):
    """
    Checks the entropy of string and numeric values in a configuration
    file (JSON or YAML).

    Values are never returned, logged, or printed: a finding carries
    only the key path and the entropy score, so a flagged value, which
    may be a real secret, is never echoed in clear.

    Args:
        file_path (str): The path to the configuration file.
        threshold (float): The per character entropy threshold.

    Returns:
        tuple: (list of (path, entropy) tuples for values below the
        threshold, count of values measured)

    Raises:
        EmptyInputError: If the file is empty or holds no data.
        UnsupportedFileError: If the file type is not JSON or YAML.
        json.JSONDecodeError, yaml.YAMLError: If the file is malformed.
    """
    low_entropy_values = []
    measured_count = [0]

    with open(file_path, 'r') as file:
        text = file.read()

    if not text.strip():
        raise EmptyInputError(f"File is empty: {file_path}")

    # The suffix test is case sensitive, so a file named .JSON is
    # refused as unsupported while the identical contents under
    # .json are measured. The file was already read in full
    # above before this decision is made.
    if file_path.endswith('.json'):
        data = json.loads(text)
    elif file_path.endswith('.yaml') or file_path.endswith('.yml'):
        data = yaml.safe_load(text)
    else:
        raise UnsupportedFileError(
            f"Unsupported file type: {file_path}. Supported types are JSON and YAML."
        )

    if data is None:
        raise EmptyInputError(f"File holds no data to measure: {file_path}")

    # Recursively traverse the data structure. String values and
    # numeric values (measured through their decimal text) are
    # measured; booleans are not. A value shorter than
    # MIN_MEASURED_LENGTH characters is counted as measured but never
    # flagged, because per character entropy is capped by the number
    # of distinct characters a short value can hold, so the score
    # cannot separate a short random value from a short weak one.
    def traverse(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                traverse(value, new_path)
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                # A value at the top level of a list, or a config that is one
                # bare string, is reported with an empty or bracket only
                # path. The finding still carries no value, so a reader
                # chasing that entry has to count entries in the file by
                # hand to find the value I flagged.
                new_path = f"{path}[{i}]"
                traverse(value, new_path)
        elif isinstance(obj, bool):
            return
        elif isinstance(obj, (str, int, float)):
            # Numbers are measured through their printed form, so the
            # score describes the decimal text, not the quantity. A
            # timestamp and a small count can share a score, and a YAML
            # date, which parses to a datetime object rather than a
            # string or a number, is not measured at all: it falls
            # through every branch of the walk without being counted.
            text_value = obj if isinstance(obj, str) else str(obj)
            measured_count[0] += 1
            if len(text_value) < MIN_MEASURED_LENGTH:
                return
            entropy = calculate_entropy(text_value)
            # Every value in the file is judged, not just values under
            # sensitive names. A hostname, an environment label like
            # production, or a repeated digit port number all have low
            # per character entropy, and all are reported as if they
            # were weak secrets. The reader has to supply the part I
            # cannot: knowing which paths were ever meant to be secret.
            if entropy < threshold:
                low_entropy_values.append((path, entropy))
                logging.warning(f"Low entropy value found at {path}: Entropy = {entropy}, Value = ***masked***")

    traverse(data)

    return low_entropy_values, measured_count[0]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Check configuration values for low entropy (potential weak secrets).",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("file_path", help="Path to the configuration file (JSON or YAML).")
    # Nothing bounds this value. A threshold below zero flags
    # nothing and reports the file clean, a very high one flags
    # every measured value, and NaN, which argparse accepts as a
    # float, makes every comparison false and also reports the
    # file clean.
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

    try:
        low_entropy_values, measured_count = check_file_entropy(file_path, args.threshold)
    except EmptyInputError as e:
        logging.error(str(e))
        print(f"Empty input: no values were measured in {file_path}.")
        sys.exit(1)
    except UnsupportedFileError as e:
        logging.error(str(e))
        print(f"Unsupported file type: {file_path}. Supported types are JSON and YAML.")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON file: {file_path}")
        print(f"Could not parse {file_path} as JSON. No values were measured.")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Failed to decode YAML file: {file_path}: {e}")
        print(f"Could not parse {file_path} as YAML. No values were measured.")
        sys.exit(1)

    if measured_count == 0:
        print(f"No measurable string or numeric values were found in {file_path}. Nothing was checked.")
        sys.exit(1)

    if low_entropy_values:
        print("Low entropy values found:")
        for path, entropy in low_entropy_values:
            print(f"  Path: {path}")
            print(f"  Value: ***masked***")
            print(f"  Entropy: {entropy:.4f}\n")
        sys.exit(1)
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