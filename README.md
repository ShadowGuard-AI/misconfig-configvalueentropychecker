![Banner](banner.png)

# misconfig-ConfigValueEntropyChecker
Calculates the per character Shannon entropy of configuration values to detect potentially weak or default secrets and keys, using the standard library `math` module. It flags values with low entropy as potentially problematic. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

Flagged values are never printed in clear, in the log warning or in the report. A finding reports only the key path and the entropy score, with the value shown as ***masked***, because a flagged value may be a real secret.

Scope of the measure: string values and numeric values (measured through their decimal text) under every key are measured; booleans are not. A value shorter than 8 characters is counted as measured but never flagged, because per character entropy is capped by the number of distinct characters a short value can hold, so the score cannot separate a short random value from a short weak one.

## Install
`git clone https://github.com/ShadowGuardAI/misconfig-configvalueentropychecker`
`pip install -r requirements.txt`

## Usage
`python3 main.py <file_path> [-t 3.0] [-v]`

Exit codes: 0 when the file was measured and no value was flagged, 1 when a value is flagged, and 1 with its own error line when nothing was measured because the file was malformed, of an unsupported type, empty, or held no measurable string or numeric values. A load failure is never reported as a clean file.

## Parameters
- `-h`: Show help message and exit
- `file_path`: Path to the configuration file (JSON or YAML).
- `-t`, `--threshold`: Entropy threshold to flag values (default: 3.0). Values below this threshold will be flagged.
- `-v`, `--verbose`: Enable verbose output (debug logging).

## License
Copyright (c) ShadowGuardAI
