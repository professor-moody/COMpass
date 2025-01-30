# COMpass


A comprehensive security analysis tool for Windows COM objects.

## Features

- **Registry Analysis**: Enumerate and analyze COM object registry entries
- **Security Analysis**: Evaluate security descriptors and permissions
- **Method Discovery**: Map available COM object methods and parameters
- **Vulnerability Detection**: Identify potential security issues in COM configurations

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/compass.git
cd compass

# Install in development mode
pip install -e .
```

## Requirements

- Python 3.7+
- Windows operating system
- pywin32 package

## Usage

Basic usage:
```bash
python run_analyzer.py
```

Options:
```bash
# Show available modules
python3 run_analyzer.py --list-modules

# Skip slow method discovery
python3 run_analyzer.py --skip methods

# Run specific modules only
python3 run_analyzer.py --modules registry,security

# Enable debug output
python3 run_analyzer.py -d

# Save results to file
python3 run_analyzer.py -o results.json
```

## Module Description

- **registry**: Analyzes COM object registry entries
- **security**: Checks security descriptors and permissions
- **methods**: Discovers and analyzes COM object methods
- **vulnerabilities**: Identifies security issues

## Example Output

```
=== COM Security Analysis Summary ===
Analysis completed: 2025-01-30 12:00:00

COM Objects analyzed: 1500
Security descriptors analyzed: 1500

Total vulnerabilities found: 25
Vulnerabilities by severity:
  CRITICAL: 2
  HIGH: 8
  MEDIUM: 10
  LOW: 5

Vulnerability types found:
  Writable Server Path: 3
  Dangerous Launch Permission: 5
  Overly Permissive Access: 7
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security Note

This tool is intended for security research and authorized testing only. Always ensure you have proper authorization before analyzing COM objects in any environment.

## Acknowledgments

- Built with pywin32
- Inspired by various COM security research projects
- Thanks to all contributors