# Program Executable Analyzer

## Description

This script analyzes MZ-PE (MS-DOS) executable file.

This tool is useful for malware analysis or debug/understand compiled dependencies.

 1. Analyze DLLs and imported functions name
 2. Analyze exported functions name
 3. Get executable filename at the compiled time
 4. Get encodings and languages used for compilation
 5. Get timestamps saved in executable
 6. Get architecture, system version, resources (Version file, Manifest)
 7. Get company name, product name, product version, copyright
 8. Sections sizes and addresses

## Requirements

 - python3
 - Python 3 Standard library

## Installation

```bash
pip install ProgramExecutableAnalyzer
```

## Usages

```bash
python3 ProgramExecutableAnalyzer.py -h
python3 ProgramExecutableAnalyzer.py executable.exe
python3 ProgramExecutableAnalyzer.py -c executable.exe  # No color
python3 ProgramExecutableAnalyzer.py -v executable.exe  # Verbose mode
```

## Screenshots

![PE Headers Analysis](https://mauricelambert.github.io/info/python/security/PEheaders.png "PE Headers Analysis")
![PE Headers Analysis](https://mauricelambert.github.io/info/python/security/PEversion.png "PE Version Analysis")
![PE Imports Analysis](https://mauricelambert.github.io/info/python/security/PEimports.png "PE Imports Analysis")

## Links

 - [Github Page](https://github.com/mauricelambert/ProgramExecutableAnalyzer/)
 - [Executable](https://mauricelambert.github.io/info/python/security/ProgramExecutableAnalyzer.pyz)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
