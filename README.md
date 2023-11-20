# Program Executable Analyzer

## Description

This script analyzes MZ-PE (MS-DOS) executable file.

This tool is useful for malware analysis or debug/understand compiled dependencies.

 1. Verify signature and print informations about signature and trust
 2. Analyze DLLs and imported functions name
 3. Analyze exported functions name
 4. Get executable filename at the compiled time
 6. Get encodings and languages used for compilation
 7. Print informations about rich headers
 8. Get timestamps saved in executable
 9. Print informations about sections and characteristics (permissions, ect...)
 10. Print the entry point position and section
 11. Get architecture, system version, resources (Version file, Manifest)
 12. Get company name, product name, product version, copyright
 13. Sections names, sizes, addresses and characteristics
 14. Analyze MS-DOS and NT headers
 15. When *matplotlib* is installed, generate charts to compare sections on the disk and in the memory
 16. When *matplotlib* and *EntropyAnalysis* are installed, generate charts for entropy analysis (with sections)
 17. Extract overlay

TODO: analyze results to detect language and score the risk.

## Requirements

 - python3
 - Python 3 Standard library

### Optional

 - matplotlib
 - EntropyAnalysis

> *Matplotlib* and *EntropyAnalysis* are not installed by *ProgramExecutableAnalyzer* because this package can be installed on server without GUI.
>> You can install optinal required packages with the following command: `python3 -m pip install matplotlib EntropyAnalysis`

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
![PE Signature Informations](https://mauricelambert.github.io/info/python/security/Signature.png "PE Signature Informations")
![PE Entropy Analysis](https://mauricelambert.github.io/info/python/security/PEEntropyAnalysis.png "PE Entropy Analysis")
![PE Compare Section Size Charts](https://mauricelambert.github.io/info/python/security/CompareSectionsSizes.png "PE Compare Section Size Charts")

## Links

 - [Github Page](https://github.com/mauricelambert/ProgramExecutableAnalyzer/)
 - [Pypi package](https://pypi.org/project/ProgramExecutableAnalyzer/)
 - [Python Executable](https://mauricelambert.github.io/info/python/security/ProgramExecutableAnalyzer.pyz)
 - [Windows Executable](https://mauricelambert.github.io/info/python/security/ProgramExecutableAnalyzer.exe)

## Licence

Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).
