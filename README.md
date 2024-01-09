# pyipx

**pyipx** is a tool for extracting and repackaging pyinstaller applications.

Here are the features supported by this script.

|                     |  Extraction   |  Repackaging  |
| :-----------------: | :-----------: | :-----------: |
|      File Type      | EXE, ELF, RAW | EXE, ELF, RAW |
|   Python Version    |  2.7 && 3.x   |      3.x      |
| PyInstaller Version |  2.0 ~ 6.3.0  |  3.6 ~ 6.3.0  |

## Installation

If you need to process ELF files, make sure pyelftools is installed.

```bash
$ pip install pyelftools==0.29
```

## Usage

For **extraction**, you need to pass the file path as parameter.

```bash
$ python pyipx.py <file>
```

This file can be of the following three types:

- EXE: executable file on Windows platform
- ELF: executable file on Linux platform
- RAW: `pydata.dump` you get from the ELF binary, [reference](https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries)

For **repackaging**, this script needs three parameters.

```bash
$ python pyipx.py <file> <dir> <out>
```

- file: original executable file
- dir: directory to be repackaged
- out: repackage file output path

## Note

1. Please use Linux to repack ELF binaries.
2. It is highly recommended to run the script in the same version of Python that was used to generate the executable.

## Inspired by

[pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor)

## License

GNU General Public License v3.0

