# Digital Steganography for Executables

This software is able to embed secret message of any format to the executables ELF and PE (cover file). It's also able to extract hidden data or analyze given executable (its steganography potential). Software uses encryption with user password which is necessary for correct embedding and extraction. If capacity of cover file is not sufficient, steganography can not be applied. There are three implemented modes:
* `embed`/`e` - requires `-c`/`--cover-file` and `-s`/`--secret-message`
* `extract`/`x` - requires `g`/`--stego-file`
* `analyze`/`a` - requires `-c`/`--cover-file`

In every mode it's necessary to specify method which will be used (argument `-m`/`--method`):
* `sub`/`instruction-substitution` - basic instruction substitution
* `ext-sub`/`extended-substitution` - extended instruction substitution
* `nops`/`nops-using` - steganography using NOP instructions
* `ext-sub-nops` - combination of all implemented methods

Neither one of them can change final size of stego-file. For more information about arguments, see `-h`/`--help`.

## Examples

Embedding image to PE executable with combination of all methods (there is also possibility to use any filepath as hidden data or do not specify `-s` - then, secret message is in stdin expected):

```
python3 main.py embed -m ext-sub-nops -c notepad.exe -s "TEST MESSAGE"
```

Extraction of the image embedded in previous example:

```
python3 main.py extract -m ext-sub-nops -g notepad.exe
```

Print analysis of ELF executable for specific method:

```
python3 main.py analyze -m sub -c hello
```

## Installation

To install every required modul to be able to run software, use following command (from project root directory):

```
pip install -r requirements.txt
```

## Testing

For testing purposes exists directory `tests/`. All test must be performed from this directory. If any test case needs password, this has to be given by `-p`/`--passwd` option. Test cases use modul `matplotlib` which generates graphs. To run all test cases, use following command:

```
python3 test.py
```

If only specific test cases want to be ran, then others must be commented in code `test.py`.

Required is to place tested executables to the directory `executables/` and desired embedding/extracting data to the directory `data/`.

## Documentation in pdoc

To be able for generating documentation, `pdoc` modul must be installed. Then, following command can be used (must be in a root directory of project):

```
pdoc ./src/* ./tests/test.py -o ./doc --logo "fit_logo.png" --logo-link "fit_logo.png" --favicon "vut_logo.ico"
```

## Error codes:

Software can sometimes fail if something is going wrong. There are few error codes specified:

* 2 - internal parsing of command-line arguments
* 100 - wrong combination of arguments was given
* 101 - disassembling of given executable failed
* 102 - error while reading given executable
* 103 - parsing configuration file failed
* 104 - embedding failed
* 105 - extraction failed (usually wrong password)
* 109 - error while asking for user password

## Copyright

&copy; 2022 Ľuboš Bever. All rights reserved.