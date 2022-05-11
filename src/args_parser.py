"""
`ArgsParser` module

Author:  *Ľuboš Bever*

Date:    *11.05.2022*

Version: *1.0*

Project: *Bachelor's thesis, BUT FIT Brno*
"""

import os.path
import sys
import argparse


class ArgsParser():
    """
    Parser class for command-line arguments.
    """
    
    __parser = None
    """
    Reference to the created `args_parser` object.
    """
    
    __args = None
    """
    Reference to the namespace with parsed command-line arguments.
    """    
        
    @classmethod
    def __set_parser(cls) -> None:
        """
        Only set command-line argument parser by creating
        types of possible required, positional and optional arguments.
        """
        
        cls.__parser = argparse.ArgumentParser(
            usage="""
  %(prog)s MODE -m METHOD [-s SECRET_MESSAGE] [-c COVER_FILE] [-g STEGO_FILE]
                         [-o CONFIG_FILE] [-f/--force] [-v/--verbose]
                         [-h/--help] [-V/--version]""",
            description="""Digital Steganography for Executables

  This software is able to embed secret message of any format to the 
  executables ELF and PE (cover file). It's also able to extract hidden data
  or analyze given executable (its steganographic potential). Software uses 
  encryption with user password which is necessary for correct embedding and 
  extraction. If capacity of cover file is not sufficient, steganography can 
  not be applied. There are three possible MODES specified by positional 
  argument. Then, required is also to choose one of possible steganography 
  methods in every MODEs. Neither one of them can change final size of 
  stego-file. Allowed values of particular arguments are listed below.""",
            epilog="\u00A9 2022 Ľuboš Bever. All rights reserved.",
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
            exit_on_error=False
            )
        
        # cls.__parser._positionals.title = "Positional arguments:"
        # cls.__parser._optionals.title = "Optional arguments:"
        
        cls.__parser.add_argument(
            "mode",
            help="""the MODE which program will run in. Possible values
are:
 * embed   - embeds secret message to the cover file,
 * extract - extracts secret message from stego-file,
 * analyze - analyzes steganographic potential of
             cover file""",
            metavar="MODE",
            choices=["e", "embed",
                     "x", "extract",
                     "a", "analyze"]
            )
        
        requiredArgs = cls.__parser.add_argument_group("required arguments")
        requiredArgs.add_argument(
            "-m",
            "--method",
            help="""steganography METHOD used to embed/extract message or
analyze cover file. Possible values are:
 * 'sub'/'instruction-substitution',
 * 'ext-sub'/'extended-substitution',
 * 'nops'/'nops-using',
 * 'ext-sub-nops'.""",
            metavar="METHOD",
            choices=["sub", "instruction-substitution",
                     "ext-sub", "extended-substitution",
                     "nops", "nops-using",
                     "mov", "mov-scheduling",
                     "ext-sub-nops"],
            required=True
            )
        
        cls.__parser.add_argument(
            "-h",
            "--help",
            help="""show this message and exit (ignores other arguments)
            """,
            action="help",
            default=argparse.SUPPRESS
            )
        cls.__parser.add_argument(
            "-s",
            "--secret-message",
            help="""SECRET_MESSAGE to be hidden within executable (any
string or file or if nothing is given, SECRET_MESSAGE
is in stdin expected)
 """,
            default=sys.stdin
            )
        cls.__parser.add_argument(
            "-c",
            "--cover-file",
            help="""COVER_FILE (executable) to be secret message hidden in
            """
            )
        cls.__parser.add_argument(
            "-g",
            "--stego-file",
            help="""STEGO_FILE (executable) with embedded secret message
to be extracted
            """
            )
        cls.__parser.add_argument(
            "-o",
            "--config-file",
            help="""CONFIG_FILE with informations determining encoding
while embedding/extracting message
            """
            )
        cls.__parser.add_argument(
            "-f",
            "--force",
            help="""strengthen the selection of potential instructions
(influence only [extended] instruction substitution)
for the purpose of higher capacity (running the program
can take up to several minutes)
            """,
            action="store_true"
            )
        cls.__parser.add_argument(
            "-v",
            "--verbose",
            help="""output verbosity while processing
            """,
            action="store_true"
            )
        cls.__parser.add_argument(
            "-V",
            "--version",
            help="""show current version and exit (ignores other arguments)""",
            action="version",
            version="%(prog)s 1.0\n\u00A9 2022 Ľuboš Bever. All rights reserved."
            )
        
        
    @classmethod
    def __eprint(cls, msg: str, ec: int) -> None:
        """
        Error print for this module. Its format is respected by used
        argsparse module.
        """
        
        p = cls.__parser
        print("usage:", file=sys.stderr)
        print(
            f"  {p.prog} " """MODE -m METHOD [-s SECRET_MESSAGE] [-c COVER_FILE] [-g STEGO_FILE]
                         [-o CONFIG_FILE] [-f/--force] [-v/--verbose]
                         [-h/--help] [-V/--version]""",
            file=sys.stderr
            )
        print(f"{p.prog}: error: {msg}", file=sys.stderr)
        sys.exit(ec)
        
        
    @classmethod
    def __check_file(cls, f: str) -> None:
        """
        Check if file exists in current file system.
        """
        
        if not os.path.isfile(f):           
            cls.__eprint(f"the following value is not a file: {f}", 100)
        
        
    @classmethod
    def __parse_secret_message(cls) -> None:
        """
        Parse required data given for embedding.
        """
        
        # Data are expected on stdin.
        if cls.__args.secret_message == sys.stdin:
            # Read given input from 'stdin'.
            print("Please, enter the data you want to embed:")
            cls.__args.secret_message = sys.stdin.read().rstrip('\n')
            # In case that empty input was given, program correctly ends.
            if cls.__args.secret_message == "":
                sys.exit(0)

        # The whole file is going to be embedded.
        elif os.path.isfile(cls.__args.secret_message):
            cls.__args.secret_message = os.path.abspath(cls.__args.secret_message)

        # Embedded string can not be empty. It does not make any sense.
        elif cls.__args.secret_message == "":
            sys.exit(0)
            
            
    @classmethod
    def __parse_method(cls, method: str) -> None:
        """
        Parse given method. It only exchange their long versions for
        short to better manipulate with them in the rest of program.
        """
        
        if method == "instruction-substitution":
            cls.__args.method = "sub"
        elif method == "extended-substitution":
            cls.__args.method = "ext-sub"
        elif method == "nops-using":
            cls.__args.method = "nops"
        elif method == "mov-scheduling":
            cls.__args.method = "mov"
            
            
    @classmethod
    def __set_config_file(cls) -> None:
        """
        Configuration file must be given by argument if this python
        program is run from other than parent and current folder.
        Default path to the configuration file is set as well.
        """
        
        # Configuration file was given by argument.
        if cls.__args.config_file is not None:
            cls.__args.config_file = os.path.abspath(cls.__args.config_file)
            cls.__check_file(cls.__args.config_file)
        # Configuration file was not given. Taking default one.
        else:
            # main.py script was invoked from ../src folder.
            if os.path.isdir("./config"):
                cls.__args.config_file = os.path.abspath("./config/eq-classes.json")
                cls.__check_file(cls.__args.config_file)
            # main.py script was invoked from ./src folder.
            elif os.path.isdir("../config"):
                cls.__args.config_file = os.path.abspath("../config/eq-classes.json")
                cls.__check_file(cls.__args.config_file)
            else:
                print(f"Please, provide configuration file for correct run or run this script from parent folder of src scripts or from src folder directly.")
                sys.exit(0)
                

    @classmethod
    def __check_args(cls) -> None:
        """
        Check correctness of parsed arguments and convert them to the appropriate form.
        """
        
        # Print HELP if no arguments were given.
        if len(sys.argv) == 1:
            cls.__parser.print_help(sys.stderr)
            sys.exit(0)
        
        # Catching exceptions according to parser setup.
        try:
            cls.__args = cls.__parser.parse_args()
        except argparse.ArgumentError:
            cls.__eprint("wrong mode or value of argument was (not) given", 2)
        
        # Only change long form to the short one.
        cls.__parse_method(cls.__args.method)
        
        # Only for better readability of the following conditions.
        mode = cls.__args.mode
        cover_file = cls.__args.cover_file
        stego_file = cls.__args.stego_file
        
        # Check required options according to given mode and validate
        # their values (checking presence of secret message, if
        # required, is not necessary as default value was set).
        if mode == "e" or mode == "embed":
            if cover_file is not None:
                cls.__args.cover_file = os.path.abspath(cover_file)
                cls.__check_file(cls.__args.cover_file)
            else:
                cls.__eprint(
                    f"cover-file needs to be specified in '{mode}' mode", 100
                    )
                
            cls.__parse_secret_message()
            
        elif mode == "x" or mode == "extract":
            if stego_file is not None:
                cls.__args.stego_file = os.path.abspath(stego_file)
                cls.__check_file(cls.__args.stego_file)
            else:
                cls.__eprint(
                    f"stego-file needs to be specified in '{mode}' mode", 100
                    )
        
        elif mode == "a" or mode == "analyze":
            if cover_file is not None:
                cls.__args.cover_file = os.path.abspath(cover_file)
                cls.__check_file(cls.__args.cover_file)
            else:
                cls.__eprint(
                    f"cover-file needs to be specified in '{mode}' mode", 100
                    )
        
        # Check configuration file and set default file if not given.
        # Configuration file is needed for every mode.
        cls.__set_config_file()
            

    @classmethod
    def parse(cls) -> object:
        """
        Run argument parser.
        """
        
        cls.__set_parser()
        cls.__check_args()
        
        return cls.__args