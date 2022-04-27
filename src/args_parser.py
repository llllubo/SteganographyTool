import os.path
import sys
import argparse


class ArgsParser():
    
    __parser = None
    __args = None
        
        
    @classmethod
    def __set_parser(cls) -> None:
        
        cls.__parser = argparse.ArgumentParser(
            usage="""
  %(prog)s MODE -m METHOD [-s SECRET_MESSAGE] [-c COVER_FILE] [-g STEGO_FILE]
                         [-o CONFIG_FILE] [-f/--force] [-v/--verbose]
                         [-h/--help] [-V/--version]""",
            description="""Steganography for Executables

  This program embeds and extracts any type of message to given executable.
  The program can run in one of four possible modes (embed, extract, analyze
  and reset) specified by positional argument. Then, neccessary is also choose
  one of possible steganography methods to embed message. There are instruction
  substitution and instruction sequence methods. Neither one of them can change
  final size of stego-file. Allowed values of particular arguments are listed
  below.""",
            epilog="\u00A9 2022 Ľuboš Bever. All rights reserved.",
            formatter_class=argparse.RawTextHelpFormatter,
            add_help=False,
            exit_on_error=False
            )
        
        # cls.__parser._positionals.title = "Positional arguments:"
        # cls.__parser._optionals.title = "Optional arguments:"
        
        cls.__parser.add_argument(
            "mode",
            help="""the mode in which program will run (possible values:
'e'/'embed', 'x'/'extract', 'a'/'analyze' or 'r'/'reset')

MODE=embed   - embeds secret message to the cover file
MODE=extract - extracts secret message from stego-file
MODE=analyze - analyzes potentional of cover file for
               given steganography method
MODE=reset   - resets hidden message from stego-file""",
            metavar="MODE",
            choices=["e", "embed",
                     "x", "extract",
                     "a", "analyze",
                     "r", "reset"]
            )
        
        requiredArgs = cls.__parser.add_argument_group("required arguments")
        requiredArgs.add_argument(
            "-m",
            "--method",
            help="""steganography METHOD used to embed/extract/reset message
or analyze cover file (possible values: 'sub'/
'instruction-substitution' or 'seq'/'instruction-sequence')""",
            metavar="METHOD",
            choices=["sub", "instruction-substitution",
                     "ext-sub", "extended-substitution",
                     "nops", "nops-using",
                     "mov", "mov-scheduling",
                     "ext-sub-nops-mov"],
            required=True
            )
        
        cls.__parser.add_argument(
            "-h",
            "--help",
            help="""show this message and exit
            """,
            action="help",
            default=argparse.SUPPRESS
            )
        cls.__parser.add_argument(
            "-s",
            "--secret-message",
            help="""SECRET_MESSAGE to be hidden within executable (any
sequence of bytes)
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
            help="""executable (STEGO_FILE) with embedded secret message
to be extracted or reset
            """
            )
        cls.__parser.add_argument(
            "-o",
            "--config-file",
            help="""configuration file (CONFIG_FILE) with informations
determining encoding while embedding/extracting message
            """
            )
        cls.__parser.add_argument(
            "-f",
            "--force",
            help="""strengthen the selection of potential instructions
(influence only [extended] substitution of instruction)
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
            help="""show current program's version and exit (ignoring other
arguments)""",
            action="version",
            version="%(prog)s 1.0\n\u00A9 2022 Ľuboš Bever. All rights reserved."
            )
        
        
    @classmethod
    def __eprint(cls, msg: str, ec: int) -> None:
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
        if not os.path.isfile(f):           
            cls.__eprint(f"the following value is not a file: {f}", 100)
        
        
    @classmethod
    def __parse_secret_message(cls) -> None:
        # ak je secret_message stdin, zacnem citat vstup
        # vystup do ./extracted/output.txt; pripona sa neuklada, ulozi sa ako same jednicky -- nuly budu ziadna pripona - binarka
        if cls.__args.secret_message == sys.stdin:
            # Read given input from 'stdin'.
            print("Please, enter the data you want to embed:")
            cls.__args.secret_message = sys.stdin.read().rstrip('\n')
            # In case that empty input was given, program correctly ends.
            if cls.__args.secret_message == "":
                sys.exit(0)
        # ak je zadane -s, check ci je to platna cesta
        # ak ano, skryvat sa bude binarny obsah suboru (teda cely subor)
        # citam subor binarne, po bajtoch, vystup bude subor (uklada sa pripona)
        # The whole file is going to be embedded.
        elif os.path.isfile(cls.__args.secret_message):
            cls.__args.secret_message = os.path.abspath(cls.__args.secret_message)
        # ak je zadane -s a nie je to platna cesta
        # ide len o random string, citam po bajtoch, extrahuje sa do ./extracted/output.txt
        # Embedded will be just string.
        elif cls.__args.secret_message == "":
            sys.exit(0)
            
            
    @classmethod
    def __parse_method(cls, method: str) -> None:
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
        # ak bude script spustany z inej zlozky ako src ci parent, bude
        # musiet byt zadany config file ze argument, inak chyba.
        
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
            else:
                cls.__args.config_file = os.path.abspath("../config/eq-classes.json")
                cls.__check_file(cls.__args.config_file)
                

    @classmethod
    def __check_args(cls) -> None:
        
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
        
        elif mode == "r" or mode == "reset":
            if stego_file is not None:
                cls.__args.stego_file = os.path.abspath(stego_file)
                cls.__check_file(cls.__args.stego_file)
            else:
                cls.__eprint(
                    f"stego-file needs to be specified in '{mode}' mode", 100
                    )
        
        # Check configuration file and set default file if not given.
        # Configuration file is needed for every mode.
        cls.__set_config_file()
            

    @classmethod
    def parse(cls) -> object:        
        cls.__set_parser()
        cls.__check_args()
        
        return cls.__args