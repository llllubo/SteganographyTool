import os.path
import sys
import argparse


class ArgsParser():
    
    __parser = None
    __args = None
        
        
    @staticmethod
    def __set_parser() -> None:
        
        ArgsParser.__parser = argparse.ArgumentParser(
            usage="""
  %(prog)s MODE -m METHOD [-s SECRET_MESSAGE] [-c COVER_FILE] [-g STEGO_FILE]
            [-v/--verbose] [-h/--help] [-V/--version]""",
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
        
        # ArgsParser.__parser._positionals.title = "Positional arguments:"
        # ArgsParser.__parser._optionals.title = "Optional arguments:"
        
        ArgsParser.__parser.add_argument(
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
        
        requiredArgs = ArgsParser.__parser.add_argument_group("required arguments")
        requiredArgs.add_argument(
            "-m",
            "--method",
            help="""steganography METHOD used to embed/extract/reset message
or analyze cover file (possible values: 'sub'/
'instruction-substitution' or 'seq'/'instruction-sequence')""",
            metavar="METHOD",
            choices=["sub", "instruction-substitution",
                     "ext-sub", "extended-substitution",
                     "nops", "nops-embedding",
                     "ext-sub-nops"],
            required=True
            )
        
        ArgsParser.__parser.add_argument(
            "-h",
            "--help",
            help="""show this message and exit
            """,
            action="help",
            default=argparse.SUPPRESS
            )
        ArgsParser.__parser.add_argument(
            "-s",
            "--secret-message",
            help="""SECRET_MESSAGE to be hidden within executable (any
sequence of bytes)
 """,
            default=sys.stdin
            )
        ArgsParser.__parser.add_argument(
            "-c",
            "--cover-file",
            help="""COVER_FILE (executable) to be secret message hidden in
            """
            )
        ArgsParser.__parser.add_argument(
            "-g",
            "--stego-file",
            help="""executable (STEGO_FILE) with embedded secret message
to be extracted or reset
            """
            )
        ArgsParser.__parser.add_argument(
            "-v",
            "--verbose",
            help="""output verbosity while processing
            """,
            action="store_true"
            )
        ArgsParser.__parser.add_argument(
            "-V",
            "--version",
            help="""show current program's version and exit (ignoring other
arguments)""",
            action="version",
            version="%(prog)s 1.0\n\u00A9 2022 Ľuboš Bever. All rights reserved."
            )
        
        
    @staticmethod
    def __eprint(msg: str, ec: int) -> None:
        p = ArgsParser.__parser
        print("usage:", file=sys.stderr)
        print(
            f"  {p.prog} " """MODE -m METHOD [-s SECRET_MESSAGE] [-c COVER_FILE] [-g STEGO_FILE]
            [-v/--verbose] [-h/--help] [-V/--version]""",
            file=sys.stderr
            )
        print(f"{p.prog}: error: {msg}", file=sys.stderr)
        sys.exit(ec)
        
        
    @staticmethod
    def __check_file(f: str) -> None:
        if not os.path.isfile(f):           
            ArgsParser.__eprint(f"the following value is not a file: {f}", 100)
        
        
    @staticmethod
    def __parse_secret_message() -> None:
        # ak je secret_message stdin, zacnem citat vstup
        # vystup do ./extracted/output.txt; pripona sa neuklada, ulozi sa ako same jednicky -- nuly budu ziadna pripona - binarka
        if ArgsParser.__args.secret_message == sys.stdin:
            # Read given input from 'stdin'.
            print("Please, enter the data you want to embed:")
            ArgsParser.__args.secret_message = sys.stdin.read().rstrip('\n')
            # In case that empty input was given, program correctly ends.
            if ArgsParser.__args.secret_message == "":
                sys.exit(0)
        # ak je zadane -s, check ci je to platna cesta
        # ak ano, skryvat sa bude binarny obsah suboru (teda cely subor)
        # citam subor binarne, po bajtoch, vystup bude subor (uklada sa pripona)
        # The whole file is going to be embedded.
        elif os.path.isfile(ArgsParser.__args.secret_message):
            ArgsParser.__args.secret_message = os.path.abspath(ArgsParser.__args.secret_message)
        # ak je zadane -s a nie je to platna cesta
        # ide len o random string, citam po bajtoch, extrahuje sa do ./extracted/output.txt
        # Embedded will be just string.
        elif ArgsParser.__args.secret_message == "":
            sys.exit(0)
        
                
    @staticmethod
    def __check_args() -> None:
        
        # Print HELP if no arguments were given.
        if len(sys.argv) == 1:
            ArgsParser.__parser.print_help(sys.stderr)
            sys.exit(0)
        
        # Catching exceptions according to parser setup.
        try:
            ArgsParser.__args = ArgsParser.__parser.parse_args()
        except argparse.ArgumentError:
            ArgsParser.__eprint("wrong mode or value of argument was (not) given", 2)
            
        # Only for better readability of the following conditions.
        mode = ArgsParser.__args.mode
        cover_file = ArgsParser.__args.cover_file
        stego_file = ArgsParser.__args.stego_file
        
        # Check required options according to given mode and validate
        # their values (checking presence of secret message, if
        # required, is not necessary as default value was set).
        if mode == "e" or mode == "embed":
            if cover_file is not None:
                ArgsParser.__args.cover_file = os.path.abspath(cover_file)
                ArgsParser.__check_file(ArgsParser.__args.cover_file)
            else:
                ArgsParser.__eprint(
                    f"cover-file needs to be specified in '{mode}' mode", 100
                    )
                
            ArgsParser.__parse_secret_message()
            
        elif mode == "x" or mode == "extract":
            if stego_file is not None:
                ArgsParser.__args.stego_file = os.path.abspath(stego_file)
                ArgsParser.__check_file(ArgsParser.__args.stego_file)
            else:
                ArgsParser.__eprint(
                    f"stego-file needs to be specified in '{mode}' mode", 100
                    )
        
        elif mode == "a" or mode == "analyze":
            if cover_file is not None:
                ArgsParser.__args.cover_file = os.path.abspath(cover_file)
                ArgsParser.__check_file(ArgsParser.__args.cover_file)
            else:
                ArgsParser.__eprint(
                    f"cover-file needs to be specified in '{mode}' mode", 100
                    )
        
        elif mode == "r" or mode == "reset":
            if stego_file is not None:
                ArgsParser.__args.stego_file = os.path.abspath(stego_file)
                ArgsParser.__check_file(ArgsParser.__args.stego_file)
            else:
                ArgsParser.__eprint(
                    f"stego-file needs to be specified in '{mode}' mode", 100
                    )
        

    @staticmethod
    def parse() -> object:        
        ArgsParser.__set_parser()
        ArgsParser.__check_args()
        
        return ArgsParser.__args