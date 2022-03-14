'''
    This file is part of AFL-Cast.

    AFL-Cast is free software: you can redistribute it and/or modify it under the terms of the 
    GNU General Public License as published by the Free Software Foundation, either version 3 
    of the License, or (at your option) any later version.

    AFL-Cast is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with AFL-Cast. 
    If not, see <https://www.gnu.org/licenses/>. 

'''

from optparse import OptionParser
from AFLGraph import AFL
import logging
import os


def build_parser():
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-i", "--input", dest="input", help="The target executable")
    parser.add_option("-b", "--bitmap", dest="bitmap", help="The fuzz_bitmap from AFL")
    parser.add_option(
        "-l",
        "--loadoffset",
        default="0x0",
        dest="offset",
        help="The offset at which the binary is loaded in IDA/Binja",
    )
    parser.add_option(
        "-g",
        "--graph",
        default="graph.dot",
        dest="graph",
        help="Graph output from Coverage",
    )
    parser.add_option(
        "-f",
        "--function",
        default="main",
        dest="function",
        help="Entry Point of AFL Instrumented code (ex. main)",
    )
    parser.add_option(
        "-o",
        "--output",
        default="coverage.dump",
        dest="outputfile",
        help="Output dump file",
    )
    return parser


def main():

    parser = build_parser()
    (options, args) = parser.parse_args()

    if options.input is None or options.bitmap is None:
        parser.error("Missing target/bitmap file")
        parser.print_help()
        exit(-1)

    # Sanity check for the input files
    if not os.path.isfile(options.input):
        parser.error("Input executable file does not exist")
        exit(-1)

    if not os.path.isfile(options.bitmap):
        parser.error("Input bitmap file does not exist")
        exit(-1)

    # Convert the offset from hex/decimal representation
    try:
        if options.offset.startswith("0x"):
            options.offset = int(options.offset, 16)
        else:
            options.offset = int(options.offset)
    except ValueError:
        parser.error("Invalid offset")
        parser.print_help()
        exit(-1)

    logging.info(f"[+] Load offset is {hex(options.offset)}")

    if options.outputfile is not None:
        logging.info(
            f"[+] Converted coverage output file will be present at {options.outputfile}"
        )

    afl = AFL(
        options.input, options.bitmap, options.function, True, ["__afl_maybe_log"]
    )
    graph = afl.get_afl_graph()
    graph.get_hits()
    graph.get_dot(options.graph)

    if options.outputfile is not None:
        graph.dump(options.outputfile)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
