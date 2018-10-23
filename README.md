# ElfParser
This project is a project to try and understand how the Executable and Linkable Format works for binaries. In it's current state, the tool parses the elf header and reads the section header table. I am building this tool with the information available on the [wikipedia page](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).

## Running
This project is written in python, and needs the following packages:
 * pwntools
 * IPython
IPython is optional, but requires removing it from the code if you don't have it. Simply run `python elf_parser.py` to execute the code. It will be parsing the `a.out` binary, which the source code is available in `main.c`. It is equivalent to `/bin/true` on unix systems.
