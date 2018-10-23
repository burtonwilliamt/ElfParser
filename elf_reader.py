from IPython import embed
import queue
from pwn import *

EI_NIDENT = 16

ELF32_sizes = {
        "Addr":4,
        "Off":4,
        "Half":2,
        "Word":4,
        "Sword":4,
    }

ELF64_sizes = {
        "Addr":8,
        "Off":8,
        "Half":2,
        "Word":4,
        "Sword":4,
        "Xword":8,
        "Sxword":8,
    }

SH_TYPE_ENUM = {
        0:"SHT_NULL",
        1:"SHT_PROGBITS",
        2:"SHT_SYMTAB",
        3:"SHT_STRTAB",
        4:"SHT_RELA",
        5:"SHT_HASH",
        6:"SHT_DYNAMIC",
        7:"SHT_NOTE",
        8:"SHT_NOBITS",
        9:"SHT_REL",
        10:"SHT_SHLIB",
        11:"SHT_DYNSYM",
        14:"SHT_INIT_ARRAY",
        15:"SHT_FINI_ARRAY",
        16:"SHT_PREINIT_ARRAY",
        17:"SHT_GROUP",
        18:"SHT_SYMTAB_SHNDX",
        }



class FileWrapper():
    def __init__(self, f):
        self.f = f

    # blindly read n bytes from the front of the file
    def read(self, n):
        result = self.f.read(n)
        return result

    # read n bytes from the next alignment of k from start
    def read_align(self, n, k=None, start=0):
        # if no alignment specified, assume aligned to n
        if not k:
            k = n
        remainder = self.f.tell() % k
        num_pad = (k-remainder) % k
        pad = self.read(num_pad)
        result = self.read(n)
        return result

    # unpack the data using the context
    def read_uint(self, n):
        result = self.read_align(n)
        return unpack(result,"all", endian=context.endian, sign=False)

    def read_int(self, n):
        result = self.read_align(n)
        return unpack(result,"all", endian=context.endian, sign=True)

    def seek(self, offset):
        self.f.seek(offset)

    def tell(self):
        return self.f.tell()

class ElfHeader():
    def __init__(self, f):
        self.e_ident = None		#unsigned char
        self.e_type = None		#Elf32_Half
        self.e_machine = None		#Elf32_Half
        self.e_version = None		#Elf32_Word
        self.e_entry = None		#Elf32_Addr
        self.e_phoff = None		#Elf32_Off
        self.e_shoff = None		#Elf32_Off
        self.e_flags = None		#Elf32_Word
        self.e_ehsize = None		#Elf32_Half
        self.e_phentsize = None		#Elf32_Half
        self.e_phnum = None		#Elf32_Half
        self.e_shentsize = None		#Elf32_Half
        self.e_shnum = None		#Elf32_Half
        self.e_shstrndx = None		#Elf32_Half
        self.parse_header(f)
        self.parse_section_header_table(f)


    def parse_header(self, f):

        #Parse e_ident
        self.e_ident = f.read(EI_NIDENT)
        #Magic number
        assert(self.e_ident[0:4] == "\x7fELF")
        # 1 means 32, 2 means 64
        EI_CLASS = ord(self.e_ident[4])
        #TODO: Are these the right sizes to put here?
        if EI_CLASS == 1:
            context.bits = 32
        elif EI_CLASS == 2:
            context.bits = 64
        else:
            assert(False)
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        if EI_DATA == 1:
            context.endian = "little"
        elif EI_DATA == 2:
            context.endian = "big"
        else:
            assert(False)
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        assert(EI_VERSION == 1)
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]

        #Parse the rest of the header
        self.e_type = self.Half(f)
        self.e_machine = self.Half(f)
        self.e_version = self.Word(f)
        self.e_entry = self.Addr(f)
        self.e_phoff = self.Off(f)
        self.e_shoff = self.Off(f)
        self.e_flags = self.Word(f)
        self.e_ehsize = self.Half(f)
        self.e_phentsize = self.Half(f)
        self.e_phnum = self.Half(f)
        self.e_shentsize = self.Half(f)
        self.e_shnum = self.Half(f)
        self.e_shstrndx = self.Half(f)


    def parse_section_header_table(self, f):
        self.sht = []
        f.seek(self.e_shoff)
        assert(self.e_shnum < 0xff00)
        for i in xrange(self.e_shnum):
            section = {}
            section["sh_name"] = self.Word(f)
            section["sh_type"] = self.Word(f)
            section["sh_flags"] = self.Xword(f)
            section["sh_addr"] = self.Addr(f)
            section["sh_offset"] = self.Off(f)
            section["sh_size"] = self.Xword(f)
            section["sh_link"] = self.Word(f)
            section["sh_info"] = self.Word(f)
            section["sh_addralign"] = self.Xword(f)
            section["sh_entsize"] = self.Xword(f)

            type_num = section["sh_type"]
            type_str = ""
            if 0x6fffffff >= type_num >= 0x60000000:
                type_str = "SHT_OS"
            elif 0x7fffffff >= type_num >= 0x70000000:
                type_str = "SHT_PROC"
            elif 0xffffffff >= type_num >=0x80000000:
                type_str = "SHT_USER"
            else:
                type_str = SH_TYPE_ENUM[type_num]
            section["sh_type_str"] = type_str
            if section["sh_type_str"] == "SHT_STRTAB":
                old_pos = f.tell()
                f.seek(section["sh_offset"])
                section["str_table"] = f.read(section["sh_size"])
                f.seek(old_pos)
            del section["sh_type"]


            section["sh_flags_strs"] = []
            if section["sh_flags"] & 0x1:
                section["sh_flags_strs"].append("SHF_WRITE")
            if section["sh_flags"] & 0x2:
                section["sh_flags_strs"].append("SHF_ALLOC")
            if section["sh_flags"] & 0x4:
                section["sh_flags_strs"].append("SHF_EXECINSTR")
            if section["sh_flags"] & 0x10:
                section["sh_flags_strs"].append("SHF_MERGE")
            if section["sh_flags"] & 0x20:
                section["sh_flags_strs"].append("SHF_STRINGS")
            if section["sh_flags"] & 0x40:
                section["sh_flags_strs"].append("SHF_INFO_LINK")
            if section["sh_flags"] & 0x80:
                section["sh_flags_strs"].append("SHF_LINK_ORDER")
            if section["sh_flags"] & 0x100:
                section["sh_flags_strs"].append("SHF_OS_NONCONFORMING")
            if section["sh_flags"] & 0x200:
                section["sh_flags_strs"].append("SHF_GROUP")
            if section["sh_flags"] & 0x400:
                section["sh_flags_strs"].append("SHF_TLS")
            if section["sh_flags"] & 0x800:
                section["sh_flags_strs"].append("SHF_COMPRESSED")
            if section["sh_flags"] & 0x0ff00000:
                section["sh_flags_strs"].append("SHF_MASKOS")
            if section["sh_flags"] & 0xf0000000:
                section["sh_flags_strs"].append("SHF_MASKPROC")

            del section["sh_flags"]

            self.sht.append(section)

        sh_names_section = self.sht[self.e_shstrndx]
        f.seek(sh_names_section["sh_offset"])
        sh_names = f.read(sh_names_section["sh_size"])
        for section in self.sht:
            section["sh_name"] = sh_names[section["sh_name"]::].split("\x00")[0]

    def Half(self, f):
        return f.read_uint(2)

    def Word(self, f):
        return f.read_uint(4)

    def Xword(self, f):
        return f.read_uint(context.bytes)

    def Addr(self, f):
        return f.read_uint(context.bytes)

    def Off(self, f):
        return f.read_uint(context.bytes)

def main():
    file_name = "a.out"
    with open(file_name, "rb") as f:
        f = FileWrapper(f)
        elf_header = ElfHeader(f)
        embed()

main()
