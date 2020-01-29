/*
Copyright (C) 2001-2015 by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef ELFTYPES_H
#define ELFTYPES_H

#ifndef ELFIO_NO_OWN_TYPES
    #if !defined(ELFIO_NO_CSTDINT) && !defined(ELFIO_NO_INTTYPES)
        #include <stdint.h>
    #else
        typedef unsigned char  uint8_t;
        typedef signed char    int8_t;
        typedef unsigned short uint16_t;
        typedef signed short   int16_t;
        #ifdef _MSC_VER
            typedef unsigned __int32 uint32_t;
            typedef signed   __int32 int32_t;
            typedef unsigned __int64 uint64_t;
            typedef signed   __int64 int64_t;
        #else
            typedef unsigned int       uint32_t;
            typedef signed   int       int32_t;
            typedef unsigned long long uint64_t;
            typedef signed   long long int64_t;
        #endif // _MSC_VER
    #endif // ELFIO_NO_CSTDINT
#endif // ELFIO_NO_OWN_TYPES

namespace ELFIO {

// Attention! Platform depended definitions.
typedef uint16_t Elf_Half;
typedef uint32_t Elf_Word;
typedef int32_t  Elf_Sword;
typedef uint64_t Elf_Xword;
typedef int64_t  Elf_Sxword;

// DECOMPILER!
typedef uint8_t  Elf64_Byte;

typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;

#define Elf32_Half Elf_Half
#define Elf64_Half Elf_Half
#define Elf32_Word Elf_Word
#define Elf64_Word Elf_Word
#define Elf32_Sword Elf_Sword
#define Elf64_Sword Elf_Sword

///////////////////////
// ELF Header Constants

// File type
#define ET_NONE        0
#define ET_REL         1
#define ET_EXEC        2
#define ET_DYN         3
#define ET_CORE        4
#define ET_LOOS   0xFE00
#define ET_HIOS   0xFEFF
#define ET_LOPROC 0xFF00
#define ET_HIPROC 0xFFFF

#define EM_NONE          0   // No machine
#define EM_M32           1   // AT&T WE 32100
#define EM_SPARC         2   // SUN SPARC
#define EM_386           3   // Intel 80386
#define EM_68K           4   // Motorola m68k family
#define EM_88K           5   // Motorola m88k family
#define EM_486           6   // Intel 80486// Reserved for future use
#define EM_860           7   // Intel 80860
#define EM_MIPS          8   // MIPS R3000 (officially, big-endian only)
#define EM_S370          9   // IBM System/370
#define EM_MIPS_RS3_LE   10  // MIPS R3000 little-endian (Oct 4 1999 Draft) Deprecated
#define EM_res011        11  // Reserved
#define EM_res012        12  // Reserved
#define EM_res013        13  // Reserved
#define EM_res014        14  // Reserved
#define EM_PARISC        15  // HPPA
#define EM_res016        16  // Reserved
#define EM_VPP550        17  // Fujitsu VPP500
#define EM_SPARC32PLUS   18  // Sun's "v8plus"
#define EM_960           19  // Intel 80960
#define EM_PPC           20  // PowerPC
#define EM_PPC64         21  // 64-bit PowerPC
#define EM_S390          22  // IBM S/390
#define EM_SPU           23  // Sony/Toshiba/IBM SPU
#define EM_res024        24  // Reserved
#define EM_res025        25  // Reserved
#define EM_res026        26  // Reserved
#define EM_res027        27  // Reserved
#define EM_res028        28  // Reserved
#define EM_res029        29  // Reserved
#define EM_res030        30  // Reserved
#define EM_res031        31  // Reserved
#define EM_res032        32  // Reserved
#define EM_res033        33  // Reserved
#define EM_res034        34  // Reserved
#define EM_res035        35  // Reserved
#define EM_V800          36  // NEC V800 series
#define EM_FR20          37  // Fujitsu FR20
#define EM_RH32          38  // TRW RH32
#define EM_MCORE         39  // Motorola M*Core // May also be taken by Fujitsu MMA
#define EM_RCE           39  // Old name for MCore
#define EM_ARM           40  // ARM
#define EM_OLD_ALPHA     41  // Digital Alpha
#define EM_SH            42  // Renesas (formerly Hitachi) / SuperH SH
#define EM_SPARCV9       43  // SPARC v9 64-bit
#define EM_TRICORE       44  // Siemens Tricore embedded processor
#define EM_ARC           45  // ARC Cores
#define EM_H8_300        46  // Renesas (formerly Hitachi) H8/300
#define EM_H8_300H       47  // Renesas (formerly Hitachi) H8/300H
#define EM_H8S           48  // Renesas (formerly Hitachi) H8S
#define EM_H8_500        49  // Renesas (formerly Hitachi) H8/500
#define EM_IA_64         50  // Intel IA-64 Processor
#define EM_MIPS_X        51  // Stanford MIPS-X
#define EM_COLDFIRE      52  // Motorola Coldfire
#define EM_68HC12        53  // Motorola M68HC12
#define EM_MMA           54  // Fujitsu Multimedia Accelerator
#define EM_PCP           55  // Siemens PCP
#define EM_NCPU          56  // Sony nCPU embedded RISC processor
#define EM_NDR1          57  // Denso NDR1 microprocesspr
#define EM_STARCORE      58  // Motorola Star*Core processor
#define EM_ME16          59  // Toyota ME16 processor
#define EM_ST100         60  // STMicroelectronics ST100 processor
#define EM_TINYJ         61  // Advanced Logic Corp. TinyJ embedded processor
#define EM_X86_64        62  // Advanced Micro Devices X86-64 processor
#define EM_PDSP          63  // Sony DSP Processor
#define EM_PDP10         64  // Digital Equipment Corp. PDP-10
#define EM_PDP11         65  // Digital Equipment Corp. PDP-11
#define EM_FX66          66  // Siemens FX66 microcontroller
#define EM_ST9PLUS       67  // STMicroelectronics ST9+ 8/16 bit microcontroller
#define EM_ST7           68  // STMicroelectronics ST7 8-bit microcontroller
#define EM_68HC16        69  // Motorola MC68HC16 Microcontroller
#define EM_68HC11        70  // Motorola MC68HC11 Microcontroller
#define EM_68HC08        71  // Motorola MC68HC08 Microcontroller
#define EM_68HC05        72  // Motorola MC68HC05 Microcontroller
#define EM_SVX           73  // Silicon Graphics SVx
#define EM_ST19          74  // STMicroelectronics ST19 8-bit cpu
#define EM_VAX           75  // Digital VAX
#define EM_CRIS          76  // Axis Communications 32-bit embedded processor
#define EM_JAVELIN       77  // Infineon Technologies 32-bit embedded cpu
#define EM_FIREPATH      78  // Element 14 64-bit DSP processor
#define EM_ZSP           79  // LSI Logic's 16-bit DSP processor
#define EM_MMIX          80  // Donald Knuth's educational 64-bit processor
#define EM_HUANY         81  // Harvard's machine-independent format
#define EM_PRISM         82  // SiTera Prism
#define EM_AVR           83  // Atmel AVR 8-bit microcontroller
#define EM_FR30          84  // Fujitsu FR30
#define EM_D10V          85  // Mitsubishi D10V
#define EM_D30V          86  // Mitsubishi D30V
#define EM_V850          87  // NEC v850
#define EM_M32R          88  // Renesas M32R (formerly Mitsubishi M32R)
#define EM_MN10300       89  // Matsushita MN10300
#define EM_MN10200       90  // Matsushita MN10200
#define EM_PJ            91  // picoJava
#define EM_OPENRISC      92  // OpenRISC 32-bit embedded processor
#define EM_ARC_A5        93  // ARC Cores Tangent-A5
#define EM_XTENSA        94  // Tensilica Xtensa Architecture
#define EM_VIDEOCORE     95  // Alphamosaic VideoCore processor
#define EM_TMM_GPP       96  // Thompson Multimedia General Purpose Processor
#define EM_NS32K         97  // National Semiconductor 32000 series
#define EM_TPC           98  // Tenor Network TPC processor
#define EM_SNP1K         99  // Trebia SNP 1000 processor
#define EM_ST200         100 // STMicroelectronics ST200 microcontroller
#define EM_IP2K          101 // Ubicom IP2022 micro controller
#define EM_MAX           102 // MAX Processor
#define EM_CR            103 // National Semiconductor CompactRISC
#define EM_F2MC16        104 // Fujitsu F2MC16
#define EM_MSP430        105 // TI msp430 micro controller
#define EM_BLACKFIN      106 // ADI Blackfin
#define EM_SE_C33        107 // S1C33 Family of Seiko Epson processors
#define EM_SEP           108 // Sharp embedded microprocessor
#define EM_ARCA          109 // Arca RISC Microprocessor
#define EM_UNICORE       110 // Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
#define EM_EXCESS        111 // eXcess: 16/32/64-bit configurable embedded CPU
#define EM_DXP           112 // Icera Semiconductor Inc. Deep Execution Processor
#define EM_ALTERA_NIOS2  113 // Altera Nios II soft-core processor
#define EM_CRX           114 // National Semiconductor CRX
#define EM_XGATE         115 // Motorola XGATE embedded processor
#define EM_C166          116 // Infineon C16x/XC16x processor
#define EM_M16C          117 // Renesas M16C series microprocessors
#define EM_DSPIC30F      118 // Microchip Technology dsPIC30F Digital Signal Controller
#define EM_CE            119 // Freescale Communication Engine RISC core
#define EM_M32C          120 // Renesas M32C series microprocessors
#define EM_res121        121 // Reserved
#define EM_res122        122 // Reserved
#define EM_res123        123 // Reserved
#define EM_res124        124 // Reserved
#define EM_res125        125 // Reserved
#define EM_res126        126 // Reserved
#define EM_res127        127 // Reserved
#define EM_res128        128 // Reserved
#define EM_res129        129 // Reserved
#define EM_res130        130 // Reserved
#define EM_TSK3000       131 // Altium TSK3000 core
#define EM_RS08          132 // Freescale RS08 embedded processor
#define EM_res133        133 // Reserved
#define EM_ECOG2         134 // Cyan Technology eCOG2 microprocessor
#define EM_SCORE         135 // Sunplus Score
#define EM_SCORE7        135 // Sunplus S+core7 RISC processor
#define EM_DSP24         136 // New Japan Radio (NJR) 24-bit DSP Processor
#define EM_VIDEOCORE3    137 // Broadcom VideoCore III processor
#define EM_LATTICEMICO32 138 // RISC processor for Lattice FPGA architecture
#define EM_SE_C17        139 // Seiko Epson C17 family
#define EM_TI_C6000      140 // Texas Instruments TMS320C6000 DSP family
#define EM_TI_C2000      141 // Texas Instruments TMS320C2000 DSP family
#define EM_TI_C5500      142 // Texas Instruments TMS320C55x DSP family
#define EM_res143        143 // Reserved
#define EM_res144        144 // Reserved
#define EM_res145        145 // Reserved
#define EM_res146        146 // Reserved
#define EM_res147        147 // Reserved
#define EM_res148        148 // Reserved
#define EM_res149        149 // Reserved
#define EM_res150        150 // Reserved
#define EM_res151        151 // Reserved
#define EM_res152        152 // Reserved
#define EM_res153        153 // Reserved
#define EM_res154        154 // Reserved
#define EM_res155        155 // Reserved
#define EM_res156        156 // Reserved
#define EM_res157        157 // Reserved
#define EM_res158        158 // Reserved
#define EM_res159        159 // Reserved
#define EM_MMDSP_PLUS    160 // STMicroelectronics 64bit VLIW Data Signal Processor
#define EM_CYPRESS_M8C   161 // Cypress M8C microprocessor
#define EM_R32C          162 // Renesas R32C series microprocessors
#define EM_TRIMEDIA      163 // NXP Semiconductors TriMedia architecture family
#define EM_QDSP6         164 // QUALCOMM DSP6 Processor
#define EM_8051          165 // Intel 8051 and variants
#define EM_STXP7X        166 // STMicroelectronics STxP7x family
#define EM_NDS32         167 // Andes Technology compact code size embedded RISC processor family
#define EM_ECOG1         168 // Cyan Technology eCOG1X family
#define EM_ECOG1X        168 // Cyan Technology eCOG1X family
#define EM_MAXQ30        169 // Dallas Semiconductor MAXQ30 Core Micro-controllers
#define EM_XIMO16        170 // New Japan Radio (NJR) 16-bit DSP Processor
#define EM_MANIK         171 // M2000 Reconfigurable RISC Microprocessor
#define EM_CRAYNV2       172 // Cray Inc. NV2 vector architecture
#define EM_RX            173 // Renesas RX family
#define EM_METAG         174 // Imagination Technologies META processor architecture
#define EM_MCST_ELBRUS   175 // MCST Elbrus general purpose hardware architecture
#define EM_ECOG16        176 // Cyan Technology eCOG16 family
#define EM_CR16          177 // National Semiconductor CompactRISC 16-bit processor
#define EM_ETPU          178 // Freescale Extended Time Processing Unit
#define EM_SLE9X         179 // Infineon Technologies SLE9X core
#define EM_L1OM          180 // Intel L1OM
#define EM_INTEL181      181 // Reserved by Intel
#define EM_INTEL182      182 // Reserved by Intel
#define EM_AARCH64       183 // ARM 64-bit architecture (AARCH64)
#define EM_res184        184 // Reserved by ARM
#define EM_AVR32         185 // Atmel Corporation 32-bit microprocessor family
#define EM_STM8          186 // STMicroeletronics STM8 8-bit microcontroller
#define EM_TILE64        187 // Tilera TILE64 multicore architecture family
#define EM_TILEPRO       188 // Tilera TILEPro multicore architecture family
#define EM_MICROBLAZE    189 // Xilinx MicroBlaze 32-bit RISC soft processor core
#define EM_CUDA          190 // NVIDIA CUDA architecture
#define EM_TILEGX        191 // Tilera TILE-Gx multicore architecture family
#define EM_CLOUDSHIELD   192 // CloudShield architecture family
#define EM_COREA_1ST     193 // KIPO-KAIST Core-A 1st generation processor family
#define EM_COREA_2ND     194 // KIPO-KAIST Core-A 2nd generation processor family
#define EM_ARC_COMPACT2  195 // Synopsys ARCompact V2
#define EM_OPEN8         196 // Open8 8-bit RISC soft processor core
#define EM_RL78          197 // Renesas RL78 family
#define EM_VIDEOCORE5    198 // Broadcom VideoCore V processor
#define EM_78KOR         199 // Renesas 78KOR family
#define EM_56800EX       200 // Freescale 56800EX Digital Signal Controller (DSC)
#define EM_BA1           201 // Beyond BA1 CPU architecture
#define EM_BA2           202 // Beyond BA2 CPU architecture
#define EM_XCORE         203 // XMOS xCORE processor family
#define EM_MCHP_PIC      204 // Microchip 8-bit PIC(r) family
#define EM_INTEL205      205 // Reserved by Intel
#define EM_INTEL206      206 // Reserved by Intel
#define EM_INTEL207      207 // Reserved by Intel
#define EM_INTEL208      208 // Reserved by Intel
#define EM_INTEL209      209 // Reserved by Intel
#define EM_KM32          210 // KM211 KM32 32-bit processor
#define EM_KMX32         211 // KM211 KMX32 32-bit processor
#define EM_KMX16         212 // KM211 KMX16 16-bit processor
#define EM_KMX8          213 // KM211 KMX8 8-bit processor
#define EM_KVARC         214 // KM211 KVARC processor
#define EM_CDP           215 // Paneve CDP architecture family
#define EM_COGE          216 // Cognitive Smart Memory Processor
#define EM_COOL          217 // iCelero CoolEngine
#define EM_NORC          218 // Nanoradio Optimized RISC
#define EM_CSR_KALIMBA   219 // CSR Kalimba architecture family
#define EM_Z80           220 // Zilog Z80
#define EM_VISIUM        221 // Controls and Data Services VISIUMcore processor
#define EM_FT32          222 // FTDI Chip FT32 high performance 32-bit RISC architecture
#define EM_MOXIE         223 // Moxie processor family
#define EM_AMDGPU        224 // AMD GPU architecture
#define EM_RISCV         243 // RISC-V
#define EM_LANAI         244 // Lanai processor
#define EM_CEVA          245 // CEVA Processor Architecture Family
#define EM_CEVA_X2       246 // CEVA X2 Processor Family
#define EM_BPF           247 // Linux BPF – in-kernel virtual machine

// File version
#define EV_NONE    0
#define EV_CURRENT 1

// Identification index
#define EI_MAG0        0
#define EI_MAG1        1
#define EI_MAG2        2
#define EI_MAG3        3
#define EI_CLASS       4
#define EI_DATA        5
#define EI_VERSION     6
#define EI_OSABI       7
#define EI_ABIVERSION  8
#define EI_PAD         9
#define EI_NIDENT     16

// Magic number
#define ELFMAG0 0x7F
#define ELFMAG1  'E'
#define ELFMAG2  'L'
#define ELFMAG3  'F'

// File class
#define ELFCLASSNONE 0
#define ELFCLASS32   1
#define ELFCLASS64   2

// Encoding
#define ELFDATANONE 0
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2

// OS extensions
#define ELFOSABI_NONE     0 // No extensions or unspecified
#define ELFOSABI_HPUX     1 // Hewlett-Packard HP-UX
#define ELFOSABI_NETBSD   2 // NetBSD
#define ELFOSABI_LINUX    3 // Linux
#define ELFOSABI_SOLARIS  6 // Sun Solaris
#define ELFOSABI_AIX      7 // AIX
#define ELFOSABI_IRIX     8 // IRIX
#define ELFOSABI_FREEBSD  9 // FreeBSD
#define ELFOSABI_TRU64   10 // Compaq TRU64 UNIX
#define ELFOSABI_MODESTO 11 // Novell Modesto
#define ELFOSABI_OPENBSD 12 // Open BSD
#define ELFOSABI_OPENVMS 13 // Open VMS
#define ELFOSABI_NSK     14 // Hewlett-Packard Non-Stop Kernel
#define ELFOSABI_AROS    15 // Amiga Research OS
#define ELFOSABI_FENIXOS 16 // The FenixOS highly scalable multi-core OS
// DECOMPILER BEGIN
#define ELFOSABI_CLOUDABI 17 // Nuxi CloudABI
#define ELFOSABI_OPENVOS  18 // Stratus Technologies OpenVOS
// DECOMPILER END
//                       64-255 Architecture-specific value range

// File flags
#define EF_ARM_ABIMASK 0xFF000000

/////////////////////
// Sections constants

// Section indexes
#define SHN_UNDEF          0
#define SHN_LORESERVE 0xFF00
#define SHN_LOPROC    0xFF00
#define SHN_HIPROC    0xFF1F
#define SHN_LOOS      0xFF20
#define SHN_HIOS      0xFF3F
#define SHN_ABS       0xFFF1
#define SHN_COMMON    0xFFF2
#define SHN_XINDEX    0xFFFF
#define SHN_HIRESERVE 0xFFFF

// Section types
#define SHT_NULL                   0
#define SHT_PROGBITS               1
#define SHT_SYMTAB                 2
#define SHT_STRTAB                 3
#define SHT_RELA                   4
#define SHT_HASH                   5
#define SHT_DYNAMIC                6
#define SHT_NOTE                   7
#define SHT_NOBITS                 8
#define SHT_REL                    9
#define SHT_SHLIB                 10
#define SHT_DYNSYM                11
#define SHT_INIT_ARRAY            14
#define SHT_FINI_ARRAY            15
#define SHT_PREINIT_ARRAY         16
#define SHT_GROUP                 17
#define SHT_SYMTAB_SHNDX          18
#define SHT_LOOS          0x60000000
#define SHT_HIOS          0x6fffffff
#define SHT_LOPROC        0x70000000
#define SHT_HIPROC        0x7FFFFFFF
#define SHT_LOUSER        0x80000000
#define SHT_HIUSER        0xFFFFFFFF

// Section attribute flags
#define SHF_WRITE                   0x1
#define SHF_ALLOC                   0x2
#define SHF_EXECINSTR               0x4
#define SHF_MERGE                  0x10
#define SHF_STRINGS                0x20
#define SHF_INFO_LINK              0x40
#define SHF_LINK_ORDER             0x80
#define SHF_OS_NONCONFORMING      0x100
#define SHF_GROUP                 0x200
#define SHF_TLS                   0x400
#define SHF_COMPRESSED            0x800
#define SHF_MASKOS           0x0ff00000
#define SHF_MASKPROC         0xF0000000

// Section group flags
#define GRP_COMDAT          0x1
#define GRP_MASKOS   0x0ff00000
#define GRP_MASKPROC 0xf0000000

// Symbol binding
#define STB_LOCAL     0
#define STB_GLOBAL    1
#define STB_WEAK      2
#define STB_LOOS     10
#define STB_HIOS     12
#define STB_MULTIDEF 13
#define STB_LOPROC   13
#define STB_HIPROC   15

// Symbol types
#define STT_NOTYPE   0
#define STT_OBJECT   1
#define STT_FUNC     2
#define STT_SECTION  3
#define STT_FILE     4
#define STT_COMMON   5
#define STT_TLS      6
#define STT_LOOS    10
#define STT_HIOS    12
#define STT_LOPROC  13
#define STT_HIPROC  15

// Symbol visibility
#define STV_DEFAULT   0
#define STV_INTERNAL  1
#define STV_HIDDEN    2
#define STV_PROTECTED 3

// Undefined name
#define STN_UNDEF 0

// Relocation types
#define R_386_NONE         0
#define R_X86_64_NONE      0
#define R_386_32           1
#define R_X86_64_64        1
#define R_386_PC32         2
#define R_X86_64_PC32      2
#define R_386_GOT32        3
#define R_X86_64_GOT32     3
#define R_386_PLT32        4
#define R_X86_64_PLT32     4
#define R_386_COPY         5
#define R_X86_64_COPY      5
#define R_386_GLOB_DAT     6
#define R_X86_64_GLOB_DAT  6
#define R_386_JMP_SLOT     7
#define R_X86_64_JUMP_SLOT 7
#define R_386_RELATIVE     8
#define R_X86_64_RELATIVE  8
#define R_386_GOTOFF       9
#define R_X86_64_GOTPCREL  9
#define R_386_GOTPC       10
#define R_X86_64_32       10
#define R_X86_64_32S      11
#define R_X86_64_16       12
#define R_X86_64_PC16     13
#define R_X86_64_8        14
#define R_X86_64_PC8      15
#define R_X86_64_DTPMOD64 16
#define R_X86_64_DTPOFF64 17
#define R_X86_64_TPOFF64  18
#define R_X86_64_TLSGD    19
#define R_X86_64_TLSLD    20
#define R_X86_64_DTPOFF32 21
#define R_X86_64_GOTTPOFF 22
#define R_X86_64_TPOFF32  23
#define R_X86_64_PC64     24
#define R_X86_64_GOTOFF64 25
#define R_X86_64_GOTPC32  26
#define R_X86_64_GOT64    27
#define R_X86_64_GOTPCREL64      28
#define R_X86_64_GOTPC64  29
#define R_X86_64_GOTPLT64 30
#define R_X86_64_PLTOFF64 31
#define R_X86_64_GOTPC32_TLSDESC 34
#define R_X86_64_TLSDESC_CALL    35
#define R_X86_64_TLSDESC         36
#define R_X86_64_IRELATIVE       37
#define R_X86_64_GNU_VTINHERIT  250
#define R_X86_64_GNU_VTENTRY    251

// Decompiler BEGIN
#define R_ARM_ABS32       2
#define R_ARM_CALL        28

#define R_MIPS_32         2
#define R_MIPS_26         4
#define R_MIPS_HI16       5
#define R_MIPS_LO16       6

#define R_PPC_ADDR32      1
#define R_PPC_ADDR16_LO   4
#define R_PPC_ADDR16_HI   5
#define R_PPC_ADDR16_HA   6
#define R_PPC_REL24       10
// Decompiler END

// Segment types
#define PT_NULL             0
#define PT_LOAD             1
#define PT_DYNAMIC          2
#define PT_INTERP           3
#define PT_NOTE             4
#define PT_SHLIB            5
#define PT_PHDR             6
#define PT_TLS              7
#define PT_LOOS    0x60000000
#define PT_HIOS    0x6fffffff
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7FFFFFFF

// Segment flags
#define PF_X                 1 // Execute
#define PF_W                 2 // Write
#define PF_R                 4 // Read
#define PF_MASKOS   0x0ff00000 // Unspecified
#define PF_MASKPROC 0xf0000000 // Unspecified

// Dynamic Array Tags
#define DT_NULL              0
#define DT_NEEDED            1
#define DT_PLTRELSZ          2
#define DT_PLTGOT            3
#define DT_HASH              4
#define DT_STRTAB            5
#define DT_SYMTAB            6
#define DT_RELA              7
#define DT_RELASZ            8
#define DT_RELAENT           9
#define DT_STRSZ            10
#define DT_SYMENT           11
#define DT_INIT             12
#define DT_FINI             13
#define DT_SONAME           14
#define DT_RPATH            15
#define DT_SYMBOLIC         16
#define DT_REL              17
#define DT_RELSZ            18
#define DT_RELENT           19
#define DT_PLTREL           20
#define DT_DEBUG            21
#define DT_TEXTREL          22
#define DT_JMPREL           23
#define DT_BIND_NOW         24
#define DT_INIT_ARRAY       25
#define DT_FINI_ARRAY       26
#define DT_INIT_ARRAYSZ     27
#define DT_FINI_ARRAYSZ     28
#define DT_RUNPATH          29
#define DT_FLAGS            30
#define DT_ENCODING         32
#define DT_PREINIT_ARRAY    32
#define DT_PREINIT_ARRAYSZ  33
#define DT_MAXPOSTAGS       34
#define DT_LOOS     0x6000000D
#define DT_HIOS     0x6ffff000
#define DT_LOPROC   0x70000000
#define DT_HIPROC   0x7FFFFFFF

#define DT_MIPS_RLD_VERSION  0x70000001
#define DT_MIPS_TIME_STAMP   0x70000002
#define DT_MIPS_ICHECKSUM    0x70000003
#define DT_MIPS_IVERSION     0x70000004
#define DT_MIPS_FLAGS        0x70000005
#define DT_MIPS_BASE_ADDRESS 0x70000006
#define DT_MIPS_CONFLICT     0x70000008
#define DT_MIPS_LIBLIST      0x70000009
#define DT_MIPS_LOCAL_GOTNO  0x7000000A
#define DT_MIPS_CONFLICTNO   0x7000000B
#define DT_MIPS_LIBLISTNO    0x70000010
#define DT_MIPS_SYMTABNO     0x70000011
#define DT_MIPS_UNREFEXTNO   0x70000012
#define DT_MIPS_GOTSYM       0x70000013
#define DT_MIPS_HIPAGENO     0x70000014
#define DT_MIPS_RLD_MAP      0x70000016

// DT_FLAGS values
#define DF_ORIGIN     0x1
#define DF_SYMBOLIC   0x2
#define DF_TEXTREL    0x4
#define DF_BIND_NOW   0x8
#define DF_STATIC_TLS 0x10

// ELF file header
struct Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf_Half    e_type;
    Elf_Half    e_machine;
    Elf_Word    e_version;
    Elf32_Addr  e_entry;
    Elf32_Off   e_phoff;
    Elf32_Off   e_shoff;
    Elf_Word    e_flags;
    Elf_Half    e_ehsize;
    Elf_Half    e_phentsize;
    Elf_Half    e_phnum;
    Elf_Half    e_shentsize;
    Elf_Half    e_shnum;
    Elf_Half    e_shstrndx;
};

struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf_Half    e_type;
    Elf_Half    e_machine;
    Elf_Word    e_version;
    Elf64_Addr  e_entry;
    Elf64_Off   e_phoff;
    Elf64_Off   e_shoff;
    Elf_Word    e_flags;
    Elf_Half    e_ehsize;
    Elf_Half    e_phentsize;
    Elf_Half    e_phnum;
    Elf_Half    e_shentsize;
    Elf_Half    e_shnum;
    Elf_Half    e_shstrndx;
};

// Section header
struct Elf32_Shdr {
    Elf_Word   sh_name;
    Elf_Word   sh_type;
    Elf_Word   sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    Elf_Word   sh_size;
    Elf_Word   sh_link;
    Elf_Word   sh_info;
    Elf_Word   sh_addralign;
    Elf_Word   sh_entsize;
};

struct Elf64_Shdr {
    Elf_Word   sh_name;
    Elf_Word   sh_type;
    Elf_Xword  sh_flags;
    Elf64_Addr sh_addr;
    Elf64_Off  sh_offset;
    Elf_Xword  sh_size;
    Elf_Word   sh_link;
    Elf_Word   sh_info;
    Elf_Xword  sh_addralign;
    Elf_Xword  sh_entsize;
};

// Segment header
struct Elf32_Phdr {
    Elf_Word   p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf_Word   p_filesz;
    Elf_Word   p_memsz;
    Elf_Word   p_flags;
    Elf_Word   p_align;
};

struct Elf64_Phdr {
    Elf_Word   p_type;
    Elf_Word   p_flags;
    Elf64_Off  p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    Elf_Xword  p_filesz;
    Elf_Xword  p_memsz;
    Elf_Xword  p_align;
};

// Symbol table entry
struct Elf32_Sym {
    Elf_Word      st_name;
    Elf32_Addr    st_value;
    Elf_Word      st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf_Half      st_shndx;
};

struct Elf64_Sym {
    Elf_Word      st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf_Half      st_shndx;
    Elf64_Addr    st_value;
    Elf_Xword     st_size;
};

#define ELF_ST_BIND(i)   ((i)>>4)
#define ELF_ST_TYPE(i)   ((i)&0xf)
#define ELF_ST_INFO(b,t) (((b)<<4)+((t)&0xf))

#define ELF_ST_VISIBILITY(o) ((o)&0x3)

// Relocation entries
struct Elf32_Rel {
    Elf32_Addr r_offset;
    Elf_Word   r_info;
};

struct Elf32_Rela {
    Elf32_Addr r_offset;
    Elf_Word   r_info;
    Elf_Sword  r_addend;
};

struct Elf64_Rel {
    Elf64_Addr r_offset;
    Elf_Xword  r_info;
};

struct Elf64_Rela {
    Elf64_Addr r_offset;
    Elf_Xword  r_info;
    Elf_Sxword r_addend;
};

// DECOMPILER!
struct Elf64_Mips_Rel {
    Elf64_Addr r_offset;
    Elf_Word   r_sym;
    Elf64_Byte r_ssym;
    Elf64_Byte r_type3;
    Elf64_Byte r_type2;
    Elf64_Byte r_type;
};

// DECOMPILER!
struct Elf64_Mips_Rela {
    Elf64_Addr r_offset;
    Elf_Word   r_sym;
    Elf64_Byte r_ssym;
    Elf64_Byte r_type3;
    Elf64_Byte r_type2;
    Elf64_Byte r_type;
    Elf_Sxword r_addend;
};

#define ELF32_R_SYM(i)    ((i)>>8)
#define ELF32_R_TYPE(i)   ((unsigned char)(i))
#define ELF32_R_INFO(s,t) (((s)<<8 )+(unsigned char)(t))

#define ELF64_R_SYM(i)    ((i)>>32)
#define ELF64_R_TYPE(i)   ((i)&0xffffffffL)
#define ELF64_R_INFO(s,t) ((((int64_t)s)<<32)+((t)&0xffffffffL))

// Dynamic structure
struct Elf32_Dyn {
    Elf_Sword d_tag;
    union {
        Elf_Word   d_val;
        Elf32_Addr d_ptr;
    } d_un;
};

struct Elf64_Dyn {
    Elf_Sxword d_tag;
    union {
        Elf_Xword  d_val;
        Elf64_Addr d_ptr;
    } d_un;
};

} // namespace ELFIO

#endif // ELFTYPES_H
