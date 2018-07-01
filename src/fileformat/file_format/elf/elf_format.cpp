/**
 * @file src/fileformat/file_format/elf/elf_format.cpp
 * @brief Methods of ElfFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <map>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/file_format/elf/elf_format.h"
#include "retdec/fileformat/types/symbol_table/elf_symbol.h"
#include "retdec/fileformat/utils/conversions.h"

using namespace retdec::utils;
using namespace ELFIO;

namespace retdec {
namespace fileformat {

namespace
{

// Relocation masks are stored as vectors of bytes (stored as little endian).
// Trailing 0x00 bytes are necessary for byte endianness swapping. Do NOT remove them.

// Relocation ALL_NONE represents COPY/NONE relocations (no bits are changed).
// We do not use empty vector, that is reserved for unknown relocations.
const std::vector<std::uint8_t> ALL_NONE = {0x00};

// Full byte aligned types common for all architectures.
const std::vector<std::uint8_t> ALL_BYTE = {0xFF};
const std::vector<std::uint8_t> ALL_WORD = {0xFF, 0xFF};
const std::vector<std::uint8_t> ALL_DWORD = {0xFF, 0xFF, 0xFF, 0xFF};
const std::vector<std::uint8_t> ALL_QWORD = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Special types to denote that relocation type is obsolete and may be reused in the future.
const std::vector<std::uint8_t> ALL_OBSOLETE_WORD = ALL_WORD;
const std::vector<std::uint8_t> ALL_OBSOLETE_DWORD = ALL_DWORD;
const std::vector<std::uint8_t> ALL_OBSOLETE_QWORD = ALL_QWORD;

// Special types to denote that relocation type is experimental and may change in the future.
const std::vector<std::uint8_t> ALL_EXPERIMENTAL_WORD = ALL_WORD;
const std::vector<std::uint8_t> ALL_EXPERIMENTAL_DWORD = ALL_DWORD;

// x64 architecture specific types.
// Source: System V Application Binary Interface AMD64 Architecture Processor Supplement.
const std::vector<std::uint8_t> x64_128BITS =
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// MIPS architecture specific types.
// Source: SYSTEM V APPLICATION BINARY INTERFACE MIPS(R) RISC Processor Supplement.
const std::vector<std::uint8_t> MIPS_TARG26 = {0xFF, 0xFF, 0xFF, 0x03};
const std::vector<std::uint8_t> MIPS_HALF16 = {0xFF, 0XFF, 0x00, 0x00};
// Special types for MIPS R6 architecture.
// Source: 'arch/mips/kernel/module-rela.c'.
const std::vector<std::uint8_t> MIPS_PC26 = MIPS_TARG26;
const std::vector<std::uint8_t> MIPS_PC21 = {0xFF, 0xFF, 0x1F, 0x00};
// Source: 'lib/ReaderWriter/ELF/Mips/MipsRelocationHandler.cpp'.
const std::vector<std::uint8_t> MIPS_PC19 = {0xFF, 0xFF, 0x07, 0x00};
const std::vector<std::uint8_t> MIPS_PC18 = {0xFF, 0xFF, 0x03, 0x00};
// Special types for microMIPS architecture.
// Source: 'llvm/trunk/lib/Target/Mips/MCTargetDesc/MipsAsmBackend.cpp'.
const std::vector<std::uint8_t> MIPS_PCHI16 = MIPS_HALF16;
const std::vector<std::uint8_t> MIPS_PCLO16 = MIPS_HALF16;

// PPC architecture specific types.
// Source: PowerPC Architecture(R) 32-bit Application Binary Interface Supplement.
const std::vector<std::uint8_t> PPC_LOW24 = {0xFC, 0xFF, 0xFF, 0x03};
const std::vector<std::uint8_t> PPC_LOW21 = {0xFF, 0xFF, 0x1F, 0x00};
const std::vector<std::uint8_t> PPC_LOW14 = {0xFC, 0xFF, 0x20, 0x00};
const std::vector<std::uint8_t> PPC_WORD30 = {0xFC, 0xFF, 0xFF, 0xFF};
// SPE specific types.
const std::vector<std::uint8_t> PPC_MID5 = {0x00, 0xF8, 0x00, 0x00};
const std::vector<std::uint8_t> PPC_MID10 = {0x00, 0xF8, 0x1F, 0x00};
// VLE specific types.
const std::vector<std::uint8_t> PPC_SPLIT20 = {0xFF, 0x7F, 0x1F, 0x00};
const std::vector<std::uint8_t> PPC_SPLIT16A = {0xFF, 0x07, 0x1F, 0x00};
const std::vector<std::uint8_t> PPC_SPLIT16D = {0xFF, 0x07, 0xE0, 0x03};
const std::vector<std::uint8_t> PPC_BDH24 = {0xFE, 0xFF, 0xFF, 0x01};
const std::vector<std::uint8_t> PPC_BDH15 = {0xFE, 0xFF, 0x00, 0x00};
const std::vector<std::uint8_t> PPC_BDH8 = {0xFF, 0x00};

// ARM architecture specific types.
// Source: ELF for the ARM(R) Architecture.
const std::vector<std::uint8_t> ARM_MOV = {0xFF, 0x0F, 0x0F, 0x00};
const std::vector<std::uint8_t> ARM_LDR = {0xFF, 0x0F, 0x80, 0x00};
const std::vector<std::uint8_t> ARM_LDC = {0xFF, 0x00, 0x80, 0x00};
// Thumb 16 special instruction types.
const std::vector<std::uint8_t> THUMB16_LDR_IMM = {0xC0, 0x07};
const std::vector<std::uint8_t> THUMB16_LDR_LIT = {0xFF, 0x00};
const std::vector<std::uint8_t> THUMB16_HALF = {0xFF, 0x00};
const std::vector<std::uint8_t> THUMB16_CBZ = {0xFF, 0x02};
const std::vector<std::uint8_t> THUMB16_B = {0xFF, 0x07};
// Thumb 32 special instruction types.
const std::vector<std::uint8_t> THUMB32_ADR = {0xFF, 0x70, 0x00, 0x04};
const std::vector<std::uint8_t> THUMB32_MOV = {0xFF, 0x70, 0x0F, 0x04};

// ARM 64 architecture specific types.
// Source: ELF for the ARM(R) 64-bit Architecture.
const std::vector<std::uint8_t> AARCH64_ADD_IMM = {0x00, 0xFC, 0x3F, 0x00}; // ADD[S] instruction.
const std::vector<std::uint8_t> AARCH64_ADR_IMM = {0xE0, 0xFF, 0xFF, 0x60}; // ADR[P] instruction.
const std::vector<std::uint8_t> AARCH64_MOV_IMM = {0xE0, 0xFF, 0x1F, 0x60}; // MOV[K|Z|N] instruction.

// Map for x86 architecture.
// Source: System V Application Binary Interface Intel386 Architecture Processor Supplement.
// Source: Oracle Thread-Local Storage (Linker and Libraries Guide).
const std::map<unsigned, const std::vector<std::uint8_t>*> x86RelocationMap =
{
	{0, &ALL_NONE},
	{1, &ALL_DWORD},
	{2, &ALL_DWORD},
	{3, &ALL_DWORD},
	{4, &ALL_DWORD},
	{5, &ALL_NONE},
	{6, &ALL_DWORD},
	{7, &ALL_DWORD},
	{8, &ALL_DWORD},
	{9, &ALL_DWORD},
	{10, &ALL_DWORD},
	{11, &ALL_DWORD},
	{12, &ALL_DWORD},
	{13, &ALL_DWORD},
	{14, &ALL_DWORD},
	{15, &ALL_DWORD},
	{16, &ALL_DWORD},
	{17, &ALL_DWORD},
	{18, &ALL_DWORD},
	{19, &ALL_DWORD},
	{20, &ALL_WORD},
	{21, &ALL_WORD},
	{22, &ALL_BYTE},
	{23, &ALL_BYTE},
	{32, &ALL_DWORD},
	{33, &ALL_DWORD},
	{34, &ALL_DWORD},
	{35, &ALL_DWORD},
	{36, &ALL_DWORD},
	{37, &ALL_DWORD},
	{39, &ALL_DWORD},
	{40, &ALL_NONE},
	{41, &ALL_DWORD},
	{42, &ALL_DWORD},
	{43, &ALL_DWORD},
	{250, &ALL_NONE},
	{251, &ALL_NONE}
};

// Map for x64 architecture.
// Source: System V Application Binary Interface AMD64 Architecture Processor Supplement.
const std::map<unsigned, const std::vector<std::uint8_t>*> x86_64RelocationMap =
{
	{0, &ALL_NONE},
	{1, &ALL_QWORD},
	{2, &ALL_DWORD},
	{3, &ALL_DWORD},
	{4, &ALL_DWORD},
	{5, &ALL_NONE},
	{6, &ALL_QWORD},
	{7, &ALL_QWORD},
	{8, &ALL_QWORD},
	{9, &ALL_DWORD},
	{10, &ALL_DWORD},
	{11, &ALL_DWORD},
	{12, &ALL_WORD},
	{13, &ALL_WORD},
	{14, &ALL_BYTE},
	{15, &ALL_BYTE},
	{16, &ALL_QWORD},
	{17, &ALL_QWORD},
	{18, &ALL_QWORD},
	{19, &ALL_DWORD},
	{20, &ALL_DWORD},
	{21, &ALL_DWORD},
	{22, &ALL_DWORD},
	{23, &ALL_DWORD},
	{24, &ALL_QWORD},
	{25, &ALL_QWORD},
	{26, &ALL_DWORD},
	{27, &ALL_QWORD},
	{28, &ALL_QWORD},
	{29, &ALL_QWORD},
	{30, &ALL_QWORD},
	{31, &ALL_QWORD},
	{32, &ALL_DWORD},
	{33, &ALL_QWORD},
	{34, &ALL_DWORD},
	{35, &ALL_NONE},
	{36, &x64_128BITS},
	{37, &ALL_QWORD},
	{38, &ALL_QWORD},
	{39, &ALL_OBSOLETE_DWORD},
	{40, &ALL_OBSOLETE_DWORD},
	{250, &ALL_NONE},
	{251, &ALL_NONE}
};

// Map for MIPS architecture.
// Source: SYSTEM V APPLICATION BINARY INTERFACE MIPS (R) RISC Processor.
// Source: https://dmz-portal.mips.com/wiki/MIPS_relocation_types.
const std::map<unsigned, const std::vector<std::uint8_t>*> mipsRelocationMap =
{
	{0, &ALL_NONE},
	{1, &MIPS_HALF16},
	{2, &ALL_DWORD},
	{3, &ALL_DWORD},
	{4, &MIPS_TARG26},
	{5, &MIPS_HALF16},
	{6, &MIPS_HALF16},
	{7, &MIPS_HALF16},
	{8, &MIPS_HALF16},
	{9, &MIPS_HALF16},
	{10, &MIPS_HALF16},
	{11, &MIPS_HALF16},
	{12, &ALL_DWORD},
	{13, &ALL_OBSOLETE_DWORD},
	{14, &ALL_OBSOLETE_DWORD},
	{15, &ALL_OBSOLETE_DWORD},
	{16, &ALL_OBSOLETE_DWORD},
	{17, &ALL_OBSOLETE_DWORD},
	{18, &ALL_OBSOLETE_QWORD},
	{19, &ALL_OBSOLETE_DWORD},
	{20, &ALL_OBSOLETE_DWORD},
	{21, &MIPS_HALF16},
	{22, &MIPS_HALF16},
	{23, &MIPS_HALF16},
	{24, &ALL_QWORD},
	{25, &ALL_DWORD},
	{26, &ALL_DWORD},
	{27, &ALL_DWORD},
	{28, &MIPS_HALF16},
	{29, &MIPS_HALF16},
	{30, &MIPS_HALF16},
	{31, &MIPS_HALF16},
	{32, &ALL_DWORD},
	{33, &MIPS_HALF16},
	{34, &MIPS_HALF16},
	{35, &ALL_DWORD},
	{36, &ALL_DWORD},
	{37, &ALL_DWORD},
	{38, &ALL_DWORD},
	{39, &ALL_DWORD},
	{40, &ALL_QWORD},
	{41, &ALL_QWORD},
	{42, &MIPS_HALF16},
	{43, &MIPS_HALF16},
	{44, &MIPS_HALF16},
	{45, &MIPS_HALF16},
	{46, &MIPS_HALF16},
	{47, &ALL_DWORD},
	{48, &ALL_QWORD},
	{49, &MIPS_HALF16},
	{50, &MIPS_HALF16},
	{52, &ALL_OBSOLETE_DWORD},
	{60, &MIPS_PC21},
	{61, &MIPS_PC26},
	{62, &MIPS_PC18},
	{63, &MIPS_PC19},
	{64, &MIPS_HALF16},
	{65, &MIPS_HALF16},
	{100, &MIPS_TARG26},
	{101, &MIPS_HALF16},
	{113, &MIPS_HALF16},
	{126, &ALL_NONE},
	{133, &MIPS_TARG26},
	{136, &MIPS_HALF16},
	{158, &MIPS_HALF16},
	{159, &MIPS_HALF16},
	{174, &MIPS_PC21},
	{175, &MIPS_PC26},
	{176, &MIPS_PC18},
	{177, &MIPS_PC19},
	{248, &ALL_DWORD},
	{249, &ALL_DWORD},
	{250, &MIPS_HALF16},
	{253, &ALL_NONE},
	{254, &ALL_NONE}
};

const std::map<unsigned, const std::vector<std::uint8_t>*> mips32RelocationMap =
{
	{127, &ALL_DWORD}
};

const std::map<unsigned, const std::vector<std::uint8_t>*> mips64RelocationMap =
{
	{127, &ALL_QWORD}
};

// Map for PowerPC architecture.
// Source: PowerPC Architecture(R) 32-bit Application Binary Interface Supplement.
const std::map<unsigned, const std::vector<std::uint8_t>*> powerpcRelocationMap =
{
	{0, &ALL_NONE},
	{1, &ALL_DWORD},
	{2, &PPC_LOW24},
	{3, &ALL_WORD},
	{4, &ALL_WORD},
	{5, &ALL_WORD},
	{6, &ALL_WORD},
	{7, &PPC_LOW14},
	{8, &PPC_LOW14},
	{9, &PPC_LOW14},
	{10, &PPC_LOW24},
	{11, &PPC_LOW14},
	{12, &PPC_LOW14},
	{13, &PPC_LOW14},
	{14, &ALL_WORD},
	{15, &ALL_WORD},
	{16, &ALL_WORD},
	{17, &ALL_WORD},
	{19, &ALL_NONE},
	{21, &ALL_NONE},
	{23, &PPC_LOW24},
	{24, &ALL_DWORD},
	{25, &ALL_WORD},
	{26, &ALL_DWORD},
	{27, &ALL_DWORD},
	{28, &ALL_DWORD},
	{29, &ALL_WORD},
	{30, &ALL_WORD},
	{31, &ALL_WORD},
	{33, &ALL_WORD},
	{34, &ALL_WORD},
	{35, &ALL_WORD},
	{36, &ALL_WORD},
	{37, &PPC_WORD30},
	{67, &ALL_NONE},
	{69, &ALL_WORD},
	{70, &ALL_WORD},
	{71, &ALL_WORD},
	{72, &ALL_WORD},
	{74, &ALL_WORD},
	{75, &ALL_WORD},
	{76, &ALL_WORD},
	{77, &ALL_WORD},
	{79, &ALL_WORD},
	{80, &ALL_WORD},
	{81, &ALL_WORD},
	{82, &ALL_WORD},
	{83, &ALL_WORD},
	{84, &ALL_WORD},
	{85, &ALL_WORD},
	{86, &ALL_WORD},
	{87, &ALL_WORD},
	{88, &ALL_WORD},
	{89, &ALL_WORD},
	{90, &ALL_WORD},
	{91, &ALL_WORD},
	{92, &ALL_WORD},
	{93, &ALL_WORD},
	{94, &ALL_WORD},
	{97, &ALL_WORD},
	{98, &ALL_WORD},
	{99, &ALL_WORD},
	{249, &ALL_WORD},
	{250, &ALL_WORD},
	{251, &ALL_WORD},
	{252, &ALL_WORD},
	{253, &ALL_NONE},
	{254, &ALL_NONE}
};

// Source: PowerPC Architecture(R) 32-bit Application Binary Interface Supplement.
const std::map<unsigned, const std::vector<std::uint8_t>*> powerpc32RelocationMap =
{
	{18, &PPC_LOW24},
	{20, &ALL_DWORD},
	{22, &ALL_DWORD},
	{23, &PPC_LOW24},
	{32, &ALL_WORD},
	{68, &ALL_DWORD},
	{73, &ALL_DWORD},
	{78, &ALL_DWORD},
	{95, &ALL_DWORD},
	{96, &ALL_DWORD},
	{101, &ALL_DWORD},
	{102, &ALL_WORD},
	{103, &ALL_WORD},
	{104, &ALL_WORD},
	{105, &ALL_WORD},
	{106, &ALL_WORD},
	{107, &ALL_WORD},
	{108, &ALL_WORD},
	{109, &PPC_LOW21},
	{110, &ALL_NONE},
	{111, &ALL_WORD},
	{112, &ALL_WORD},
	{113, &ALL_WORD},
	{114, &ALL_WORD},
	{115, &ALL_DWORD},
	{116, &ALL_WORD},
	{180, &PPC_LOW21},
	{181, &PPC_LOW21},
	{182, &PPC_LOW21},
	{183, &ALL_WORD},
	{184, &ALL_WORD},
	{185, &ALL_WORD},
	{201, &PPC_MID5},
	{202, &PPC_MID5},
	{203, &PPC_MID5},
	{204, &PPC_MID5},
	{205, &PPC_MID5},
	{206, &PPC_MID5},
	{207, &PPC_MID5},
	{208, &PPC_MID5},
	{208, &PPC_MID5},
	{210, &PPC_MID5},
	{211, &PPC_MID5},
	{212, &PPC_MID5},
	{213, &PPC_MID10},
	{214, &PPC_MID10},
	{215, &PPC_MID10},
	{216, &PPC_BDH8},
	{217, &PPC_BDH15},
	{218, &PPC_BDH24},
	{219, &PPC_SPLIT16A},
	{220, &PPC_SPLIT16D},
	{221, &PPC_SPLIT16A},
	{222, &PPC_SPLIT16D},
	{223, &PPC_SPLIT16A},
	{224, &PPC_SPLIT16D},
	{225, &ALL_DWORD},
	{226, &ALL_DWORD},
	{227, &PPC_SPLIT16A},
	{228, &PPC_SPLIT16D},
	{229, &PPC_SPLIT16A},
	{230, &PPC_SPLIT16D},
	{231, &PPC_SPLIT16A},
	{232, &PPC_SPLIT16D},
	{233, &PPC_SPLIT20},
	{248, &ALL_DWORD},
	{255, &ALL_WORD}
};

// Map for 64-bit PowerPC architecture.
// Source: 64-bit PowerPC ELF Application Binary Interface Supplement.
const std::map<unsigned, const std::vector<std::uint8_t>*> powerpc64RelocationMap =
{
	{20, &ALL_QWORD},
	{22, &ALL_QWORD},
	{38, &ALL_QWORD},
	{39, &ALL_WORD},
	{40, &ALL_WORD},
	{41, &ALL_WORD},
	{42, &ALL_WORD},
	{43, &ALL_QWORD},
	{44, &ALL_QWORD},
	{45, &ALL_QWORD},
	{46, &ALL_QWORD},
	{47, &ALL_WORD},
	{48, &ALL_WORD},
	{49, &ALL_WORD},
	{50, &ALL_WORD},
	{51, &ALL_QWORD},
	{52, &ALL_WORD},
	{53, &ALL_WORD},
	{54, &ALL_WORD},
	{55, &ALL_WORD},
	{56, &ALL_WORD},
	{57, &ALL_WORD},
	{58, &ALL_WORD},
	{59, &ALL_WORD},
	{60, &ALL_WORD},
	{61, &ALL_WORD},
	{62, &ALL_WORD},
	{63, &ALL_WORD},
	{64, &ALL_WORD},
	{65, &ALL_WORD},
	{66, &ALL_WORD},
	{68, &ALL_QWORD},
	{73, &ALL_QWORD},
	{78, &ALL_QWORD},
	{95, &ALL_WORD},
	{96, &ALL_WORD},
	{100, &ALL_WORD},
	{101, &ALL_WORD},
	{102, &ALL_WORD},
	{103, &ALL_WORD},
	{104, &ALL_WORD},
	{105, &ALL_WORD},
	{106, &ALL_WORD},
	{107, &ALL_DWORD},
	{108, &ALL_DWORD},
	{109, &ALL_DWORD},
	{110, &ALL_WORD},
	{111, &ALL_WORD},
	{112, &ALL_WORD},
	{113, &ALL_WORD},
	{114, &ALL_WORD},
	{115, &ALL_WORD},
	{117, &ALL_QWORD},
	{247, &ALL_NONE},
	{248, &ALL_QWORD}
};

// Map for ARM architecture.
// Source: ELF for the ARM(R) 64-bit Architecture.
const std::map<unsigned, const std::vector<std::uint8_t>*> arm32RelocationMap =
{
	{0, &ALL_NONE},
	{1, &ALL_DWORD},
	{2, &ALL_DWORD},
	{3, &ALL_DWORD},
	{4, &ARM_LDR},
	{5, &ALL_WORD},
	{6, &ARM_LDR},
	{7, &THUMB16_LDR_IMM},
	{8, &ALL_BYTE},
	{9, &ALL_DWORD},
	{10, &ALL_DWORD},
	{11, &THUMB16_LDR_LIT},
	{12, &ALL_DWORD},
	{13, &ALL_DWORD},
	{14, &ALL_OBSOLETE_DWORD},
	{15, &ALL_OBSOLETE_DWORD},
	{16, &ALL_OBSOLETE_DWORD},
	{17, &ALL_DWORD},
	{18, &ALL_DWORD},
	{19, &ALL_DWORD},
	{20, &ALL_NONE},
	{21, &ALL_DWORD},
	{22, &ALL_DWORD},
	{23, &ALL_DWORD},
	{24, &ALL_DWORD},
	{25, &ALL_DWORD},
	{26, &ALL_DWORD},
	{27, &ALL_OBSOLETE_DWORD},
	{28, &ALL_DWORD},
	{29, &ALL_DWORD},
	{30, &ALL_DWORD},
	{31, &ALL_DWORD},
	{32, &ALL_OBSOLETE_DWORD},
	{33, &ALL_OBSOLETE_DWORD},
	{34, &ALL_OBSOLETE_DWORD},
	{35, &ALL_OBSOLETE_DWORD},
	{36, &ALL_OBSOLETE_DWORD},
	{37, &ALL_OBSOLETE_DWORD},
	{38, &ALL_DWORD},
	{39, &ALL_OBSOLETE_DWORD},
	{40, &ALL_DWORD},
	{41, &ALL_DWORD},
	{42, &ALL_DWORD},
	{43, &ARM_MOV},
	{44, &ARM_MOV},
	{45, &ARM_MOV},
	{46, &ARM_MOV},
	{47, &THUMB32_MOV},
	{48, &THUMB32_MOV},
	{49, &THUMB32_MOV},
	{50, &THUMB32_MOV},
	{51, &ALL_DWORD},
	{52, &THUMB16_CBZ},
	{53, &THUMB32_ADR},
	{54, &ARM_LDR},
	{55, &ALL_DWORD},
	{56, &ALL_DWORD},
	{57, &ALL_DWORD},
	{58, &ALL_DWORD},
	{59, &ALL_DWORD},
	{60, &ALL_DWORD},
	{61, &ALL_DWORD},
	{62, &ARM_LDR},
	{63, &ARM_LDR},
	{64, &ARM_LDR},
	{65, &ARM_LDR},
	{66, &ARM_LDR},
	{67, &ARM_LDC},
	{68, &ARM_LDC},
	{69, &ARM_LDC},
	{70, &ALL_DWORD},
	{71, &ALL_DWORD},
	{72, &ALL_DWORD},
	{73, &ALL_DWORD},
	{74, &ALL_DWORD},
	{75, &ARM_LDR},
	{76, &ARM_LDR},
	{77, &ARM_LDR},
	{78, &ARM_LDR},
	{79, &ARM_LDR},
	{80, &ARM_LDR},
	{81, &ARM_LDC},
	{82, &ARM_LDC},
	{83, &ARM_LDC},
	{84, &ARM_MOV},
	{85, &ARM_MOV},
	{86, &ARM_MOV},
	{87, &THUMB32_MOV},
	{88, &THUMB32_MOV},
	{89, &THUMB32_MOV},
	{90, &ALL_EXPERIMENTAL_DWORD},
	{91, &ALL_EXPERIMENTAL_DWORD},
	{92, &ALL_EXPERIMENTAL_DWORD},
	{93, &ALL_EXPERIMENTAL_DWORD},
	{94, &ALL_DWORD},
	{95, &ALL_DWORD},
	{96, &ALL_DWORD},
	{97, &ARM_LDR},
	{98, &ARM_LDR},
	{100, &ALL_OBSOLETE_DWORD},
	{101, &ALL_OBSOLETE_DWORD},
	{102, &THUMB16_B},
	{103, &THUMB16_HALF},
	{104, &ALL_DWORD},
	{105, &ALL_DWORD},
	{106, &ALL_DWORD},
	{107, &ALL_DWORD},
	{108, &ALL_DWORD},
	{109, &ARM_LDR},
	{110, &ARM_LDR},
	{111, &ARM_LDR},
	// Relocations from 112 to 127 are private.
	// According to docs, they must not appear in object files.
	{128, &ALL_OBSOLETE_DWORD},
	{129, &ALL_EXPERIMENTAL_WORD},
	{129, &ALL_EXPERIMENTAL_DWORD},
	{130, &ALL_EXPERIMENTAL_DWORD},
	{131, &ALL_EXPERIMENTAL_DWORD},
	{132, &ALL_EXPERIMENTAL_DWORD},
	{133, &ALL_EXPERIMENTAL_DWORD},
	{134, &ALL_EXPERIMENTAL_DWORD},
	{135, &ALL_EXPERIMENTAL_DWORD},
	// Relocations from 136 to 255 are reserved.
	// We will treat them as unknown for now.
};

// Map for ARM 64-bit architecture.
// Source: ELF for the ARM(R) 64-bit Architecture.
const std::map<unsigned, const std::vector<std::uint8_t>*> arm64RelocationMap =
{
	{0, &ALL_NONE},
	{256, &ALL_NONE},
	{257, &ALL_QWORD},
	{258, &ALL_DWORD},
	{259, &ALL_WORD},
	{260, &ALL_QWORD},
	{261, &ALL_DWORD},
	{262, &ALL_WORD},
	{263, &AARCH64_MOV_IMM},
	{264, &AARCH64_MOV_IMM},
	{265, &AARCH64_MOV_IMM},
	{266, &AARCH64_MOV_IMM},
	{267, &AARCH64_MOV_IMM},
	{268, &AARCH64_MOV_IMM},
	{269, &AARCH64_MOV_IMM},
	{270, &AARCH64_MOV_IMM},
	{271, &AARCH64_MOV_IMM},
	{272, &AARCH64_MOV_IMM},
	{273, &ALL_DWORD},
	{274, &AARCH64_ADR_IMM},
	{275, &AARCH64_ADR_IMM},
	{276, &AARCH64_ADR_IMM},
	{277, &AARCH64_ADD_IMM},
	{278, &ALL_DWORD},
	{279, &ALL_DWORD},
	{280, &ALL_DWORD},
	{282, &ALL_DWORD},
	{283, &ALL_DWORD},
	{284, &ALL_DWORD},
	{285, &ALL_DWORD},
	{286, &ALL_DWORD},
	{287, &AARCH64_MOV_IMM},
	{288, &AARCH64_MOV_IMM},
	{289, &AARCH64_MOV_IMM},
	{290, &AARCH64_MOV_IMM},
	{291, &AARCH64_MOV_IMM},
	{292, &AARCH64_MOV_IMM},
	{293, &AARCH64_MOV_IMM},
	{299, &ALL_DWORD},
	{300, &AARCH64_MOV_IMM},
	{301, &AARCH64_MOV_IMM},
	{302, &AARCH64_MOV_IMM},
	{303, &AARCH64_MOV_IMM},
	{304, &AARCH64_MOV_IMM},
	{305, &AARCH64_MOV_IMM},
	{306, &AARCH64_MOV_IMM},
	{307, &ALL_QWORD},
	{308, &ALL_DWORD},
	{309, &ALL_DWORD},
	{310, &ALL_DWORD},
	{311, &AARCH64_ADR_IMM},
	{312, &ALL_DWORD},
	{313, &ALL_DWORD},
	{512, &AARCH64_ADR_IMM},
	{513, &AARCH64_ADR_IMM},
	{514, &AARCH64_ADD_IMM},
	{515, &AARCH64_MOV_IMM},
	{516, &AARCH64_MOV_IMM},
	{517, &AARCH64_ADR_IMM},
	{518, &AARCH64_ADR_IMM},
	{519, &AARCH64_ADD_IMM},
	{520, &AARCH64_MOV_IMM},
	{521, &AARCH64_MOV_IMM},
	{522, &ALL_DWORD},
	{523, &AARCH64_MOV_IMM},
	{524, &AARCH64_MOV_IMM},
	{525, &AARCH64_MOV_IMM},
	{526, &AARCH64_MOV_IMM},
	{527, &AARCH64_MOV_IMM},
	{528, &AARCH64_ADD_IMM},
	{529, &AARCH64_ADD_IMM},
	{530, &AARCH64_ADD_IMM},
	{531, &ALL_DWORD},
	{532, &ALL_DWORD},
	{533, &ALL_DWORD},
	{534, &ALL_DWORD},
	{535, &ALL_DWORD},
	{536, &ALL_DWORD},
	{537, &ALL_DWORD},
	{538, &ALL_DWORD},
	{539, &AARCH64_MOV_IMM},
	{540, &AARCH64_MOV_IMM},
	{541, &AARCH64_ADR_IMM},
	{542, &ALL_DWORD},
	{543, &ALL_DWORD},
	{544, &AARCH64_MOV_IMM},
	{545, &AARCH64_MOV_IMM},
	{546, &AARCH64_MOV_IMM},
	{547, &AARCH64_MOV_IMM},
	{548, &AARCH64_MOV_IMM},
	{549, &AARCH64_ADD_IMM},
	{550, &AARCH64_ADD_IMM},
	{551, &AARCH64_ADD_IMM},
	{552, &ALL_DWORD},
	{553, &ALL_DWORD},
	{554, &ALL_DWORD},
	{556, &ALL_DWORD},
	{557, &ALL_DWORD},
	{558, &ALL_DWORD},
	{559, &ALL_DWORD},
	{560, &ALL_DWORD},
	{561, &AARCH64_ADR_IMM},
	{562, &AARCH64_ADR_IMM},
	{563, &ALL_DWORD},
	{564, &AARCH64_ADD_IMM},
	{565, &AARCH64_MOV_IMM},
	{566, &AARCH64_MOV_IMM},
	{567, &ALL_NONE},
	{568, &ALL_NONE},
	{569, &ALL_NONE},
	{570, &ALL_DWORD},
	{571, &ALL_DWORD},
	{572, &ALL_DWORD},
	{573, &ALL_DWORD},
	{1024, &ALL_QWORD},
	{1025, &ALL_QWORD},
	{1026, &ALL_QWORD},
	{1027, &ALL_QWORD},
	{1028, &ALL_QWORD},
	{1029, &ALL_QWORD},
	{1030, &ALL_QWORD},
	{1031, &ALL_QWORD},
	{1032, &ALL_QWORD}
};

// Useful ELF note types

constexpr std::size_t NT_PRSTATUS = 0x00000001;
constexpr std::size_t NT_PRPSINFO = 0x00000003;
constexpr std::size_t NT_AUXV = 0x00000006;
constexpr std::size_t NT_FILE = 0x46494c45;

// Various architecture registers

const std::vector<std::string> x86Regs {
	"ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs",
	"eax_o", "eip", "cs", "eflags", "esp", "ss"
};

const std::vector<std::string> armRegs {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
	"r12", "sp", "lr", "pc", "cpsr"
};

const std::vector<std::string> x64Regs {
	"r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax",
	"rcx", "rdx", "rsi", "rdi", "rax_o", "rip", "cs", "rflags", "rsp", "ss",
	"fs_b", "gs_b", "ds", "es", "fs", "gs"
};

const std::vector<std::string> aarch64Regs {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
	"x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21",
	"x22", "x23", "x24", "x25","x26", "x27", "x28", "x29", "x30", "sp", "pc",
	"pstate"
};

// Names are same for both 32 and 64 bit PowerPC architectures
const std::vector<std::string> ppcRegs {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21",
	"r22", "r23", "r24", "r25","r26", "r27", "r28", "r29", "r30", "r31",
	"pc", "msr", "r3_o", "ctr", "lr", "xer", "cr", "softe", "trap", "dar",
	"dsisr", "result"
};

/**
 * Get type of symbol
 * @param bind ELF symbol bind
 * @param type ELF symbol type
 * @param link Link to ELF section
 * @return Type of symbol
 */
Symbol::Type getSymbolType(unsigned char bind, unsigned char type, ELFIO::Elf_Half link)
{
	switch(link)
	{
		case SHN_ABS:
			return Symbol::Type::ABSOLUTE_SYM;
		case SHN_COMMON:
			return Symbol::Type::COMMON;
		case SHN_UNDEF:
			if(bind != STB_LOCAL)
			{
				return Symbol::Type::EXTERN;
			}
			else if(type == STT_NOTYPE)
			{
				return Symbol::Type::UNDEFINED_SYM;
			}
		default:;
	}

	if(type == STT_COMMON)
	{
		return Symbol::Type::COMMON;
	}

	switch(bind)
	{
		case STB_LOCAL:
			return Symbol::Type::PRIVATE;
		case STB_GLOBAL:
			return Symbol::Type::PUBLIC;
		case STB_WEAK:
			return Symbol::Type::WEAK;
		default:;
	}

	return Symbol::Type::UNDEFINED_SYM;
}

/**
 * Get usage type of symbol
 * @param type ELF symbol type
 * @return Usage type of symbol
 */
Symbol::UsageType getSymbolUsageType(unsigned char type)
{
	switch(type)
	{
		case STT_FUNC:
			return Symbol::UsageType::FUNCTION;
		case STT_OBJECT:
			return Symbol::UsageType::OBJECT;
		case STT_FILE:
			return Symbol::UsageType::FILE;
		default:
			return Symbol::UsageType::UNKNOWN;
	}
}

/**
 * Get type of section
 * @param sec ELF section
 * @return Type of section
 */
ElfSection::Type getSectionType(const ELFIO::section &sec)
{
	const auto secFlags = sec.get_flags();
	if(secFlags & SHF_EXECINSTR)
	{
		return ElfSection::Type::CODE;
	}
	else if(sec.get_type() == SHT_PROGBITS)
	{
		if(startsWith(sec.get_name(), ".debug"))
		{
			return ElfSection::Type::DEBUG;
		}
		else if((secFlags & SHF_ALLOC) && !(secFlags & SHF_WRITE))
		{
			return ElfSection::Type::CONST_DATA;
		}
	}

	switch(sec.get_type())
	{
		case SHT_NULL:
			return ElfSection::Type::UNDEFINED_SEC_SEG;
		case SHT_NOBITS:
			return ElfSection::Type::BSS;
		case SHT_NOTE:
			return ElfSection::Type::INFO;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
		case SHT_STRTAB:
		case SHT_RELA:
		case SHT_REL:
		case SHT_HASH:
		case SHT_DYNAMIC:
		case SHT_SYMTAB_SHNDX:
			return ElfSection::Type::DATA;
		default:
			return (secFlags & SHF_WRITE || secFlags & SHF_COMPRESSED || secFlags & SHF_ALLOC) ?
				ElfSection::Type::DATA : ElfSection::Type::INFO;
	}
}

/**
 * Get type of segment
 * @param seg ELF segment
 * @return Type of segment
 */
Segment::Type getSegmentType(const ELFIO::segment &seg)
{
	const auto flags = seg.get_flags();
	switch(seg.get_type())
	{
		case PT_PHDR:
		case PT_NOTE:
			return Segment::Type::INFO;
		case PT_INTERP:
		case PT_DYNAMIC:
		case PT_TLS:
			return (flags & PF_W) ? Segment::Type::DATA : Segment::Type::CONST_DATA;
		case PT_LOAD:
			return (flags & PF_X) ? Segment::Type::CODE_DATA : Segment::Type::DATA;
		case PT_NULL:
		case PT_SHLIB:
		default:
			return Segment::Type::UNDEFINED_SEC_SEG;
	}
}

/**
 * Count size of area based on dynamic records
 * @param address Start address of area in @a seg
 * @param seg ELF segment in which the area starts
 * @param table Loaded dynamic records. Based on these records is calculated
 *    size of selected area.
 * @return Size of selected area or @c zero if is unable to determine the size
 */
std::size_t getAreaSize(std::size_t address, const Segment &seg, const DynamicTable &table)
{
	if(address < seg.getAddress() || address - seg.getAddress() > seg.getSizeInFile() ||
		(!seg.getAddress() && !seg.getSizeInFile()))
	{
		return 0;
	}

	std::size_t size = 0;

	for(const auto &item : table)
	{
		if(item.getValue() > address)
		{
			switch(item.getType())
			{
				case DT_NULL:
				case DT_NEEDED:
				case DT_PLTRELSZ:
				case DT_RELASZ:
				case DT_RELAENT:
				case DT_STRSZ:
				case DT_SYMENT:
				case DT_SONAME:
				case DT_RPATH:
				case DT_RELSZ:
				case DT_RELENT:
				case DT_INIT_ARRAYSZ:
				case DT_FINI_ARRAYSZ:
				case DT_RUNPATH:
				case DT_PREINIT_ARRAYSZ:
					break;
				default:
					size = !size ? item.getValue() : std::min(size, static_cast<std::size_t>(item.getValue()));
			}
		}
	}

	return size ? size - address : seg.getSizeInFile() - (address - seg.getAddress());
}

/**
 * Get relocation tables related to the symbol table @a symbolTable
 * @param file Parser of ELF file
 * @param symbolTable ELF symbol table section
 * @param relTables Into this parameter are stored pointers to all relocation
 *    tables which are related to @a symbolTable. If there is no such relocation
 *    table, vector is empty.
 * @param appliesSections Into this parameter are stored pointers to sections
 *    on which relocations are applied. For each table from @a relTables is stored
 *    one pointer on the same vector index. Stored pointer may be @c nullptr.
 *
 * Pointers to relocation tables are dynamically allocated and must be released
 *    (otherwise there is a memory leak). Pointers to applies sections are not
 *    dynamically allocated and cannot be released.
 */
void getRelatedRelocationTables(const ELFIO::elfio *file, const ELFIO::section *symbolTable, std::vector<ELFIO::relocation_section_accessor*> &relTables, std::vector<ELFIO::section*> &appliesSections)
{
	relTables.clear();
	appliesSections.clear();
	if(!file || !symbolTable)
	{
		return;
	}

	for(Elf_Half i = 0, e = file->sections.size(); i < e; ++i)
	{
		section *symTab;
		auto *relSec = file->sections[i];
		if(relSec && (relSec->get_type() == SHT_REL || relSec->get_type() == SHT_RELA) &&
			relSec->get_link() < e && (symTab = file->sections[relSec->get_link()]) &&
			symTab->get_index() == symbolTable->get_index())
		{
			relTables.push_back(new relocation_section_accessor(*file, relSec));
			appliesSections.push_back((relSec->get_info() && relSec->get_info() < e) ? file->sections[relSec->get_info()] : nullptr);
		}
	}
}

/**
 * Fix symbol name
 * @param symbolName Name of symbol
 */
void fixSymbolName(std::string &symbolName)
{
	const auto pos = symbolName.find("@@GLIBC_");
	if(pos && pos != std::string::npos)
	{
		symbolName.erase(pos);
	}
}

/**
 * Create new relocation with given parameters
 * @param name Name of symbol being relocated
 * @param offset Offset of symbol being relocated
 * @param index Symbol index
 * @param address Address of symbol being relocated
 * @param type Type of relocation
 * @param addend Relocation addend
 * @return new relocation
 */
Relocation createRelocation(const std::string &name, std::uint64_t offset, std::uint64_t index,
	std::uint64_t address, std::uint32_t type, std::int64_t addend)
{
	Relocation relocation;

	relocation.setName(name);
	relocation.setLinkToSymbol(index);
	relocation.setAddress(address);
	relocation.setSectionOffset(offset);
	relocation.setAddend(addend);
	relocation.setType(type);

	return relocation;
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToFile Path to input file
 * @param loadFlags Load flags
 */
ElfFormat::ElfFormat(std::string pathToFile, LoadFlags loadFlags) : FileFormat(pathToFile, loadFlags)
{
	initStructures();
}

/**
 * Constructor
 * @param inputStream Representation of input file
 * @param loadFlags Load flags
 */
ElfFormat::ElfFormat(std::istream &inputStream, LoadFlags loadFlags) : FileFormat(inputStream, loadFlags)
{
	initStructures();
}

/**
 * Destructor
 */
ElfFormat::~ElfFormat()
{

}

/**
 * Constructor of RelocationTableInfo
 */
ElfFormat::RelocationTableInfo::RelocationTableInfo() : address(0), size(0), entrySize(0), type(SHT_NULL)
{

}

/**
 * Destructor of RelocationTableInfo
 */
ElfFormat::RelocationTableInfo::~RelocationTableInfo()
{

}

/**
 * Init internal structures
 */
void ElfFormat::initStructures()
{
	elfClass = ELFCLASSNONE;
	if(!(stateIsValid = reader.load(fileStream)))
	{
		return;
	}
	fileFormat = Format::ELF;
	elfClass = reader.get_class();
	loadSections();
	loadSegments();
	if(!getNumberOfSymbolTables() && reader.segments.size() && !isUnknownEndian() &&
		(elfClass == ELFCLASS32 || elfClass == ELFCLASS64))
	{
		writer.create(elfClass, reader.get_encoding());
		writer.set_os_abi(static_cast<unsigned char>(getOsOrAbi()));
		writer.set_type(reader.get_type());
		writer.set_machine(reader.get_machine());
		loadInfoFromDynamicSegment();
	}
	computeSectionTableHashes();
	loadStrings();
	loadNotes(); // must be done after sections and segments
	loadCoreInfo(); // must be done after notes
}

std::size_t ElfFormat::initSectionTableHashOffsets()
{
	switch(getElfClass())
	{
		case ELFCLASS32:
			secHashInfo.emplace_back(16, 8);
			secHashInfo.emplace_back(8, 4);
			break;
		case ELFCLASS64:
			secHashInfo.emplace_back(24, 16);
			secHashInfo.emplace_back(8, 4);
			break;
		default:;
	}

	return secHashInfo.size();
}

/**
 * Load ELF string table to @a writer member of this class
 * @param dynamicSection Section from @a writer which represents ELF dynamic segment
 * @param table Loaded dynamic records from @a dynamicSection
 * @return Pointer to added string table or @c nullptr if string table was not
 *    successfully added to @a writer
 */
ELFIO::section* ElfFormat::addStringTable(ELFIO::section *dynamicSection, const DynamicTable &table)
{
	if(!dynamicSection || dynamicSection->get_type() != SHT_DYNAMIC)
	{
		return nullptr;
	}

	const auto *strAddrRecord = table.getRecordOfType(DT_STRTAB);
	const auto *strSizeRecord = table.getRecordOfType(DT_STRSZ);
	if(!strAddrRecord || !strSizeRecord)
	{
		return nullptr;
	}

	const auto strTabAddr = strAddrRecord->getValue();
	const auto strTabSize = strSizeRecord->getValue();
	const auto *strTabSeg = getSegmentFromAddress(strTabAddr);
	if(!strTabSeg || strTabSeg->getOffset() + (strTabAddr - strTabSeg->getAddress()) + strTabSize > getLoadedFileLength())
	{
		return nullptr;
	}

	auto *stringTable = writer.sections.add("string_" + dynamicSection->get_name());
	stringTable->set_type(SHT_STRTAB);
	stringTable->set_offset(strTabSeg->getOffset() + (strTabAddr - strTabSeg->getAddress()));
	stringTable->set_address(strTabAddr);
	stringTable->set_entry_size(0);
	stringTable->set_addr_align(0);
	stringTable->set_link(0);
	stringTable->set_data(nullptr, 0);
	stringTable->set_size(strTabSize);

	if(strTabSeg->getIndex() < reader.segments.size())
	{
		const auto *seg = reader.segments[strTabSeg->getIndex()];
		if(seg)
		{
			stringTable->set_addr_align(seg->get_align());
			if(strTabSize + (strTabAddr - strTabSeg->getAddress()) <= strTabSeg->getSizeInFile())
			{
				const auto* data = seg->get_data();
				if(data)
				{
					stringTable->set_data(seg->get_data() + (strTabAddr - strTabSeg->getAddress()), strTabSize);
				}
			}
			else if(reader.get_istream())
			{
				stringTable->load(*reader.get_istream(), stringTable->get_offset(), strTabSize);
			}
		}
	}

	dynamicSection->set_link(stringTable->get_index());
	return stringTable;
}

/**
 * Load ELF symbol table to @a writer member of this class
 * @param dynamicSection Section from @a writer which represents ELF dynamic segment
 * @param table Loaded dynamic records from @a dynamicSection
 * @param stringTable String table associated with symbol table
 * @return Pointer to added symbol table or @c nullptr if symbol table was not
 *    successfully added to @a writer
 */
ELFIO::section* ElfFormat::addSymbolTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *stringTable)
{
	if(!dynamicSection || dynamicSection->get_type() != SHT_DYNAMIC || !stringTable)
	{
		return nullptr;
	}

	const auto *symAddrRecord = table.getRecordOfType(DT_SYMTAB);
	const auto *symEntrySizeRecord = table.getRecordOfType(DT_SYMENT);
	if(!symAddrRecord || !symEntrySizeRecord)
	{
		return nullptr;
	}

	const auto symTabAddr = symAddrRecord->getValue();
	const auto *symTabSeg = getSegmentFromAddress(symTabAddr);
	if(!symTabSeg)
	{
		return nullptr;
	}

	const auto symTabSize = getAreaSize(symTabAddr, *symTabSeg, table);
	if(!symTabSize || symTabSeg->getOffset() + (symTabAddr - symTabSeg->getAddress()) + symTabSize > getLoadedFileLength())
	{
		return nullptr;
	}

	auto *symbolTable = writer.sections.add("symbol_" + dynamicSection->get_name());
	symbolTable->set_type(SHT_DYNSYM);
	symbolTable->set_offset(symTabSeg->getOffset() + (symTabAddr - symTabSeg->getAddress()));
	symbolTable->set_address(symTabAddr);
	symbolTable->set_entry_size(symEntrySizeRecord->getValue());
	symbolTable->set_addr_align(0);
	symbolTable->set_link(stringTable->get_index());
	symbolTable->set_data(nullptr, 0);
	symbolTable->set_size(symTabSize);

	if(symTabSeg->getIndex() < reader.segments.size())
	{
		const auto *seg = reader.segments[symTabSeg->getIndex()];
		if(seg)
		{
			symbolTable->set_addr_align(seg->get_align());
			if(seg->get_data() && symTabSize + (symTabAddr - symTabSeg->getAddress()) <= symTabSeg->getSizeInFile())
			{
				symbolTable->set_data(seg->get_data() + (symTabAddr - symTabSeg->getAddress()), static_cast<Elf_Word>(symTabSize));
			}
			else if(reader.get_istream())
			{
				symbolTable->load(*reader.get_istream(), symbolTable->get_offset(), symTabSize);
			}
		}
	}

	return symbolTable;
}

/**
 * Load relocation table (REL or RELA) to @a writer member of this class
 * @param dynamicSection Section from @a writer which represents ELF dynamic segment
 * @param info Information about relocations
 * @param symbolTable Symbol table associated with relocation table
 * @return Pointer to added relocation table or @c nullptr if relocation table
 *    was not successfully added to @a writer
 */
ELFIO::section* ElfFormat::addRelocationTable(ELFIO::section *dynamicSection, const RelocationTableInfo &info, ELFIO::section *symbolTable)
{
	if(!dynamicSection || dynamicSection->get_type() != SHT_DYNAMIC || (info.type != SHT_REL && info.type != SHT_RELA) || !symbolTable)
	{
		return nullptr;
	}

	const auto *relSeg = getSegmentFromAddress(info.address);
	if(!relSeg || !info.size || relSeg->getOffset() + (info.address - relSeg->getAddress()) + info.size > getLoadedFileLength())
	{
		return nullptr;
	}

	auto *relocationTable = writer.sections.add((info.type == SHT_REL ? "rel_" : "rela_") + dynamicSection->get_name());
	relocationTable->set_type(info.type);
	relocationTable->set_offset(relSeg->getOffset() + (info.address - relSeg->getAddress()));
	relocationTable->set_address(info.address);
	relocationTable->set_entry_size(info.entrySize);
	relocationTable->set_addr_align(0);
	relocationTable->set_link(symbolTable->get_index());
	relocationTable->set_data(nullptr, 0);
	relocationTable->set_size(info.size);
	relocationTable->set_info(0);

	if(relSeg->getIndex() < reader.segments.size())
	{
		const auto *seg = reader.segments[relSeg->getIndex()];
		if(seg)
		{
			relocationTable->set_addr_align(seg->get_align());
			if(seg->get_data() && info.size + (info.address - relSeg->getAddress()) <= relSeg->getSizeInFile())
			{
				relocationTable->set_data(seg->get_data() + (info.address - relSeg->getAddress()), info.size);
			}
			else if(reader.get_istream())
			{
				relocationTable->load(*reader.get_istream(), relocationTable->get_offset(), info.size);
			}
		}
	}

	return relocationTable;
}

/**
 * Load REL relocation table to @a writer member of this class
 * @param dynamicSection Section from @a writer which represents ELF dynamic segment
 * @param table Loaded dynamic records from @a dynamicSection
 * @param symbolTable Symbol table associated with relocation table
 * @return Pointer to added relocation table or @c nullptr if relocation table
 *    was not successfully added to @a writer
 */
ELFIO::section* ElfFormat::addRelRelocationTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *symbolTable)
{
	if(!dynamicSection || dynamicSection->get_type() != SHT_DYNAMIC)
	{
		return nullptr;
	}

	const auto *addrRecord = table.getRecordOfType(DT_REL);
	const auto *sizeRecord = table.getRecordOfType(DT_RELSZ);
	const auto *entrySizeRecord = table.getRecordOfType(DT_RELENT);
	if(!addrRecord || !sizeRecord || !entrySizeRecord)
	{
		return nullptr;
	}

	RelocationTableInfo info;
	info.address = addrRecord->getValue();
	info.size = sizeRecord->getValue();
	info.entrySize = entrySizeRecord->getValue();
	info.type = SHT_REL;
	return addRelocationTable(dynamicSection, info, symbolTable);
}

/**
 * Load RELA relocation table to @a writer member of this class
 * @param dynamicSection Section from @a writer which represents ELF dynamic segment
 * @param table Loaded dynamic records from @a dynamicSection
 * @param symbolTable Symbol table associated with relocation table
 * @return Pointer to added relocation table or @c nullptr if relocation table
 *    was not successfully added to @a writer
 */
ELFIO::section* ElfFormat::addRelaRelocationTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *symbolTable)
{
	if(!dynamicSection || dynamicSection->get_type() != SHT_DYNAMIC)
	{
		return nullptr;
	}

	const auto *addrRecord = table.getRecordOfType(DT_RELA);
	const auto *sizeRecord = table.getRecordOfType(DT_RELASZ);
	const auto *entrySizeRecord = table.getRecordOfType(DT_RELAENT);
	if(!addrRecord || !sizeRecord || !entrySizeRecord)
	{
		return nullptr;
	}

	RelocationTableInfo info;
	info.address = addrRecord->getValue();
	info.size = sizeRecord->getValue();
	info.entrySize = entrySizeRecord->getValue();
	info.type = SHT_RELA;
	return addRelocationTable(dynamicSection, info, symbolTable);
}

/**
 * Load ELF global offset table to @a writer member of this class
 * @param dynamicSection Section from @a writer which represents ELF dynamic segment
 * @param table Loaded dynamic records from @a dynamicSection
 * @return Pointer to added table or @c nullptr if table was not successfully added
 *    to @a writer
 */
ELFIO::section* ElfFormat::addGlobalOffsetTable(ELFIO::section *dynamicSection, const DynamicTable &table)
{
	if(!dynamicSection || dynamicSection->get_type() != SHT_DYNAMIC)
	{
		return nullptr;
	}

	const auto addrRecord = table.getRecordOfType(DT_PLTGOT);
	if(!addrRecord)
	{
		return nullptr;
	}

	const auto gotAddr = addrRecord->getValue();
	const auto *gotSeg = getSegmentFromAddress(gotAddr);
	if(!gotSeg || gotAddr - gotSeg->getAddress() > gotSeg->getSizeInFile())
	{
		return nullptr;
	}

	auto *gotTable = writer.sections.add("got_" + dynamicSection->get_name());
	gotTable->set_type(SHT_PROGBITS);
	gotTable->set_flags(SHF_ALLOC + SHF_WRITE);
	gotTable->set_offset(gotSeg->getOffset() + (gotAddr - gotSeg->getAddress()));
	gotTable->set_address(gotAddr);
	gotTable->set_entry_size(0);
	gotTable->set_addr_align(0);
	gotTable->set_link(0);
	gotTable->set_data(nullptr, 0);
	gotTable->set_size(gotSeg->getSizeInFile() - (gotAddr - gotSeg->getAddress()));

	if(gotSeg->getIndex() < reader.segments.size())
	{
		const auto *seg = reader.segments[gotSeg->getIndex()];
		if(seg)
		{
			gotTable->set_addr_align(seg->get_align());
			if(seg->get_data())
			{
				const auto w = std::min<std::size_t>(gotTable->get_size(), seg->get_data_size() - (gotAddr - gotSeg->getAddress()));
				const auto gotSegOffset = gotAddr - gotSeg->getAddress();
				if (seg->get_offset() + gotSegOffset + w > bytes.size())
				{
					return nullptr;
				}
				gotTable->set_data(seg->get_data() + gotSegOffset, static_cast<Elf_Word>(w));
			}
		}
	}

	return gotTable;
}

/**
 * Fix symbol link to section based on processor-specific analysis
 * @param symbolLink Original link to section
 * @param symbolValue Value of symbol
 * @return Fixed link to ELF section
 *
 * All sections must be loaded in member @a sections before invocation of this method
 */
ELFIO::Elf_Half ElfFormat::fixSymbolLink(ELFIO::Elf_Half symbolLink, ELFIO::Elf64_Addr symbolValue)
{
	if(!isMips())
	{
		return symbolLink;
	}

	if(symbolLink == SHN_LOPROC || symbolLink == SHN_LOPROC + 1 || symbolLink == SHN_LOPROC + 2)
	{
		const auto *sec = getSectionFromAddress(symbolValue);
		if(sec)
		{
			return sec->getIndex();
		}
	}

	return symbolLink;
}

/**
 * Get relocation mask for specific type of relocation
 * @param relType Relocation type
 * @param mask Relocation mask
 * @return @c true if mask can be determined, @c false otherwise
 */
bool ElfFormat::getRelocationMask(unsigned relType, std::vector<std::uint8_t> &mask)
{
	std::vector<const std::map<unsigned, const std::vector<std::uint8_t>*>*> maps;

	switch(reader.get_machine())
	{
		case EM_386:
		case EM_486:
			maps.push_back(&x86RelocationMap);
			break;
		case EM_X86_64:
			maps.push_back(&x86_64RelocationMap);
			break;
		case EM_MIPS:
		case EM_MIPS_RS3_LE:
		case EM_MIPS_X:
			maps.push_back(&mipsRelocationMap);
			switch(elfClass)
			{
				case ELFCLASS32:
					maps.push_back(&mips32RelocationMap);
					break;
				case ELFCLASS64:
					maps.push_back(&mips64RelocationMap);
					break;
				default:;
			}
			break;
		case EM_ARM:
			maps.push_back(&arm32RelocationMap);
			break;
		case EM_AARCH64:
			maps.push_back(&arm64RelocationMap);
			break;
		case EM_PPC:
			maps.push_back(&powerpcRelocationMap);
			maps.push_back(&powerpc32RelocationMap);
			break;
		case EM_PPC64:
			maps.push_back(&powerpcRelocationMap);
			maps.push_back(&powerpc64RelocationMap);
			break;
		case EM_NONE:
			if(isWiiPowerPc())
			{
				maps.push_back(&powerpcRelocationMap);
				maps.push_back(&powerpc32RelocationMap);
				break;
			}
			break;
		default:
			return false;
	}

	for(const auto &item : maps)
	{
		auto iter = item->find(relType);
		if(iter != item->end())
		{
			mask = *(iter->second);
			return true;
		}
	}

	unknownRelocs.insert(relType);
	return false;
}

/**
 * Load relocation tables which are related to @a symbolTable section
 * @param file Parser of ELF file
 * @param symbolTable Symbol table section
 * @param nameAddressMap Into this multimap is stored name and address of each stored relocation
 */
void ElfFormat::loadRelocations(const ELFIO::elfio *file, const ELFIO::section *symbolTable, std::unordered_multimap<std::string, unsigned long long> &nameAddressMap)
{
	Relocation relocation;
	std::string relName;
	Elf_Word relType = 0, relSymbol = 0;
	Elf64_Addr relOffset = 0, relValue = 0;
	Elf_Sxword relAddend = 0, relCalcValue = 0;
	std::vector<std::uint8_t> relocationMask;
	std::vector<relocation_section_accessor*> relTables;
	std::vector<section*> appSecs;
	nameAddressMap.clear();
	getRelatedRelocationTables(file, symbolTable, relTables, appSecs);

	for(std::size_t i = 0, addrOffset = 0, e = relTables.size(); i < e; ++i)
	{
		if(!relTables[i])
		{
			continue;
		}
		auto *reltab = new RelocationTable();
		addrOffset = (appSecs[i] && isObjectFile()) ? appSecs[i]->get_offset() - getBaseOffset() : 0;

		for(std::size_t j = 0, f = relTables[i]->get_loaded_entries_num(); j < f; ++j)
		{
			if (isMips() && elfClass == ELFCLASS64)
			{
				Elf_Word index = 0;
				Elf64_Byte value = 0;
				Elf64_Byte type[3] = {0, 0, 0};
				relTables[i]->mips64_get_entry(j, relOffset, index, value, type[2], type[1], type[0], relAddend);

				Elf_Xword size;
				Elf_Half section;
				unsigned char bind, symbolType, other;
				symbol_section_accessor symbols(*file, file->sections[symbolTable->get_index()]);
				symbols.get_symbol(index, relName, relValue, size, bind, symbolType, section, other);

				for (int k = 0; k < 3; ++k)
				{
					if (type[k])
					{
						relocation = createRelocation(relName, relOffset, index, relOffset + addrOffset, type[k], relAddend);
						if(getRelocationMask(type[k], relocationMask))
						{
							relocation.setMask(relocationMask);
						}
						appSecs[i] ? relocation.setLinkToSection(appSecs[i]->get_index()) : relocation.invalidateLinkToSection();
						reltab->addRelocation(relocation);
						nameAddressMap.emplace(relName, relOffset + addrOffset);
					}
				}
			}
			else
			{
				relTables[i]->get_entry(j, relOffset, relValue, relName, relType, relAddend, relCalcValue);
				relocation = createRelocation(relName, relOffset, 0, relOffset + addrOffset, relType, relAddend);
				if(getRelocationMask(relType, relocationMask))
				{
					relocation.setMask(relocationMask);
				}
				appSecs[i] ? relocation.setLinkToSection(appSecs[i]->get_index()) : relocation.invalidateLinkToSection();

				// We need to call this once more because ELFIO does not provide us with symbol index in the previous overload of this method
				relTables[i]->get_entry(j, relOffset, relSymbol, relType, relAddend);
				relocation.setLinkToSymbol(relSymbol);

				reltab->addRelocation(relocation);
				nameAddressMap.emplace(relName, relOffset + addrOffset);
			}
		}

		reltab->setLinkToSymbolTable(symbolTables.size());
		relocationTables.push_back(reltab);
		delete relTables[i];
	}
}

/**
 * Load symbols from symbol table
 * @param file Parser of ELF file
 * @param elfSymbolTable Pointer to symbol table accessor
 * @param section Pointer to symbol table section
 *
 * All sections must be loaded in member @a sections before invocation of this method
 */
void ElfFormat::loadSymbols(const ELFIO::elfio *file, const ELFIO::symbol_section_accessor *elfSymbolTable, const ELFIO::section *section)
{
	if(!file || !elfSymbolTable || !section)
	{
		return;
	}
	if(!exportTable)
	{
		exportTable = new ExportTable();
	}

	auto *symtab = new SymbolTable();
	Export newExport;
	std::string name;
	Elf_Half link = 0;
	Elf_Xword size = 0;
	Elf64_Addr value = 0;
	unsigned char bind = 0, type = 0, other = 0;
	std::unordered_multimap<std::string, unsigned long long> importNameAddressMap;
	loadRelocations(file, section, importNameAddressMap);

	for(std::size_t i = 0, e = elfSymbolTable->get_loaded_symbols_num(); i < e; ++i)
	{
		auto symbol = std::make_shared<ElfSymbol>();
		elfSymbolTable->get_symbol(i, name, value, size, bind, type, link, other);
		size ? symbol->setSize(size) : symbol->invalidateSize();
		symbol->setType(getSymbolType(bind, type, link));
		symbol->setUsageType(getSymbolUsageType(type));
		symbol->setOriginalName(name);
		fixSymbolName(name);
		symbol->setName(name);
		symbol->setIndex(i);
		symbol->setElfType(type);
		symbol->setElfBind(bind);
		symbol->setElfOther(other);
		link = fixSymbolLink(link, value);
		if(link >= file->sections.size() || !file->sections[link] || link == SHN_ABS ||
			link == SHN_COMMON || link == SHN_UNDEF || link == SHN_XINDEX)
		{
			symbol->invalidateLinkToSection();
			symbol->setAddress(value);
			symbol->setIsThumbSymbol(isArm() && value % 2);
			// Ignore first STN_UNDEF STT_NOTYPE symbol when considering imports
			if(link == SHN_UNDEF && i != 0)
			{
				if(!importTable)
				{
					importTable = new ImportTable();
				}
				auto keyIter = importNameAddressMap.equal_range(name);
				// we create std::set from std::multimap values in order to ensure determinism
				std::set<std::pair<std::string, unsigned long long>> addresses(keyIter.first, keyIter.second);
				for(const auto &address : addresses)
				{
					auto import = std::make_unique<Import>();
					import->setName(name);
					import->setAddress(address.second);
					importTable->addImport(std::move(import));
				}
				if(keyIter.first == keyIter.second && getSectionFromAddress(value))
				{
					auto import = std::make_unique<Import>();
					import->setName(name);
					import->setAddress(value);
					importTable->addImport(std::move(import));
				}
			}
		}
		else
		{
			const auto a = isObjectFile() ? value + file->sections[link]->get_address() : value;
			symbol->setLinkToSection(link);
			symbol->setAddress(a);
			symbol->setIsThumbSymbol(isArm() && a % 2);
			if(section->get_type() == SHT_DYNSYM)
			{
				newExport.setAddress(isObjectFile() ? value + file->sections[link]->get_address() : value);
				newExport.setName(name);
				exportTable->addExport(newExport);
			}
		}
		symtab->addSymbol(std::move(symbol));
	}

	symtab->setName(section->get_name());
	if(symtab->hasSymbols())
	{
		symbolTables.push_back(symtab);
	}
	else
	{
		delete symtab;
	}

	loadImpHash();
	loadExpHash();
}

/**
 * Add new symbol table based on existing symbol table and based on global offset table
 * @param oldTab Existing symbol table
 * @param dynTab Loaded dynamic records related to existing symbol table and to global offset table
 * @param got Section from @a writer which represents global offset table
 *
 * This method performs processor-specific analysis of global offset table
 */
void ElfFormat::loadSymbols(const SymbolTable &oldTab, const DynamicTable &dynTab, ELFIO::section &got)
{
	if(!isMips() || isUnknownEndian())
	{
		return;
	}

	got.set_entry_size(getBytesPerWord());
	const auto *gotSymRec = dynTab.getRecordOfType(DT_MIPS_GOTSYM);
	if(!gotSymRec)
	{
		return;
	}

	const std::size_t firstSymbolIndex = gotSymRec->getValue();
	const std::size_t noOfSymbols = oldTab.getNumberOfSymbols();
	if(firstSymbolIndex >= noOfSymbols)
	{
		return;
	}

	const auto *data = got.get_data();
	const std::size_t dataSize = got.get_data_size() - (got.get_data_size() % got.get_entry_size());
	const std::size_t noOfGotSymbols = noOfSymbols - firstSymbolIndex;
	if(!data || !noOfGotSymbols || dataSize < noOfGotSymbols * got.get_entry_size())
	{
		return;
	}

	std::vector<std::size_t> gotValues;

	for(std::size_t i = 0, e = dataSize / got.get_entry_size(); i < e; ++i)
	{
		std::size_t value = 0;

		for(std::size_t j = 0, f = got.get_entry_size(); j < f; ++j)
		{
			const auto index = (isBigEndian() ? i * got.get_entry_size() + j : (i + 1) * got.get_entry_size() - j - 1);
			value += static_cast<unsigned char>(data[index]);
			if(j + 1 < f)
			{
				value <<= getByteLength();
			}
		}

		gotValues.push_back(value);
	}

	unsigned long long addr;
	const auto *firstSym = oldTab.getSymbol(firstSymbolIndex);
	if(!firstSym || !firstSym->getAddress(addr))
	{
		return;
	}

	auto iter = find(gotValues.begin(), gotValues.end(), addr);
	auto *newTab = new SymbolTable();

	for(std::size_t i = firstSymbolIndex, e = noOfSymbols; i < e && iter != gotValues.end(); ++i, ++iter)
	{
		auto *oldSym = static_cast<const ElfSymbol*>(oldTab.getSymbol(i));
		if(!oldSym || !oldSym->getAddress(addr) || addr != *iter)
		{
			continue;
		}

		auto newSym = std::make_shared<ElfSymbol>(*oldSym);
		newSym->setAddress(got.get_address() + got.get_entry_size() * (iter - gotValues.begin()));
		newSym->setSize(got.get_entry_size());
		newSym->setIndex(i - firstSymbolIndex);
		newTab->addSymbol(std::move(newSym));
	}

	newTab->setName(got.get_name());
	if(newTab->hasSymbols())
	{
		symbolTables.push_back(newTab);
	}
	else
	{
		delete newTab;
	}
}

/**
 * Load dynamic table
 * @param table Parameter for store dynamic table
 * @param elfDynamicTable Pointer to dynamic section accessor
 *
 * @a Content of elfDynamicTable is stored into @a table. Previous content
 * of @a table is deleted.
 */
void ElfFormat::loadDynamicTable(DynamicTable &table, const ELFIO::dynamic_section_accessor *elfDynamicTable)
{
	table.clear();
	if(!elfDynamicTable)
	{
		return;
	}

	DynamicEntry entry;
	std::string desc;
	Elf_Xword type = 0, value = 0;

	for(std::size_t i = 0, e = elfDynamicTable->get_loaded_entries_num(); i < e; ++i)
	{
		elfDynamicTable->get_entry(i, type, value, desc);
		entry.setType(type);
		entry.setValue(value);
		entry.setDescription(desc);
		table.addRecord(entry);
		if(type == DT_NULL)
		{
			break;
		}
	}
}

/**
 * Load dynamic table
 * @param elfDynamicTable Pointer to dynamic section accessor
 */
void ElfFormat::loadDynamicTable(const ELFIO::dynamic_section_accessor *elfDynamicTable)
{
	auto *table = new DynamicTable();
	loadDynamicTable(*table, elfDynamicTable);
	dynamicTables.push_back(table);
}

/**
 * Load information about sections
 */
void ElfFormat::loadSections()
{
	const auto noOfSections = reader.sections.size();

	// we must load all sections before invocation of method loadSymbols()
	for(std::size_t i = 0; i < noOfSections; ++i)
	{
		auto *fSec = new ElfSection();
		const auto *sec = reader.sections[i];
		if(!sec)
		{
			delete fSec;
			continue;
		}
		fSec->setName(sec->get_name());
		fSec->setIndex(sec->get_index());
		fSec->setOffset(sec->get_offset());
		fSec->setSizeInFile(sec->get_size());
		fSec->setAddress(sec->get_address());
		fSec->setMemory(isObjectFile() && !sec->get_address() ? sec->get_offset() - getBaseOffset() : sec->get_address());
		fSec->setType(getSectionType(*sec));
		if(sec->get_entry_size())
		{
			fSec->setSizeOfOneEntry(sec->get_entry_size());
		}
		fSec->load(this);
		fSec->setElfType(sec->get_type());
		fSec->setElfAlign(sec->get_addr_align());
		fSec->setElfFlags(sec->get_flags());
		fSec->setElfLink(sec->get_link());
		fSec->setNumberOfSections(noOfSections);
		fSec->setArchByteSize(getBytesPerWord());
		sections.push_back(fSec);
	}

	for(auto i = 0; i < noOfSections; ++i)
	{
		auto *sec = reader.sections[i];
		if(!sec)
		{
			continue;
		}
		switch(sec->get_type())
		{
			case SHT_SYMTAB:
			case SHT_DYNSYM:
			{
				auto sym = symbol_section_accessor(reader, sec);
				loadSymbols(&reader, &sym, sec);
				break;
			}
			case SHT_DYNAMIC:
			{
				auto dyn = dynamic_section_accessor(reader, sec);
				loadDynamicTable(&dyn);
				break;
			}
			default:;
		}
	}
}

/**
 * Load information about segments
 */
void ElfFormat::loadSegments()
{
	for(Elf_Half i = 0, e = reader.segments.size(); i < e; ++i)
	{
		auto *fSeg = new ElfSegment();
		const auto *seg = reader.segments[i];
		if(!seg)
		{
			delete fSeg;
			continue;
		}
		fSeg->setIndex(seg->get_index());
		fSeg->setOffset(seg->get_offset());
		fSeg->setSizeInFile(seg->get_file_size());
		fSeg->setAddress(seg->get_virtual_address());
		fSeg->setMemory(seg->get_virtual_address() || seg->get_type() == PT_LOAD);
		fSeg->setSizeInMemory(seg->get_memory_size());
		fSeg->setType(getSegmentType(*seg));
		fSeg->setElfType(seg->get_type());
		fSeg->setElfFlags(seg->get_flags());
		fSeg->setElfAlign(seg->get_align());
		fSeg->load(this);
		segments.push_back(fSeg);
	}
}

/**
 * Load information from dynamic tables
 * @param noOfTables Number of dynamic tables which have been added to @a writer
 *    member of this class. It is supposed, that each of these tables have been
 *    added as the new section to the end of section list andas the new dynamic
 *    table to the end of dynamic table list.
 */
void ElfFormat::loadInfoFromDynamicTables(std::size_t noOfTables)
{
	const auto noOfWriterSections = writer.sections.size();
	if(!noOfTables || noOfTables > noOfWriterSections || noOfTables > getNumberOfDynamicTables())
	{
		return;
	}

	for(std::size_t i = 0; i < noOfTables; ++i)
	{
		auto *sec = writer.sections[noOfWriterSections - noOfTables + i];
		auto *dynTab = dynamicTables[getNumberOfDynamicTables() - noOfTables + i];
		auto *strTab = addStringTable(sec, *dynTab);
		if(!strTab)
		{
			continue;
		}

		auto *dynAccessor = new dynamic_section_accessor(writer, sec);
		loadDynamicTable(*dynTab, dynAccessor);
		delete dynAccessor;

		auto *symTab = addSymbolTable(sec, *dynTab, strTab);
		if(!symTab)
		{
			continue;
		}

		addRelRelocationTable(sec, *dynTab, symTab);
		addRelaRelocationTable(sec, *dynTab, symTab);
		auto *symAccessor = new symbol_section_accessor(writer, symTab);
		loadSymbols(&writer, symAccessor, symTab);
		delete symAccessor;

		// MIPS specific analysis
		if(isMips() && symbolTables.size())
		{
			auto *got = addGlobalOffsetTable(sec, *dynTab);
			if(got)
			{
				auto *symbols = symbolTables.back();
				loadSymbols(*symbols, *dynTab, *got);
			}
		}
	}
}

/**
 * Load information from dynamic segment
 */
void ElfFormat::loadInfoFromDynamicSegment()
{
	std::size_t noOfDynTables = 0;

	for(std::size_t i = 0, e = reader.segments.size(); i < e; ++i)
	{
		auto *seg = reader.segments[i];
		if(!seg || seg->get_type() != PT_DYNAMIC || !reader.get_istream())
		{
			continue;
		}

		if(seg->get_offset() + seg->get_file_size() > getFileLength())
		{
			continue;
		}

		seg->load(*reader.get_istream(), seg->get_offset(), seg->get_file_size());
		auto *dynamic = writer.sections.add("dynamic_" + numToStr(++noOfDynTables));
		dynamic->set_type(SHT_DYNAMIC);
		dynamic->set_offset(seg->get_offset());
		dynamic->set_address(seg->get_virtual_address());
		dynamic->set_entry_size((reader.get_class() == ELFCLASS32) ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn));
		dynamic->set_addr_align(seg->get_align());
		dynamic->set_link(0);
		dynamic->set_size(seg->get_file_size());
		dynamic->set_data(seg->get_data(), seg->get_file_size());
		auto *accessor = new dynamic_section_accessor(writer, dynamic);
		loadDynamicTable(accessor);
		delete accessor;
	}

	loadInfoFromDynamicTables(noOfDynTables);
}

/**
 * Load notes from PT_NOTE segment or SHT_NOTE section
 * @param notes ElfNotes structure
 */
void ElfFormat::loadNoteSecSeg(ElfNoteSecSeg& notes) const
{
	const std::size_t offset = notes.getSecSegOffset();
	const std::size_t size = notes.getSecSegLength();
	if(!offset || !size)
	{
		return;
	}

	const auto endianess = getEndianness();
	// Specification for 64-bit files claims that entry size should be 8 bytes
	// but every 64-bit ELF file analyzed had only 4 byte long entries.
	const auto entrySize = 4;

	std::size_t currOff = offset;
	std::size_t maxOff = offset + size;
	while(currOff < maxOff)
	{
		std::uint64_t nameSize = 0;
		if(!getXByteOffset(currOff, entrySize, nameSize, endianess))
		{
			notes.setMalformed("could not read note owner size");
			break;
		}
		currOff += entrySize;

		std::uint64_t descSize = 0;
		if(!getXByteOffset(currOff, entrySize, descSize, endianess))
		{
			notes.setMalformed("could not read note description size");
			break;
		}
		currOff += entrySize;

		// Get note type
		std::uint64_t type = 0;
		if(!getXByteOffset(currOff, entrySize, type, endianess))
		{
			notes.setMalformed("could not read note type");
			break;
		}
		currOff += entrySize;

		if(currOff + nameSize > maxOff)
		{
			notes.setMalformed("note owner size too big");
			break;
		}

		// Get owner name stored as C string
		std::string name;
		if(!getString(name, currOff, nameSize))
		{
			break;
		}

		// Move offset behind name - aligned to entry size
		auto mod = nameSize % entrySize;
		currOff += nameSize + (mod ? entrySize - mod : 0);

		if(currOff + descSize > maxOff)
		{
			notes.setMalformed("note data size too big");
			break;
		}

		ElfNoteEntry note;
		note.dataOffset = currOff;
		note.dataLength = descSize;

		// Move offset behind description - aligned to entry size
		mod = descSize % entrySize;
		currOff += descSize + (mod ? entrySize - mod : 0);

		note.name = name.c_str(); // Trims trailing zero if present
		note.type = type;
		notes.addNote(note);
	}
}

/**
 * Load notes from ELF note sections or segments
 */
void ElfFormat::loadNotes()
{
	// Check sections first as they contain more information
	for(const Section* sec : sections)
	{
		auto section = static_cast<const ElfSection*>(sec);
		// For some reason Android uses SHT_PROGBITS for notes
		if(section->getElfType() == SHT_NOTE
				|| section->getName() == ".note.android.ident")
		{
			ElfNoteSecSeg res(section);
			loadNoteSecSeg(res);
			if(!res.isEmpty())
			{
				noteSecSegs.emplace_back(std::move(res));
			}
		}
	}

	// Go to segments only if there are no sections or no information was
	// loaded because SHT_NOTE sections must overlap with PT_NOTE segments
	if(!noteSecSegs.empty())
	{
		return;
	}

	// Check segments - kernel core dumps do not create sections
	for(const Segment* seg : segments)
	{
		auto segment = static_cast<const ElfSegment*>(seg);
		if(segment->getElfType() == PT_NOTE)
		{
			ElfNoteSecSeg res(segment);
			loadNoteSecSeg(res);
			if(!res.isEmpty())
			{
				noteSecSegs.emplace_back(std::move(res));
			}
		}
	}
}

/**
 * Load file map from core file
 * @param offset offset off NT_FILE note data
 * @param size size of NT_FILE note data
 *
 * This function expects only data from non-malformed notes to avoid multiple
 * offset sanity checks. Make sure this is not used with malformed notes!
 */
void ElfFormat::loadCoreFileMap(std::size_t offset, std::size_t size)
{
	const auto endianness = getEndianness();
	// As I have only two 32-bit MIPS samples from lldb test repository,
	// this MIPS condition may be wrong.
	const auto entrySize = isMips() ? 8 : elfClass == ELFCLASS32 ? 4 : 8;

	std::size_t currOff = offset;
	std::size_t maxOff = offset + size;

	if(currOff + 2 * entrySize > maxOff)
	{
		return;
	}

	std::uint64_t count;
	getXByteOffset(currOff, entrySize, count, endianness);
	currOff += entrySize;

	std::uint64_t pageSize;
	getXByteOffset(currOff, entrySize, pageSize, endianness);
	currOff += entrySize;

	// We will use this to extract strings so we have to retype to signed type
	const char* data = reinterpret_cast<const char*>(getLoadedBytes().data());
	std::size_t pathOff = currOff + 3 * entrySize * count;

	for(std::size_t i = 0; i < count; ++i)
	{
		if(pathOff > maxOff)
		{
			return;
		}

		FileMapEntry entry;
		getXByteOffset(currOff, entrySize, entry.startAddr, endianness);
		currOff += entrySize;
		getXByteOffset(currOff, entrySize, entry.endAddr, endianness);
		currOff += entrySize;
		getXByteOffset(currOff, entrySize, entry.pageOffset, endianness);
		currOff += entrySize;

		// Paths are stored as zero delimited strings after address table
		entry.filePath = data + pathOff;
		pathOff += entry.filePath.size() + 1;

		elfCoreInfo->addFileMapEntry(entry);
	}
}

/**
 * Load prstatus info struct from core file
 * @param offset offset off NT_PRSTATUS note data
 * @param size size of NT_PRSTATUS note data
 *
 * This function expects only data from non-malformed notes to avoid multiple
 * offset sanity checks. Make sure this is not used with malformed notes!
 */
void ElfFormat::loadCorePrStat(std::size_t offset, std::size_t size)
{
	PrStatusInfo info;
	const auto endianness = getEndianness();

	// Skip to pid and ppid value
	std::size_t currOff = offset + (elfClass == ELFCLASS32 ? 0x18 : 0x20);
	std::size_t maxOff = offset + size;
	if(currOff + 8 > maxOff)
	{
		return;
	}

	// Load process IDs
	get4ByteOffset(currOff, info.pid, endianness);
	get4ByteOffset(currOff + 4, info.ppid, endianness);

	// Skip to GP registers (offsets are from start)
	currOff = offset + (elfClass == ELFCLASS32 ? 0x48 : 0x70);

	// Get register characteristics for specific architecture
	std::size_t regSize = elfClass == ELFCLASS32 ? 4 : 8;
	std::vector<std::string> regNames;
	switch(getTargetArchitecture())
	{
		// Order of registers must agree with arch. specific prstatus struct
		case Architecture::X86:
			regNames = x86Regs;
			break;

		case Architecture::X86_64:
			regNames = x64Regs;
			break;

		case Architecture::ARM:
			regNames = elfClass == ELFCLASS32 ? armRegs : aarch64Regs;
			break;

		case Architecture::POWERPC:
			// Names should be same for both 32 and 64 bit PowerPC
			regNames = ppcRegs;
			break;

		case Architecture::MIPS:
			// I did not manage to find register descriptions for MIPS

		case Architecture::UNKNOWN:
			/* fall-thru */

		default:
			return;
	}

	if(currOff + regNames.size() * regSize > maxOff)
	{
		return;
	}

	// Load registers for process
	std::uint64_t value = 0;
	for(const auto& name : regNames)
	{
		getXByteOffset(currOff, regSize, value, endianness);
		currOff += regSize;
		info.registers.emplace(name, value);
	}

	// Store process info
	elfCoreInfo->addPrStatusInfo(info);
}

/**
 * Load prpsinfo info struct from core file
 * @param offset offset off NT_PRPSINFO note data
 * @param size size of NT_PRPSINFO note data
 *
 * This function expects only data from non-malformed notes to avoid multiple
 * offset sanity checks. Make sure this is not used with malformed notes!
 */
void ElfFormat::loadCorePrPsInfo(std::size_t offset, std::size_t size)
{
	std::size_t currOff = offset + (elfClass == ELFCLASS32 ? 0x1c : 0x28);
	if(currOff + 16 + 80 < offset + size)
	{
		return;
	}

	std::string res;
	getString(res, currOff, 16);
	elfCoreInfo->setAppName(res.c_str());

	getString(res, currOff + 16, 80);
	elfCoreInfo->setCmdLine(res.c_str());
}

/**
 * Load info from auxiliary vector
 * @param offset offset off NT_AUXV note data
 * @param size size of NT_AUXV note data
 *
 * This function expects only data from non-malformed notes to avoid multiple
 * offset sanity checks. Make sure this is not used with malformed notes!
 */
void ElfFormat::loadCoreAuxvInfo(std::size_t offset, std::size_t size)
{
	const auto endianness = getEndianness();
	const auto entrySize = elfClass == ELFCLASS32 ? 4 : 8;

	std::size_t maxOff = offset + size;
	while(offset < maxOff)
	{
		AuxVectorEntry entry;
		getXByteOffset(offset, entrySize, entry.first, endianness);
		offset += entrySize;
		getXByteOffset(offset, entrySize, entry.second, endianness);
		offset += entrySize;

		elfCoreInfo->addAuxVectorEntry(entry);
	}
}

/**
 * Load information from core files that we can read
 */
void ElfFormat::loadCoreInfo()
{
	elfCoreInfo = new ElfCoreInfo;
	if(!elfCoreInfo)
	{
		return;
	}

	for(const auto& noteSeg : noteSecSegs)
	{
		if(noteSeg.isMalformed())
		{
			continue;
		}

		for(const ElfNoteEntry& entry : noteSeg.getNotes())
		{
			if(entry.name == "CORE")
			{
				switch(entry.type)
				{
					case NT_FILE:
						loadCoreFileMap(entry.dataOffset, entry.dataLength);
						break;

					case NT_PRSTATUS:
						loadCorePrStat(entry.dataOffset, entry.dataLength);
						break;

					case NT_PRPSINFO:
						loadCorePrPsInfo(entry.dataOffset, entry.dataLength);
						break;

					case NT_AUXV:
						loadCoreAuxvInfo(entry.dataOffset, entry.dataLength);
						break;

					default:
						break;
				}
			}
		}
	}

	//elfCoreInfo->dump(std::cout); // Debug output
}

retdec::utils::Endianness ElfFormat::getEndianness() const
{
	switch(reader.get_encoding())
	{
		case ELFDATA2LSB:
			return Endianness::LITTLE;
		case ELFDATA2MSB:
			return Endianness::BIG;
		default:
			return Endianness::UNKNOWN;
	}
}

std::size_t ElfFormat::getBytesPerWord() const
{
	switch(reader.get_machine())
	{
		// Architecture::X86
		case EM_386:
		case EM_486:
			return 4;

		// Architecture::X86_64
		case EM_X86_64:
			return 8;

		// Architecture::MIPS
		case EM_MIPS:
		case EM_MIPS_RS3_LE:
		case EM_MIPS_X:
			return (elfClass == ELFCLASS64) ? 8 : 4;

		// Architecture::ARM
		case EM_ARM:
			return 4;
		case EM_AARCH64:
			return 8;

		// Architecture::POWERPC
		case EM_PPC:
			return 4;
		case EM_PPC64:
			return 8;
		case EM_NONE:
			return isWiiPowerPc() ? 4 : 0;

		// unsupported architecture
		default:
			return 0;
	}
}

bool ElfFormat::hasMixedEndianForDouble() const
{
	unsigned long long abiVersion = 0;
	bool hasAbi = getAbiVersion(abiVersion);
	return isArm() && (!hasAbi || abiVersion < 5);
}

/**
 * Get declared length of file. This length may be shorter or longer than real length of file.
 * @return Declared length of file
 */
std::size_t ElfFormat::getDeclaredFileLength() const
{
	const std::size_t tablesMax = std::max(getSectionTableOffset() + getSectionTableSize(), getSegmentTableOffset() + getSegmentTableSize());
	return std::max(tablesMax, FileFormat::getDeclaredFileLength());
}

bool ElfFormat::areSectionsValid() const
{
	return FileFormat::areSectionsValid() && reader.sections.size() && reader.sections[0] && reader.sections[0]->get_type() == SHT_NULL;
}

bool ElfFormat::isObjectFile() const
{
	return reader.get_type() == ET_REL;
}

bool ElfFormat::isDll() const
{
	return reader.get_type() == ET_DYN;
}

bool ElfFormat::isExecutable() const
{
	return reader.get_type() == ET_EXEC;
}

bool ElfFormat::getMachineCode(unsigned long long &result) const
{
	result = reader.get_machine();
	return true;
}

bool ElfFormat::getAbiVersion(unsigned long long &result) const
{
	// this works only for 32-bit ARM
	if(!isArm() || getWordLength() != 32)
	{
		return false;
	}

	const auto abi = (getFileFlags() & EF_ARM_ABIMASK) >> 24;
	if(abi)
	{
		result = abi;
	}

	return abi;
}

bool ElfFormat::getImageBaseAddress(unsigned long long &imageBase) const
{
	// not in ELF files
	static_cast<void>(imageBase);
	return false;
}

bool ElfFormat::getEpAddress(unsigned long long &result) const
{
	const unsigned long long epAddress = reader.get_entry();
	if(epAddress)
	{
		result = epAddress;
		return true;
	}
	else if(!isArm() || isObjectFile())
	{
		return false;
	}

	for(const auto *item : segments)
	{
		unsigned long long size;
		if(!item->getSizeInMemory(size))
		{
			size = item->getSizeInFile();
		}

		if(epAddress >= item->getAddress() && epAddress - item->getAddress() < size && item->getOffset())
		{
			result = epAddress;
			return true;
		}
	}

	return false;
}

bool ElfFormat::getEpOffset(unsigned long long &epOffset) const
{
	unsigned long long epRva;
	if(!getEpAddress(epRva))
	{
		return false;
	}

	for(const auto *item : segments)
	{
		unsigned long long size;
		if(!item->getSizeInMemory(size))
		{
			size = item->getSizeInFile();
		}

		if(epRva >= item->getAddress() && epRva - item->getAddress() < size)
		{
			epOffset = item->getOffset() + (epRva - item->getAddress());
			return true;
		}
	}

	for(const auto *item : sections)
	{
		unsigned long long size;
		if(!item->getSizeInMemory(size))
		{
			size = item->getSizeInFile();
		}

		unsigned long long address = item->getAddress();
		if(isObjectFile() && !address)
		{
			address = item->getOffset() - getBaseOffset();
		}

		if(item->getMemory() && epRva >= address && epRva - address < size)
		{
			epOffset = item->getOffset() + (epRva - address);
			return true;
		}
	}

	return false;
}

Architecture ElfFormat::getTargetArchitecture() const
{
	switch(reader.get_machine())
	{
		case EM_386:
		case EM_486:
			return Architecture::X86;
		case EM_X86_64:
			return Architecture::X86_64;
		case EM_MIPS:
		case EM_MIPS_RS3_LE:
		case EM_MIPS_X:
			return Architecture::MIPS;
		case EM_ARM:
		case EM_AARCH64:
			return Architecture::ARM;
		case EM_PPC:
		case EM_PPC64:
			return Architecture::POWERPC;
		case EM_NONE:
			return isWiiPowerPc() ? Architecture::POWERPC : Architecture::UNKNOWN;
		default:
			return Architecture::UNKNOWN;
	}
}

std::size_t ElfFormat::getDeclaredNumberOfSections() const
{
	return reader.get_sections_num();
}

std::size_t ElfFormat::getDeclaredNumberOfSegments() const
{
	return reader.get_segments_num();
}

std::size_t ElfFormat::getSectionTableOffset() const
{
	return reader.get_sections_offset();
}

std::size_t ElfFormat::getSectionTableEntrySize() const
{
	return reader.get_section_entry_size();
}

std::size_t ElfFormat::getSegmentTableOffset() const
{
	return reader.get_segments_offset();
}

std::size_t ElfFormat::getSegmentTableEntrySize() const
{
	return reader.get_segment_entry_size();
}

/**
 * Get type of file
 * @return Type of file (e_type item from ELF header)
 */
std::size_t ElfFormat::getTypeOfFile() const
{
	return reader.get_type();
}

/**
 * Get file version
 * @return File version (e_version item from ELF header)
 */
std::size_t ElfFormat::getFileVersion() const
{
	return reader.get_version();
}

/**
 * Get version of file header
 * @return Version of file header (EI_VERSION item from ELF header)
 */
std::size_t ElfFormat::getFileHeaderVersion() const
{
	return reader.get_elf_version();
}

/**
 * Get size of file header
 * @return Size of file header (e_ehsize item from ELF header)
 */
std::size_t ElfFormat::getFileHeaderSize() const
{
	return reader.get_header_size();
}

/**
 * Get file flags
 * @return File flags (e_flags item from ELF header)
 */
std::size_t ElfFormat::getFileFlags() const
{
	return reader.get_flags();
}

/**
 * Get operating system or ABI associated with file
 * @return Operating system or ABI associated with file
 */
std::size_t ElfFormat::getOsOrAbi() const
{
	return reader.get_os_abi();
}

/**
 * Get ABI version
 * @return ABI version
 *
 * This information is taken from ELF header
 */
std::size_t ElfFormat::getOsOrAbiVersion() const
{
	return reader.get_abi_version();
}

/**
 * Get size of section table
 * @return Size of section table
 */
std::size_t ElfFormat::getSectionTableSize() const
{
	return reader.sections.size() * reader.get_section_entry_size();
}

/**
 * Get size of segment table
 * @return Size of segment table
 */
std::size_t ElfFormat::getSegmentTableSize() const
{
	return reader.segments.size() * reader.get_segment_entry_size();
}

/**
 * Get class of ELF file
 * @return ELFIO::ELFCLASS32 if file is 32-bit ELF file, ELFIO::ELFCLASS64 if file is
 *    64-bit ELF file or any other value otherwise
 */
int ElfFormat::getElfClass() const
{
	return elfClass;
}

/**
 * Return @c true, if target architecture of input file is PowerPC processor for Wii platform
 */
bool ElfFormat::isWiiPowerPc() const
{
	const auto *sec1 = getSection(".PPC.EMB.apuinfo");
	const auto *sec2 = getSection(".init");
	if(!sec1 || !sec2)
	{
		return false;
	}

	const auto bytes = sec2->getBytes();
	return !bytes.find("Metrowerks Target Resident Kernel for PowerPC");
}

/**
 * Returns the base offset of the executable/relocatable file. Base address is always 0 for executable files.
 * For relocatable files, it is offset of the minimum SHF_ALLOC or SHT_PROGBITS/SHT_NOBITS section if no SHF_ALLOC section was found.
 * If no such section is found, it is 0.
 */
unsigned long long ElfFormat::getBaseOffset() const
{
	if(!isObjectFile())
	{
		return 0;
	}

	unsigned long long minOffset = std::numeric_limits<unsigned long long>::max();
	for(const auto& sec : sections)
	{
		const ElfSection* elfSec = static_cast<const ElfSection*>(sec);
		if(elfSec->getElfFlags() & SHF_ALLOC)
		{
			if(elfSec->getOffset() < minOffset)
			{
				minOffset = elfSec->getOffset();
			}
		}
	}

	if(minOffset != std::numeric_limits<unsigned long long>::max())
	{
		return minOffset;
	}

	for(const auto& sec : sections)
	{
		const ElfSection* elfSec = static_cast<const ElfSection*>(sec);
		if(elfSec->getElfType() == SHT_PROGBITS || elfSec->getElfType() == SHT_NOBITS)
		{
			if(elfSec->getOffset() < minOffset)
			{
				minOffset = elfSec->getOffset();
			}
		}
	}

	return minOffset == std::numeric_limits<unsigned long long>::max() ? 0 : minOffset;
}

} // namespace fileformat
} // namespace retdec
