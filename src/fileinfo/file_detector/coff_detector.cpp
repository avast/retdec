/**
 * @file src/fileinfo/file_detector/coff_detector.cpp
 * @brief Methods of CoffDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include <pelib/PeLibInc.h>

#include "retdec/utils/array.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_detector/coff_detector.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::COFF;
using namespace PeLib;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

namespace {

const unsigned long long COFF_HEADER_SIZE = 20;
const unsigned long long COFF_SECTION_TABLE_ENTRY_SIZE = 40;
const unsigned long long COFF_16_FLAGS_SIZE = 16;

/**
 * Get link to symbol section
 * @param link Link to section in number representation
 * @return Link to section in string representation
 */
std::string getSymbolLinkToSection(std::int16_t link)
{
	if(!link)
	{
		return "UNDEFINED";
	}
	else if(link == IMAGE_SYM_ABSOLUTE)
	{
		return "ABSOLUTE";
	}
	else if(link == IMAGE_SYM_DEBUG)
	{
		return "DEBUG";
	}

	return numToStr(link - 1);
}

/**
 * Get type of symbol
 * @param type Type of symbol in number representation
 * @return Type of symbol in string representation
 */
std::string getSymbolType(std::uint8_t type)
{
	if(type == IMAGE_SYM_DTYPE_NULL)
	{
		return "SIMPLE";
	}
	else if(type == IMAGE_SYM_DTYPE_POINTER)
	{
		return "POINTER";
	}
	else if(type == IMAGE_SYM_DTYPE_FUNCTION)
	{
		return "FUNCTION";
	}
	else if(type == IMAGE_SYM_DTYPE_ARRAY)
	{
		return "ARRAY";
	}

	return "";
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToInputFile Path to input file
 * @param finfo Instance of class for storing information about file
 * @param searchPar Parameters for detection of used compiler (or packer)
 * @param loadFlags Load flags
 */
CoffDetector::CoffDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags) :
	FileDetector(pathToInputFile, finfo, searchPar, loadFlags)
{
	fileParser = coffParser = std::make_shared<CoffWrapper>(fileInfo.getPathToFile(), loadFlags);
	loaded = coffParser->isInValidState();
}

/**
 * Destructor
 */
CoffDetector::~CoffDetector()
{

}

/**
 * Get file flags
 */
void CoffDetector::getFileFlags()
{
	const auto flags = coffParser->getFileFlags();
	fileInfo.setFileFlagsSize(COFF_16_FLAGS_SIZE);
	fileInfo.setFileFlags(flags);
	const unsigned long long flagMasks[] = {IMAGE_FILE_RELOCS_STRIPPED,
											IMAGE_FILE_EXECUTABLE_IMAGE,
											IMAGE_FILE_LINE_NUMS_STRIPPED,
											IMAGE_FILE_LOCAL_SYMS_STRIPPED,
											IMAGE_FILE_AGGRESSIVE_WS_TRIM,
											IMAGE_FILE_LARGE_ADDRESS_AWARE,
											IMAGE_FILE_BYTES_REVERSED_LO | IMAGE_FILE_BYTES_REVERSED_HI,
											IMAGE_FILE_32BIT_MACHINE,
											IMAGE_FILE_DEBUG_STRIPPED,
											IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
											IMAGE_FILE_NET_RUN_FROM_SWAP,
											IMAGE_FILE_SYSTEM,
											IMAGE_FILE_DLL,
											IMAGE_FILE_UP_SYSTEM_ONLY};
	const unsigned long long flagsSize = arraySize(flagMasks);
	const std::string flagsDesc[flagsSize] = {"relocation information was stripped",
											"valid executable file",
											"COFF line numbers were stripped",
											"COFF symbol table entries were stripped",
											"aggressively trim working set",
											"application can handle addresses larger than 2 GB",
											"reversed endianness",
											"computer supports 32-bit words",
											"debugging information was removed",
											"copy image from removable media",
											"copy image from network",
											"system file",
											"dynamic-link library",
											"file should be run only on a uniprocessor machine"};
	const std::string flagsAbbv[flagsSize] = {"r", "v", "l", "s", "a", "2", "e", "3", "d", "R", "N", "S", "D", "1"};
	for(unsigned long long i = 0; i < flagsSize; ++i)
	{
		if(flags & flagMasks[i])
		{
			fileInfo.addFileFlagsDescriptor(flagsDesc[i], flagsAbbv[i]);
		}
	}
}

/**
 * Get information from file headers
 */
void CoffDetector::getHeaderInfo()
{
	fileInfo.setCoffFileHeaderSize(COFF_HEADER_SIZE);
	getFileFlags();
}

/**
 * Get symbols from COFF symbol table
 */
void CoffDetector::getCoffSymbols()
{
	const auto *parser = coffParser->getCoffParser();
	if(!parser)
	{
		return;
	}

	const auto offset = coffParser->getCoffSymbolTableOffset();
	if(!offset)
	{
		return;
	}

	SymbolTable symbolTable;
	symbolTable.setTableOffset(offset);
	symbolTable.setNumberOfDeclaredSymbols(coffParser->getNumberOfCoffSymbols());
	Symbol symbol;
	std::size_t index = 0;

	for(const auto &item : parser->symbols())
	{
		const auto symbolRef = parser->getCOFFSymbol(item);
		StringRef name;
		if(parser->getSymbolName(symbolRef, name))
		{
			name = "";
		}
		symbol.setName(name);
		symbol.setIndex(index);
		symbol.setValue(symbolRef.getValue());
		symbol.setLinkToSection(getSymbolLinkToSection(symbolRef.getSectionNumber()));
		symbol.setType(getSymbolType(symbolRef.getComplexType()));
		symbolTable.addSymbol(symbol);
		index += symbolRef.getNumberOfAuxSymbols() + 1;
	}

	fileInfo.addSymbolTable(symbolTable);
}

/**
 * Get relocations from COFF relocation table
 */
void CoffDetector::getCoffRelocations()
{
	const auto* symbolTable = coffParser->getSymbolTable(0);
	for(const auto* rt : coffParser->getRelocationTables())
	{
		RelocationTable relTable;
		relTable.setNumberOfDeclaredRelocations(rt->getNumberOfRelocations());

		for(std::size_t i = 0; i < rt->getNumberOfRelocations(); ++i)
		{
			const auto* r = rt->getRelocation(i);
			Relocation rel;
			rel.setOffset(r->getSectionOffset());
			rel.setRelocationType(r->getType());
			rel.setAddend(r->getAddend());

			unsigned long long symbolIndex;
			if(r->getLinkToSymbol(symbolIndex))
			{
				const auto* symbol = symbolTable ? symbolTable->getSymbolWithIndex(symbolIndex) : nullptr;
				rel.setSymbolName(symbol ? symbol->getName() : "");
			}
			else
			{
				rel.setSymbolName("");
			}

			relTable.addRelocation(rel);
		}

		fileInfo.addRelocationTable(relTable);
	}
}

/**
 * Get information about sections
 */
void CoffDetector::getSections()
{
	const auto *parser = coffParser->getCoffParser();
	if(!parser)
	{
		return;
	}

	const auto declSections = coffParser->getDeclaredNumberOfSections();
	fileInfo.setNumberOfDeclaredSections(declSections);
	fileInfo.setSectionTableEntrySize(COFF_SECTION_TABLE_ENTRY_SIZE);
	fileInfo.setSectionTableSize(declSections * COFF_SECTION_TABLE_ENTRY_SIZE);

	const unsigned long long flagMasks[] = {IMAGE_SCN_TYPE_NO_PAD,
											IMAGE_SCN_CNT_CODE,
											IMAGE_SCN_CNT_INITIALIZED_DATA,
											IMAGE_SCN_CNT_UNINITIALIZED_DATA,
											IMAGE_SCN_LNK_OTHER,
											IMAGE_SCN_LNK_INFO,
											IMAGE_SCN_LNK_REMOVE,
											IMAGE_SCN_LNK_COMDAT,
											0x4000,
											IMAGE_SCN_GPREL,
											IMAGE_SCN_MEM_PURGEABLE,
											IMAGE_SCN_MEM_LOCKED,
											IMAGE_SCN_MEM_PRELOAD,
											IMAGE_SCN_LNK_NRELOC_OVFL,
											IMAGE_SCN_MEM_DISCARDABLE,
											IMAGE_SCN_MEM_NOT_CACHED,
											IMAGE_SCN_MEM_NOT_PAGED,
											IMAGE_SCN_MEM_SHARED,
											IMAGE_SCN_MEM_EXECUTE,
											IMAGE_SCN_MEM_READ,
											IMAGE_SCN_MEM_WRITE};
	const auto flagsSize = arraySize(flagMasks);
	std::string purgeableDesc, purgeableAbbv;
	if(coffParser->isArm())
	{
		purgeableDesc = "section contains Thumb code";
		purgeableAbbv = "T";
	}
	else
	{
		purgeableDesc = "IMAGE_SCN_MEM_PURGEABLE";
		purgeableAbbv = "a";
	}
	const std::string flagsDesc[flagsSize] = {"section should not be padded to the next boundary",
											"section contains executable code",
											"section contains initialized data",
											"section contains uninitialized data",
											"IMAGE_SCN_LNK_OTHER",
											"section contains comments or other information",
											"section will not become part of executable file",
											"section contains COMDAT data",
											"reset speculative exceptions handling bits in the TLB entries for this section",
											"section contains data referenced through the global pointer",
											purgeableDesc,
											"IMAGE_SCN_MEM_LOCKED",
											"IMAGE_SCN_MEM_PRELOAD",
											"section contains extended relocations",
											"section can be discarded as needed",
											"section cannot be cached",
											"section cannot be paged",
											"section can be shared in memory",
											"section can be executed as code",
											"section can be read",
											"section can be written to"};
	const std::string flagsAbbv[flagsSize] = {"b", "E", "i", "u", "l", "C", "D", "o",
											"t", "g", purgeableAbbv, "L", "P", "R",
											"d", "c", "p", "s", "x", "r", "w"};
	const unsigned long long sectionFlagsSize = 32;
	std::size_t index = 0;

	for(const auto &item : parser->sections())
	{
		StringRef name;
		if(item.getName(name))
		{
			name = "";
		}
		FileSection fs;
		fs.setName(name);
		fs.setIndex(index);
		const auto *sect = parser->getCOFFSection(item);
		if(sect)
		{
			fs.setStartAddress(sect->VirtualAddress);
			fs.setSizeInMemory(sect->VirtualSize);
			fs.setOffset(sect->PointerToRawData);
			fs.setSizeInFile(sect->SizeOfRawData);
			fs.setRelocationsOffset(sect->PointerToRelocations);
			fs.setNumberOfRelocations(sect->NumberOfRelocations);
			fs.setLineNumbersOffset(sect->PointerToLinenumbers);
			fs.setNumberOfLineNumbers(sect->NumberOfLinenumbers);
			fs.setFlagsSize(sectionFlagsSize);
			fs.setFlags(sect->Characteristics);
			fs.clearFlagsDescriptors();
			const auto flags = fs.getFlags();

			for(unsigned long long j = 0; j < flagsSize; ++j)
			{
				if(flags & flagMasks[j])
				{
					fs.addFlagsDescriptor(flagsDesc[j], flagsAbbv[j]);
				}
			}
		}
		const auto *auxSect = coffParser->getSection(index);
		if(auxSect)
		{
			fs.setCrc32(auxSect->getCrc32());
			fs.setMd5(auxSect->getMd5());
			fs.setSha256(auxSect->getSha256());
		}

		fileInfo.addSection(fs);
		++index;
	}
}

void CoffDetector::detectFileClass()
{
	if(coffParser->is32BitArchitecture())
	{
		fileInfo.setFileClass("32-bit");
	}
	else
	{
		fileInfo.setFileClass("64-bit");
	}
}

void CoffDetector::detectArchitecture()
{
	unsigned long long machineType = 0;
	if(!coffParser->getMachineCode(machineType))
	{
		return;
	}
	std::string result;

	switch(machineType)
	{
		// x86/x64/ia64-based
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
			result = "x86";
			break;
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
			result = "x86-64";
			break;
		case PELIB_IMAGE_FILE_MACHINE_IA64:
			result = "IA-64 (Intel Itanium)";
			break;

		// MIPS
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
			result = "MIPS (R3000 - big endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
			result = "MIPS (R3000 - little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_R4000:
			result = "MIPS (R4000 - little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_R10000:
			result = "MIPS (R10000 - little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
			result = "MIPS (WCE MIPSv2 - little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
			result = "MIPS16";
			break;
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
			result = "MIPS (MIPSIV - MIPS with FPU)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
			result = "MIPS16 with FPU";
			break;

		// ARM
		case PELIB_IMAGE_FILE_MACHINE_ARM:
			result = "ARM (little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
			// "ARM or THUMB (interworking)";
			result = "ARM";
			break;
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
			// "ARM (ARMv7 or higher) THUMB mode only";
			result = "ARM (ARMv7 or higher)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
			result = "ARM (ARMv8 64-bit mode)";
			break;

		// Hitachi
		case PELIB_IMAGE_FILE_MACHINE_SH3:
			result = "Hitachi SH3";
			break;
		case PELIB_IMAGE_FILE_MACHINE_SH3DSP:
			result = "Hitachi SH3 DSP";
			break;
		case PELIB_IMAGE_FILE_MACHINE_SH3E:
			result = "Hitachi SH3E";
			break;
		case PELIB_IMAGE_FILE_MACHINE_SH4:
			result = "Hitachi SH4";
			break;
		case PELIB_IMAGE_FILE_MACHINE_SH5:
			result = "Hitachi SH5";
			break;

		// Power PC
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
			result = "PowerPC (little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			result = "PowerPC with FPU";
			break;

		// Alpha
		case PELIB_IMAGE_FILE_MACHINE_ALPHA:
			result = "ALPHA";
			break;
		case PELIB_IMAGE_FILE_MACHINE_ALPHA64:
			result = "ALPHA64";
			break;

		// Other
		case PELIB_IMAGE_FILE_MACHINE_MOTOROLA68000:
			result = "Motorola 68000";
			break;
		case PELIB_IMAGE_FILE_MACHINE_PARISC:
			result = "Hewlett-Packard PA-RISC";
			break;
		case PELIB_IMAGE_FILE_MACHINE_AM33:
			result = "Matsushita AM33";
			break;
		case PELIB_IMAGE_FILE_MACHINE_EBC:
			result = "EFI byte code";
			break;
		case PELIB_IMAGE_FILE_MACHINE_MSIL:
			result = "MSIL - Microsoft Intermediate Language (aka CIL - Common Intermediate Language)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_M32R:
			result = "Mitsubishi M32R (little endian)";
			break;
		case PELIB_IMAGE_FILE_MACHINE_TRICORE:
			result = "Siemens TriCore";
			break;
		case PELIB_IMAGE_FILE_MACHINE_UNKNOWN:
		default:
			std::stringstream sstm;
			sstm << "Unknown machine type (" << machineType << ")";
			result = sstm.str();
	}
	fileInfo.setTargetArchitecture(result);
}

void CoffDetector::detectFileType()
{
	fileInfo.setFileType(coffParser->getTypeOfFile());
}

void CoffDetector::getAdditionalInfo()
{
	getHeaderInfo();
	getSections();
	getCoffSymbols();
	getCoffRelocations();
}

/**
 * Pointer to detector is dynamically allocated and must be released (otherwise there is a memory leak)
 * More detailed description of this method is in the super class
 */
retdec::cpdetect::CompilerDetector* CoffDetector::createCompilerDetector() const
{
	return new CoffCompiler(*coffParser, cpParams, fileInfo.toolInfo);
}

} // namespace fileinfo
