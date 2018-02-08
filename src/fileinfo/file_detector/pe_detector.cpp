/**
 * @file src/fileinfo/file_detector/pe_detector.cpp
 * @brief Methods of PeDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/utils/array.h"
#include "retdec/utils/time.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_detector/pe_detector.h"

using namespace retdec::utils;
using namespace PeLib;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const unsigned long long PE_COFF_HEADER_SIZE = 20;
const unsigned long long PE_SECTION_TABLE_ENTRY_SIZE = 40;
const unsigned long long PE_16_FLAGS_SIZE = 16;

} // anonymous namespace

/**
 * Constructor
 * @param pathToInputFile Path to input file
 * @param finfo Instance of class for storing information about file
 * @param searchPar Parameters for detection of used compiler (or packer)
 * @param loadFlags Load flags
 */
PeDetector::PeDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags) :
	FileDetector(pathToInputFile, finfo, searchPar, loadFlags)
{
	fileParser = peParser = std::make_shared<PeWrapper>(fileInfo.getPathToFile(), loadFlags);
	loaded = peParser->isInValidState();
}

/**
 * Destructor
 */
PeDetector::~PeDetector()
{

}

/**
 * Get file flags
 */
void PeDetector::getFileFlags()
{
	const unsigned long long flags = peParser->getFileFlags();
	fileInfo.setFileFlagsSize(PE_16_FLAGS_SIZE);
	fileInfo.setFileFlags(flags);
	const unsigned long long flagMasks[] = {PELIB_IMAGE_FILE_RELOCS_STRIPPED,
											PELIB_IMAGE_FILE_EXECUTABLE_IMAGE,
											PELIB_IMAGE_FILE_LINE_NUMS_STRIPPED,
											PELIB_IMAGE_FILE_LOCAL_SYMS_STRIPPED,
											PELIB_IMAGE_FILE_AGGRESSIVE_WS_TRIM,
											PELIB_IMAGE_FILE_LARGE_ADDRESS_AWARE,
											PELIB_IMAGE_FILE_BYTES_REVERSED_LO | PELIB_IMAGE_FILE_BYTES_REVERSED_HI,
											PELIB_IMAGE_FILE_32BIT_MACHINE,
											PELIB_IMAGE_FILE_DEBUG_STRIPPED,
											PELIB_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
											PELIB_IMAGE_FILE_NET_RUN_FROM_SWAP,
											PELIB_IMAGE_FILE_SYSTEM,
											PELIB_IMAGE_FILE_DLL,
											PELIB_IMAGE_FILE_UP_SYSTEM_ONLY};
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
 * Get DLL flags
 */
void PeDetector::getDllFlags()
{
	unsigned long long flags;
	if(!peParser->getDllFlags(flags))
	{
		return;
	}
	fileInfo.setDllFlagsSize(PE_16_FLAGS_SIZE);
	fileInfo.setDllFlags(flags);
	const unsigned long long flagMasks[] = {PELIB_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
											PELIB_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
											PELIB_IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
											PELIB_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
											PELIB_IMAGE_DLLCHARACTERISTICS_NO_SEH,
											PELIB_IMAGE_DLLCHARACTERISTICS_NO_BIND,
											PELIB_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
											PELIB_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE};
	const unsigned long long flagsSize = arraySize(flagMasks);
	const std::string flagsDesc[flagsSize] = {"DLL can be relocated at load time",
											"code integrity checks are enforced",
											"image is NX compatible",
											"isolation aware, but do not isolate the image",
											"does not use structured exception handling",
											"do not bind the image",
											"WDM driver",
											"terminal server aware"};
	const std::string flagsAbbv[flagsSize] = {"r", "c", "n", "i", "e", "b", "w", "t"};
	for(unsigned long long i = 0; i < flagsSize; ++i)
	{
		if(flags & flagMasks[i])
		{
			fileInfo.addDllFlagsDescriptor(flagsDesc[i], flagsAbbv[i]);
		}
	}
}

/**
 * Get information from file headers
 */
void PeDetector::getHeaderInfo()
{
	fileInfo.setFileStatus(peParser->getPeType());
	fileInfo.setCoffFileHeaderSize(PE_COFF_HEADER_SIZE);
	fileInfo.setOptionalHeaderSize(peParser->getOptionalHeaderSize());
	fileInfo.setChecksum(peParser->getChecksum());
	fileInfo.setStackReserveSize(peParser->getSizeOfStackReserve());
	fileInfo.setStackCommitSize(peParser->getSizeOfStackCommit());
	fileInfo.setHeapReserveSize(peParser->getSizeOfHeapReserve());
	fileInfo.setHeapCommitSize(peParser->getSizeOfHeapCommit());
	fileInfo.setTimeStamp(timestampToDate(static_cast<std::time_t>(peParser->getTimeStamp())));
	getFileFlags();
	getDllFlags();
}

/**
 * Get symbols from COFF symbol table
 */
void PeDetector::getCoffSymbols()
{
	const auto offset = peParser->getCoffSymbolTableOffset();
	if(!offset)
	{
		return;
	}
	SymbolTable symbolTable;
	symbolTable.setTableOffset(offset);
	symbolTable.setNumberOfDeclaredSymbols(peParser->getNumberOfCoffSymbols());
	Symbol symbol;

	for(unsigned long long i = 0; peParser->getCoffSymbol(i, symbol); ++i)
	{
		symbolTable.addSymbol(symbol);
	}

	fileInfo.addSymbolTable(symbolTable);
}

/**
 * Get information about relocation table
 */
void PeDetector::getRelocationTableInfo()
{
	unsigned long long relocs = 0;
	if(peParser->getNumberOfRelocations(relocs))
	{
		RelocationTable relTable;
		relTable.setNumberOfDeclaredRelocations(relocs);
		fileInfo.addRelocationTable(relTable);
	}
}

/**
 * Get information about data directories
 */
void PeDetector::getDirectories()
{
	fileInfo.setNumberOfDeclaredDataDirectories(peParser->getDeclaredNumberOfDataDirectories());
	DataDirectory dir;

	for(unsigned long long i = 0, e = peParser->getNumberOfDataDirectories(); i < e; ++i)
	{
		if(peParser->getDataDirectory(i, dir))
		{
			fileInfo.addDataDirectory(dir);
		}
	}
}

/**
 * Get information about sections
 */
void PeDetector::getSections()
{
	const unsigned long long storedSections = peParser->getNumberOfSections();
	const unsigned long long declSections = peParser->getDeclaredNumberOfSections();
	fileInfo.setNumberOfDeclaredSections(declSections);
	fileInfo.setSectionTableEntrySize(PE_SECTION_TABLE_ENTRY_SIZE);
	fileInfo.setSectionTableSize(declSections * PE_SECTION_TABLE_ENTRY_SIZE);

	const unsigned long long flagMasks[] = {PELIB_IMAGE_SCN_TYPE_NO_PAD,
											PELIB_IMAGE_SCN_CNT_CODE,
											PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA,
											PELIB_IMAGE_SCN_CNT_UNINITIALIZED_DATA,
											PELIB_IMAGE_SCN_LNK_OTHER,
											PELIB_IMAGE_SCN_NO_DEFER_SPEC_EXC,
											PELIB_IMAGE_SCN_GPREL,
											PELIB_IMAGE_SCN_MEM_PURGEABLE,
											PELIB_IMAGE_SCN_MEM_LOCKED,
											PELIB_IMAGE_SCN_MEM_PRELOAD,
											PELIB_IMAGE_SCN_LNK_NRELOC_OVFL,
											PELIB_IMAGE_SCN_MEM_DISCARDABLE,
											PELIB_IMAGE_SCN_MEM_NOT_CACHED,
											PELIB_IMAGE_SCN_MEM_NOT_PAGED,
											PELIB_IMAGE_SCN_MEM_SHARED,
											PELIB_IMAGE_SCN_MEM_EXECUTE,
											PELIB_IMAGE_SCN_MEM_READ,
											PELIB_IMAGE_SCN_MEM_WRITE};
	const unsigned long long flagsSize = arraySize(flagMasks);
	unsigned long long flags;
	std::string purgeableDesc, purgeableAbbv;
	if(peParser->isArm())
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
	const std::string flagsAbbv[flagsSize] = {"b", "E", "i", "u", "l", "t", "g", purgeableAbbv, "L",
											"P", "R", "d", "c", "p", "s", "x", "r", "w"};
	FileSection fs;

	for(unsigned long long i = 0; i < storedSections; ++i)
	{
		if(!peParser->getFileSection(i, fs))
		{
			continue;
		}
		flags = fs.getFlags();
		for(unsigned long long j = 0; j < flagsSize; ++j)
		{
			if(flags & flagMasks[j])
			{
				fs.addFlagsDescriptor(flagsDesc[j], flagsAbbv[j]);
			}
		}
		fileInfo.addSection(fs);
	}
}

/**
 * Get information about .NET
 */
void PeDetector::getDotnetInfo()
{
	if (!peParser->isDotNet())
	{
		return;
	}

	fileInfo.setDotnetUsed(true);
	if (auto clrHeader = peParser->getCLRHeader())
	{
		fileInfo.setDotnetRuntimeVersion(clrHeader->getMajorRuntimeVersion(), clrHeader->getMinorRuntimeVersion());
	}
	if (auto metadataHeader = peParser->getMetadataHeader())
	{
		fileInfo.setDotnetMetadataHeaderAddress(metadataHeader->getAddress());
	}
	if (auto metadataStream = peParser->getMetadataStream())
	{
		fileInfo.setDotnetMetadataStreamInfo(metadataStream->getOffset(), metadataStream->getSize());
	}
	if (auto stringStream = peParser->getStringStream())
	{
		fileInfo.setDotnetStringStreamInfo(stringStream->getOffset(), stringStream->getSize());
	}
	if (auto blobStream = peParser->getBlobStream())
	{
		fileInfo.setDotnetBlobStreamInfo(blobStream->getOffset(), blobStream->getSize());
	}
	if (auto guidStream = peParser->getGuidStream())
	{
		fileInfo.setDotnetGuidStreamInfo(guidStream->getOffset(), guidStream->getSize());
	}
	if (auto userStringStream = peParser->getUserStringStream())
	{
		fileInfo.setDotnetUserStringStreamInfo(userStringStream->getOffset(), userStringStream->getSize());
	}
	fileInfo.setDotnetModuleVersionId(peParser->getModuleVersionId());
	fileInfo.setDotnetTypeLibId(peParser->getTypeLibId());
	fileInfo.setDotnetDefinedClassList(peParser->getDefinedDotnetClasses());
	fileInfo.setDotnetImportedClassList(peParser->getImportedDotnetClasses());
}

void PeDetector::detectFileClass()
{
	switch(peParser->getPeClass())
	{
		case PEFILE32:
			fileInfo.setFileClass("32-bit");
			break;
		case PEFILE64:
			fileInfo.setFileClass("64-bit");
			break;
		default:;
	}
}

void PeDetector::detectArchitecture()
{
	unsigned long long machineType = 0;
	if(!peParser->getMachineCode(machineType))
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

void PeDetector::detectFileType()
{
	fileInfo.setFileType(peParser->getTypeOfFile());
}

void PeDetector::getAdditionalInfo()
{
	getHeaderInfo();
	getDirectories();
	getSections();
	getCoffSymbols();
	getRelocationTableInfo();
	getDotnetInfo();

	/* In future we can detect more information about PE files:
		- TimeDateStamp
		- MajorLinkerVersion
		- MinorLinkerVersion
		- SizeOfCode
		- SizeOfInitializedData
		- SizeOfUninitializedData
		- BaseOfCode
		- BaseOfData
		- SectionAlignment
		- FileAlignment
		- MajorOperatingSystemVersion
		- MinorOperatingSystemVersion
		- MajorImageVersion
		- MinorImageVersion
		- MajorSubsystemVersion
		- MinorSubsystemVersion
		- Win32VersionValue
		- SizeOfImage
		- SizeOfHeaders
		- Subsystem
		- LoaderFlags
	*/
}

/**
 * Pointer to detector is dynamically allocated and must be released (otherwise there is a memory leak)
 * More detailed description of this method is in the super class
 */
retdec::cpdetect::CompilerDetector* PeDetector::createCompilerDetector() const
{
	return new PeCompiler(*peParser, cpParams, fileInfo.toolInfo);
}

} // namespace fileinfo
