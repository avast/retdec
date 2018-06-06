/**
 * @file src/fileinfo/file_detector/macho_detector.cpp
 * @brief Methods of MachODetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/utils/array.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_detector/macho_detector.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::object;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param pathToInputFile Path to input file
 * @param finfo Instance of class for storing information about file
 * @param searchPar Parameters for detection of used compiler (or packer)
 * @param loadFlags Load flags
 */
MachODetector::MachODetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags) :
	FileDetector(pathToInputFile, finfo, searchPar, loadFlags)
{
	fileParser = machoParser = std::make_shared<MachOWrapper>(fileInfo.getPathToFile(), loadFlags);
	loaded = machoParser->isInValidState();
}

/**
 * Destructor
 */
MachODetector::~MachODetector()
{

}

/**
 * Get entry point info
 */
void MachODetector::getEntryPoint()
{
	unsigned long long res = 0;
	if(fileParser->getEpAddress(res))
	{
		fileInfo.toolInfo.epAddress = res;
		fileInfo.toolInfo.entryPointAddress = true;

		for(auto sec : fileParser->getSections())
		{
			if(sec->getAddress() <= res && res < sec->getEndAddress())
			{
				fileInfo.toolInfo.epSection = *sec;
				fileInfo.toolInfo.entryPointSection = true;
			}
		}
	}
	if(fileParser->getEpOffset(res))
	{
		fileInfo.toolInfo.epOffset = res;
		fileInfo.toolInfo.entryPointOffset = true;
	}
}

/**
 * Get segments info
 */
void MachODetector::getSegments()
{
	unsigned long long res = machoParser->getDeclaredNumberOfSegments();
	fileInfo.setNumberOfDeclaredSegments(res);
	FileSegment fseg;

	for(auto seg : fileParser->getSegments())
	{
		/// @todo add segment name, type and flags, memory protection
		fseg.setIndex(seg->getIndex());
		fseg.setOffset(seg->getOffset());
		fseg.setVirtualAddress(seg->getAddress());
		fseg.setSizeInFile(seg->getSizeInFile());
		if(seg->getSizeInMemory(res))
		{
			fseg.setSizeInMemory(res);
		}
		fileInfo.addSegment(fseg);
	}
}

/**
 * Get information about sections
 */
void MachODetector::getSections()
{
	unsigned long long res = machoParser->getDeclaredNumberOfSections();
	fileInfo.setNumberOfDeclaredSections(res);
	FileSection fsec;

	for(auto sec : fileParser->getSections())
	{
		/// @todo add section type, flags, reserved1/reserved2
		fsec.setName(sec->getName());
		fsec.setIndex(sec->getIndex());
		fsec.setOffset(sec->getOffset());
		fsec.setSizeInFile(sec->getSizeInFile());
		fsec.setStartAddress(sec->getAddress());
		if(sec->getSizeInMemory(res))
		{
			fsec.setSizeInMemory(res);
		}
		MachOSection *mSec = static_cast<MachOSection*>(sec);
		fsec.setMemoryAlignment(pow(2, mSec->getAlignment()));
		fsec.setRelocationsOffset(mSec->getRelocationOffset());
		fsec.setNumberOfRelocations(mSec->getNumberOfRelocations());
		fileInfo.addSection(fsec);
	}
}

/**
 * Get information about symbols
 */
void MachODetector::getSymbols()
{
	SymbolTable symbolTable;
	Symbol symbol;

	/// @todo table offset, number of symbols
	// symbolTable.setTableOffset();
	// symbolTable.setNumberOfDeclaredSymbols();

	for(auto tabPtr : machoParser->getSymbolTables())
	{
		symbolTable.clearSymbols();

		for(const auto& symPtr : *tabPtr)
		{
			symbol.setName(symPtr->getName());
			symbol.setIndex(symPtr->getIndex());

			unsigned long long result = 0;
			if(symPtr->getAddress(result))
			{
				symbol.setAddress(result);
			}
			if(symPtr->getSize(result))
			{
				symbol.setSize(result);
			}
			if(symPtr->getLinkToSection(result))
			{
				symbol.setLinkToSection(std::to_string(result));
			}
			if(symPtr->isThumbSymbol())
			{
				symbol.setOther("THUMB");
			}

			/// @todo value, type, bind, flags
			// symbol.setType();
			// symbol.setBind();
			// symbol.setValue();

			symbolTable.addSymbol(symbol);
		}

		fileInfo.addSymbolTable(symbolTable);
	}
}

/**
 * Get information about encrypted files
 */
void MachODetector::getEncryption()
{
	unsigned long offset = 0, size = 0, id = 0;
	if(machoParser->getEncryptionInfo(offset, size, id))
	{
		std::stringstream message;
		message << "Warning: This file is encrypted (encryption algorithm: " << id
			<< ", offset: " << numToStr(offset, hexWithPrefix)
			<< ", size: " << numToStr(size, hexWithPrefix) << ").";
		fileInfo.messages.push_back(message.str());
	}
}

/**
 * Get information about operating system
 */
void MachODetector::getOsInfo()
{
	std::string name, version;
	if(machoParser->getTargetOs(name, version))
	{
		fileInfo.setOsAbi(name);
		fileInfo.setOsAbiVersion(version);
	}
}

/**
 * Get relocation tables and relocations
 */
void MachODetector::getRelocations()
{
	const auto* symbolTable = machoParser->getSymbolTable(0);
	for(const auto* tabPtr : machoParser->getRelocationTables())
	{
		RelocationTable relTable;
		relTable.setNumberOfDeclaredRelocations(tabPtr->getNumberOfRelocations());

		for(std::size_t i = 0; i < tabPtr->getNumberOfRelocations(); ++i)
		{
			const auto* r = tabPtr->getRelocation(i);
			Relocation relocation;
			relocation.setRelocationType(r->getType());
			relocation.setOffset(r->getSectionOffset());

			unsigned long long symbolIndex;
			if(r->getLinkToSymbol(symbolIndex))
			{
				const auto* symbol = symbolTable ? symbolTable->getSymbolWithIndex(symbolIndex) : nullptr;
				relocation.setSymbolName(symbol ? symbol->getName() : "");
			}
			else
			{
				relocation.setSymbolName("");
			}

			relTable.addRelocation(relocation);
		}

		fileInfo.addRelocationTable(relTable);
	}
}

void MachODetector::detectFileClass()
{
	fileInfo.setFileFormat(machoParser->getFileFormatName());
	if(machoParser->isFatBinary())
	{
		fileInfo.messages.push_back("Warning: Information about symbols, sections etc. is shown for just one architecture.");
	}
	if(machoParser->is32Bit())
	{
		fileInfo.setFileClass("32-bit");
	}
	else
	{
		fileInfo.setFileClass("64-bit");
	}
}

void MachODetector::detectArchitecture()
{
	unsigned long long machineType = 0;
	if(!machoParser->getMachineCode(machineType))
	{
		return;
	}
	std::string result;

	switch(machineType)
	{
		case MachO::CPU_TYPE_X86:
			result = "x86";
			break;

		case MachO::CPU_TYPE_X86_64:
			result = "x86-64";
			break;
		case MachO::CPU_TYPE_MC98000:
		case MachO::CPU_TYPE_POWERPC:
			machoParser->isLittleEndian() ? result = "PowerPC (little endian)" : result = "PowerPC (big endian)";
			break;
		case MachO::CPU_TYPE_POWERPC64:
			machoParser->isLittleEndian() ? result = "PowerPC (little endian, 64-bit mode)" : result = "PowerPC (big endian, 64-bit mode)";
			break;
		case MachO::CPU_TYPE_ARM:
			machoParser->isLittleEndian() ? result = "ARM (little endian)" : result = "ARM (big endian)";
			break;
		case MachO::CPU_TYPE_ARM64:
			machoParser->isLittleEndian() ? result = "ARM (little endian, 64-bit mode)" : result = "ARM (big endian, 64-bit mode)";
			break;
		case MachO::CPU_TYPE_SPARC:
			if(machoParser->is32Bit())
			{
				machoParser->isLittleEndian() ? result = "SPARC (little endian)" : result = "SPARC (big endian)";
				break;
			}
			else
			{
				machoParser->isLittleEndian() ? result = "SPARC (little endian, 64-bit mode)" : result = "SPARC (big endian, 64-bit mode)";
				break;
			}

		// TODO: fatal error: case value evaluates to -1, which cannot be
		// narrowed to type 'unsigned long long' [-Wc++11-narrowing]
		// case MachO::CPU_TYPE_ANY:
		default:
			std::stringstream sstm;
			sstm << "Unknown machine type (" << machineType << ")";
			result = sstm.str();
	}
	fileInfo.setTargetArchitecture(result);
}

void MachODetector::detectFileType()
{
	fileInfo.setFileType(machoParser->getTypeOfFile());
}

void MachODetector::getAdditionalInfo()
{
	getEntryPoint();
	getSegments();
	getSections();
	getSymbols();
	getEncryption();
	getOsInfo();
	getRelocations();
}

/**
 * Pointer to detector is dynamically allocated and must be released (otherwise there is a memory leak)
 * More detailed description of this method is in the super class
 */
retdec::cpdetect::CompilerDetector* MachODetector::createCompilerDetector() const
{
	return new MachOCompiler(*machoParser, cpParams, fileInfo.toolInfo);
}

/**
 * Check if file is Mach-O Universal Binary archive
 * @return @c true if file is Mach-O fat archive, @c false otherwise
 */
bool MachODetector::isMachoUniversalArchive()
{
	return machoParser->isStaticLibrary();
}

} // namespace fileinfo
