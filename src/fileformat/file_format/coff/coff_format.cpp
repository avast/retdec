/**
 * @file src/fileformat/file_format/coff/coff_format.cpp
 * @brief Definition of CoffFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdint>
#include <system_error>

#include <pelib/PeLibInc.h>

#include "retdec/utils/string.h"
#include "retdec/fileformat/file_format/coff/coff_format.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::COFF;
using namespace llvm::object;
using namespace PeLib;

namespace retdec {
namespace fileformat {

namespace
{

// Relocation masks are stored as vectors of bytes.
// Relocation maps store pointers to these vectors.

// All relocations are stored as little endian.
// Trailing 0x00 bytes are necessary for byte endianness swapping.

// Relocation ALL_NONE represents COPY/NONE relocations (no bits are changed).
// We do not use empty vector, that is reserved for unknown relocations.
const std::vector<std::uint8_t> ALL_NONE = {0x00};

// Full byte aligned types common for all architectures.
const std::vector<std::uint8_t> ALL_BYTE = {0xFF};
const std::vector<std::uint8_t> ALL_WORD = {0xFF, 0xFF};
const std::vector<std::uint8_t> ALL_DWORD = {0xFF, 0xFF, 0xFF, 0xFF};
const std::vector<std::uint8_t> ALL_QWORD = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Masks for x86 architecture.
// Source: Visual Studio, Microsoft Portable Executable and Common Object File Format Specification.
const std::map<unsigned, const std::vector<std::uint8_t>*> x86RelocationMap =
{
	{0x00, &ALL_NONE},
	{0x01, &ALL_DWORD},
	{0x02, &ALL_DWORD},
	{0x06, &ALL_DWORD},
	{0x07, &ALL_DWORD},
	{0x09, &ALL_DWORD},
	{0x0A, &ALL_WORD},
	{0x0B, &ALL_DWORD},
	{0x0C, &ALL_DWORD},
	{0x0D, &ALL_BYTE},
	{0x14, &ALL_DWORD}
};

// Masks for x64 architecture.
// Source: Visual Studio, Microsoft Portable Executable and Common Object File Format Specification.
const std::map<unsigned, const std::vector<std::uint8_t>*> x64RelocationMap =
{
	{0x00, &ALL_NONE},
	{0x01, &ALL_QWORD},
	{0x02, &ALL_DWORD},
	{0x03, &ALL_DWORD},
	{0x04, &ALL_DWORD},
	{0x05, &ALL_DWORD},
	{0x06, &ALL_DWORD},
	{0x07, &ALL_DWORD},
	{0x08, &ALL_DWORD},
	{0x09, &ALL_DWORD},
	{0x0A, &ALL_WORD},
	{0x0B, &ALL_DWORD},
	{0x0C, &ALL_BYTE},
	{0x0D, &ALL_DWORD},
	{0x0E, &ALL_DWORD},
	{0x0F, &ALL_NONE},
	{0x10, &ALL_DWORD}
};

// Masks for ARM 32 architecture.
// Source: Visual Studio, Microsoft Portable Executable and Common Object File Format Specification.
const std::map<unsigned, const std::vector<std::uint8_t>*> arm32RelocationMap =
{
	{0x00, &ALL_NONE},
	{0x01, &ALL_DWORD},
	{0x02, &ALL_DWORD},
	{0x03, &ALL_DWORD},
	{0x04, &ALL_DWORD},
	// Relococation 0x05 is not defined in docs but used in some objects.
	{0x05, &ALL_DWORD},
	// Relocations from 0x05 to 0x0D are undefined.
	{0x0E, &ALL_WORD},
	{0x0F, &ALL_DWORD},
	{0x10, &ALL_DWORD},
	{0x11, &ALL_DWORD},
	{0x12, &ALL_DWORD},
	// Relocation 0x13 is unused.
	{0x14, &ALL_DWORD},
	{0x15, &ALL_DWORD},
	{0x16, &ALL_NONE}
};

// Masks for ARM 64 architecture.
// Source: Visual Studio, Microsoft Portable Executable and Common Object File Format Specification.
const std::map<unsigned, const std::vector<std::uint8_t>*> arm64RelocationMap =
{
	{0x00, &ALL_NONE},
	{0x01, &ALL_DWORD},
	{0x02, &ALL_DWORD},
	{0x03, &ALL_DWORD},
	{0x04, &ALL_DWORD},
	{0x05, &ALL_DWORD},
	{0x06, &ALL_DWORD},
	{0x07, &ALL_DWORD},
	{0x08, &ALL_DWORD},
	{0x09, &ALL_DWORD},
	{0x0A, &ALL_DWORD},
	{0x0B, &ALL_DWORD},
	{0x0C, &ALL_DWORD},
	{0x0D, &ALL_WORD},
	{0x0E, &ALL_QWORD},
	{0x0F, &ALL_DWORD},
	{0x10, &ALL_DWORD},
};

/**
 * Get type of section
 * @param secName Name of section
 * @param secFlags Flags of section
 * @return Type of COFF section
 */
PeCoffSection::Type getSectionType(const std::string &secName, unsigned long long secFlags)
{
	if(secFlags & IMAGE_SCN_CNT_CODE || secFlags & IMAGE_SCN_MEM_EXECUTE)
	{
		return PeCoffSection::Type::CODE;
	}
	else if(secFlags & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
	{
		return PeCoffSection::Type::BSS;
	}
	else if(secFlags & IMAGE_SCN_MEM_DISCARDABLE && startsWith(secName, ".debug"))
	{
		return PeCoffSection::Type::DEBUG;
	}
	else if(secFlags & IMAGE_SCN_CNT_INITIALIZED_DATA)
	{
		return (!(secFlags & IMAGE_SCN_MEM_WRITE)) ? PeCoffSection::Type::CONST_DATA : PeCoffSection::Type::DATA;
	}
	else if(secFlags & IMAGE_SCN_LNK_INFO)
	{
		return PeCoffSection::Type::INFO;
	}

	return PeCoffSection::Type::UNDEFINED_SEC_SEG;
}

/**
 * Get type of symbol
 * @param link Link to COFF section
 * @param value COFF symbol value
 * @param storageClass COFF symbol storage class
 * @return Type of symbol
 */
Symbol::Type getSymbolType(std::int16_t link, std::uint32_t value, std::uint8_t storageClass)
{
	if(!link)
	{
		return value ? Symbol::Type::COMMON : Symbol::Type::EXTERN;
	}
	else if(link == IMAGE_SYM_ABSOLUTE || link == IMAGE_SYM_DEBUG)
	{
		return Symbol::Type::ABSOLUTE_SYM;
	}
	else if(storageClass == IMAGE_SYM_CLASS_EXTERNAL)
	{
		return Symbol::Type::PUBLIC;
	}
	else if(storageClass == IMAGE_SYM_CLASS_STATIC)
	{
		return Symbol::Type::PRIVATE;
	}

	return Symbol::Type::UNDEFINED_SYM;
}

/**
 * Get usage type of symbol
 * @param storageClass COFF symbol storage class
 * @param complexType COFF symbol complex type
 * @return Usage type of symbol
 */
Symbol::UsageType getSymbolUsageType(std::uint8_t storageClass, std::uint8_t complexType)
{
	if(complexType == IMAGE_SYM_DTYPE_FUNCTION)
	{
		return Symbol::UsageType::FUNCTION;
	}
	else if(storageClass == IMAGE_SYM_CLASS_FILE)
	{
		return Symbol::UsageType::FILE;
	}

	return Symbol::UsageType::UNKNOWN;
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToFile Path to input file
 * @param loadFlags Load flags
 */
CoffFormat::CoffFormat(std::string pathToFile, LoadFlags loadFlags) : FileFormat(pathToFile, loadFlags), fileBuffer(MemoryBuffer::getFile(Twine(pathToFile)))
{
	initStructures();
}

/**
 * Destructor
 */
CoffFormat::~CoffFormat()
{
	delete file;
}

/**
 * Init internal structures
 */
void CoffFormat::initStructures()
{
	file = nullptr;
	if(fileBuffer && !fileBuffer.getError())
	{
		std::error_code errorCode;
		file = new COFFObjectFile(fileBuffer.get()->getMemBufferRef(), errorCode);
		stateIsValid = !errorCode;
	}
	else
	{
		stateIsValid = false;
	}

	if(stateIsValid)
	{
		fileFormat = Format::COFF;
		loadSections();
		loadSymbols();
		loadRelocations();
		computeSectionTableHashes();
		loadStrings();
	}
}

std::size_t CoffFormat::initSectionTableHashOffsets()
{
	secHashInfo.emplace_back(20, 4);
	secHashInfo.emplace_back(16, 4);
	secHashInfo.emplace_back(36, 4);
	return secHashInfo.size();
}

/**
 * Load information about sections
 */
void CoffFormat::loadSections()
{
	std::size_t index = 0;
	std::vector<Section*> sectionsForLoad;

	for(const auto &item : file->sections())
	{
		auto *section = new PeCoffSection();
		const auto *coffSec = file->getCOFFSection(item);
		StringRef name;
		if(item.getName(name))
		{
			name = "";
		}
		section->setName(name);
		section->setIndex(index++);
		if(coffSec)
		{
			section->setType(getSectionType(name, coffSec->Characteristics));
			section->setOffset(coffSec->PointerToRawData);
			section->setSizeInFile(coffSec->SizeOfRawData);
			section->setSizeInMemory(coffSec->VirtualSize);
			section->setAddress(coffSec->VirtualAddress);
			section->setMemory(coffSec->VirtualAddress);
			section->setPeCoffFlags(coffSec->Characteristics);
		}
		sections.push_back(section);
		if(section->getSizeInFile() && section->getOffset() < getLoadedFileLength())
		{
			section->load(this);
		}
	}
}

/**
 * Load information about symbols
 */
void CoffFormat::loadSymbols()
{
	auto *table = new SymbolTable();
	std::size_t index = 0;

	for(const auto &item : file->symbols())
	{
		auto symbol = std::make_shared<Symbol>();
		const auto symbolRef = file->getCOFFSymbol(item);
		StringRef name;
		if(file->getSymbolName(symbolRef, name))
		{
			name = "";
		}
		const auto link = symbolRef.getSectionNumber();
		if(!link || link == IMAGE_SYM_ABSOLUTE || link == IMAGE_SYM_DEBUG)
		{
			symbol->invalidateLinkToSection();
			symbol->invalidateAddress();
		}
		else
		{
			symbol->setLinkToSection(link - 1);
			if((static_cast<std::size_t>(link) & 0xFFFF) <= getNumberOfSections() && sections[link - 1])
			{
				const auto a = sections[link - 1]->getAddress() + symbolRef.getValue();
				symbol->setAddress(a);
				symbol->setIsThumbSymbol(isArm() && a % 2);
			}
			else
			{
				symbol->invalidateAddress();
			}
		}
		symbol->setOriginalName(name);
		symbol->setName(name);
		symbol->setIndex(index);
		symbol->setType(getSymbolType(link, symbolRef.getValue(), symbolRef.getStorageClass()));
		symbol->setUsageType(getSymbolUsageType(symbolRef.getStorageClass(), symbolRef.getComplexType()));
		table->addSymbol(symbol);
		index += symbolRef.getNumberOfAuxSymbols() + 1;
	}

	if(table->hasSymbols())
	{
		symbolTables.push_back(table);
	}
	else
	{
		delete table;
	}
}

/**
 * Load information about relocations
 */
void CoffFormat::loadRelocations()
{
	if(symbolTables.empty())
	{
		return;
	}

	const SymbolTable *symTable = getSymbolTable(0);
	RelocationTable *relTable = nullptr;

	std::size_t secIndex = 0, nextAddress = 0;
	for(const auto &sec : file->sections())
	{
		const auto *ffSec = getSection(secIndex);
		const auto *coffSec = file->getCOFFSection(sec);
		for(const auto &reloc : file->getRelocations(coffSec))
		{
			Relocation rel;

			std::vector<std::uint8_t> relMask;
			if(getRelocationMask(reloc.Type, relMask))
			{
				rel.setMask(relMask);
			}

			rel.setSectionOffset(reloc.VirtualAddress);
			rel.setAddress(nextAddress + reloc.VirtualAddress);
			const auto *sym = symTable->getSymbolWithIndex(reloc.SymbolTableIndex);
			if(sym)
			{
				rel.setLinkToSymbol(reloc.SymbolTableIndex);
				rel.setName(sym->getName());
			}
			else
			{
				rel.invalidateLinkToSymbol();
			}
			rel.setType(reloc.Type);
			rel.setLinkToSection(secIndex);

			if(!relTable)
			{
				relTable = new RelocationTable();
				relTable->setLinkToSymbolTable(0);
			}

			relTable->addRelocation(rel);
		}

		if(relTable)
		{
			relocationTables.push_back(relTable);
			relTable = nullptr;
		}

		++secIndex;
		nextAddress += ffSec->getLoadedSize();
	}
}

/**
 * Get relocation mask for specific type of relocation
 * @param relType Relocation type
 * @param mask Relocation mask
 * @return @c true if mask can be determined, @c false otherwise
 */
bool CoffFormat::getRelocationMask(unsigned relType, std::vector<std::uint8_t> &mask)
{
	const std::map<unsigned, const std::vector<std::uint8_t>*> *map;

	if(isX86())
	{
		map = &x86RelocationMap;
	}
	else if(isX86_64())
	{
		map = &x64RelocationMap;
	}
	else if(isArm() && is32BitArchitecture())
	{
		map = &arm32RelocationMap;
	}
	else if(isArm() && !is32BitArchitecture())
	{
		map = &arm64RelocationMap;
	}
	else
	{
		// Architecture not supported.
		return false;
	}

	auto it = map->find(relType);
	if (it != map->end())
	{
		mask = *(it->second);
		return true;
	}

	// Unknown relocation type.
	unknownRelocs.insert(relType);
	return false;
}

retdec::utils::Endianness CoffFormat::getEndianness() const
{
	switch(file->getMachine())
	{
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
		case PELIB_IMAGE_FILE_MACHINE_R4000:
		case PELIB_IMAGE_FILE_MACHINE_R10000:
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
		case PELIB_IMAGE_FILE_MACHINE_ARM:
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			return Endianness::LITTLE;
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
			return Endianness::BIG;
		default:
			return Endianness::UNKNOWN;
	}
}

std::size_t CoffFormat::getBytesPerWord() const
{
	switch(file->getMachine())
	{
		// Architecture::X86
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
			return 4;

		// Architecture::X86_64
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
			return 8;

		// Architecture::MIPS
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
			return 4;
		case PELIB_IMAGE_FILE_MACHINE_R4000:
			return getFileFlags() & IMAGE_FILE_32BIT_MACHINE ? 4 : 8;
		case PELIB_IMAGE_FILE_MACHINE_R10000:
			return 8;
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
			return 4;
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
			return 2;
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
			return 8;
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
			return 2;

		// Architecture::ARM
		case PELIB_IMAGE_FILE_MACHINE_ARM:
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
			return 4;
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
			return 8;

		// Architecture::POWERPC
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			return getFileFlags() & IMAGE_FILE_32BIT_MACHINE ? 4 : 8;

		// unsupported architecture
		default:
			return 0;
	}
}

bool CoffFormat::hasMixedEndianForDouble() const
{
	return false;
}

/**
 * Get declared length of file. This length may be shorter or longer than real length of file.
 * @return Declared length of file
 */
std::size_t CoffFormat::getDeclaredFileLength() const
{
	std::size_t declSize = FileFormat::getDeclaredFileLength();
	if(getNumberOfCoffSymbols() && getCoffSymbolTableOffset())
	{
		std::size_t symTabMaxOffset = getCoffSymbolTableOffset() + (getNumberOfCoffSymbols() * file->getSymbolTableEntrySize());
		declSize = std::max(declSize, symTabMaxOffset);
	}

	return declSize + getSizeOfStringTable();
}

bool CoffFormat::areSectionsValid() const
{
	return true;
}

bool CoffFormat::isObjectFile() const
{
	return !isDll() && !(getFileFlags() & IMAGE_FILE_EXECUTABLE_IMAGE);
}

bool CoffFormat::isDll() const
{
	return getFileFlags() & IMAGE_FILE_DLL;
}

bool CoffFormat::isExecutable() const
{
	return !isDll() && !isObjectFile();
}

bool CoffFormat::getMachineCode(unsigned long long &result) const
{
	result = file->getMachine();
	return true;
}

bool CoffFormat::getAbiVersion(unsigned long long &result) const
{
	// not in COFF files
	static_cast<void>(result);
	return false;
}

bool CoffFormat::getImageBaseAddress(unsigned long long &imageBase) const
{
	// not in COFF files
	static_cast<void>(imageBase);
	return false;
}

bool CoffFormat::getEpAddress(unsigned long long &result) const
{
	// not in COFF files
	static_cast<void>(result);
	return false;
}

bool CoffFormat::getEpOffset(unsigned long long &epOffset) const
{
	// not in COFF files
	static_cast<void>(epOffset);
	return false;
}

Architecture CoffFormat::getTargetArchitecture() const
{
	switch(file->getMachine())
	{
		case PELIB_IMAGE_FILE_MACHINE_I386:
		case PELIB_IMAGE_FILE_MACHINE_I486:
		case PELIB_IMAGE_FILE_MACHINE_PENTIUM:
			return Architecture::X86;
		case PELIB_IMAGE_FILE_MACHINE_AMD64:
			return Architecture::X86_64;
		case PELIB_IMAGE_FILE_MACHINE_R3000_BIG:
		case PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE:
		case PELIB_IMAGE_FILE_MACHINE_R4000:
		case PELIB_IMAGE_FILE_MACHINE_R10000:
		case PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2:
		case PELIB_IMAGE_FILE_MACHINE_MIPS16:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU:
		case PELIB_IMAGE_FILE_MACHINE_MIPSFPU16:
			return Architecture::MIPS;
		case PELIB_IMAGE_FILE_MACHINE_ARM:
		case PELIB_IMAGE_FILE_MACHINE_THUMB:
		case PELIB_IMAGE_FILE_MACHINE_ARMNT:
		case PELIB_IMAGE_FILE_MACHINE_ARM64:
			return Architecture::ARM;
		case PELIB_IMAGE_FILE_MACHINE_POWERPC:
		case PELIB_IMAGE_FILE_MACHINE_POWERPCFP:
			return Architecture::POWERPC;
		default:
			return Architecture::UNKNOWN;
	}
}

std::size_t CoffFormat::getDeclaredNumberOfSections() const
{
	return file->getNumberOfSections();
}

std::size_t CoffFormat::getDeclaredNumberOfSegments() const
{
	return 0;
}

std::size_t CoffFormat::getSectionTableOffset() const
{
	return sizeof(coff_file_header);
}

std::size_t CoffFormat::getSectionTableEntrySize() const
{
	return sizeof(coff_section);
}

std::size_t CoffFormat::getSegmentTableOffset() const
{
	return 0;
}

std::size_t CoffFormat::getSegmentTableEntrySize() const
{
	return 0;
}

/**
 * Get offset of COFF symbol table
 * @return Offset of COFF symbol table
 */
std::size_t CoffFormat::getCoffSymbolTableOffset() const
{
	return file->getPointerToSymbolTable();
}

/**
 * Get number of symbols in COFF symbol table
 * @return Number of symbols in COFF symbol table
 */
std::size_t CoffFormat::getNumberOfCoffSymbols() const
{
	return file->getNumberOfSymbols();
}

/**
 * Get size in bytes of string table
 * @return Size in bytes of string table
 */
std::size_t CoffFormat::getSizeOfStringTable() const
{
	unsigned long long stringTableOffset = 0;
	if(getCoffSymbolTableOffset() && getNumberOfCoffSymbols())
	{
		stringTableOffset = getCoffSymbolTableOffset() + (getNumberOfCoffSymbols() * file->getSymbolTableEntrySize());
	}

	std::uint64_t result = 0;
	if(!stringTableOffset || stringTableOffset >= getLoadedFileLength() || !get4ByteOffset(stringTableOffset, result))
	{
		return 0;
	}
	else if(result < 4)
	{
		result = 4;
	}

	return result;
}

/**
 * Get file flags
 * @return File flags as number
 */
std::size_t CoffFormat::getFileFlags() const
{
	return file->getCharacteristics();
}

/**
 * Get time stamp
 * @return File time stamp
 */
std::size_t CoffFormat::getTimeStamp() const
{
	return file->getTimeDateStamp();
}

/**
 * Is machine based on a 32-bit-word architecture?
 * @return @c true if machine is based on 32-bit word architecture, @c false otherwise
 */
bool CoffFormat::is32BitArchitecture() const
{
	return (getFileFlags() & IMAGE_FILE_32BIT_MACHINE) || getWordLength() == 32;
}

} // namespace fileformat
} // namespace retdec
