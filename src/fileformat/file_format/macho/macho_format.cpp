/**
 * @file src/fileformat/file_format/macho/macho_format.cpp
 * @brief Definition of MachOFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <system_error>

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/file_format/macho/macho_format.h"

using namespace retdec::utils;
using namespace llvm;
using namespace llvm::MachO;
using namespace llvm::object;

namespace retdec {
namespace fileformat {

namespace
{

/**
 * (R/E)IP or PC register data information offset in LC_UNIXTHREAD
 */
const unsigned IP_UNIXTHREAD_OFFSET_PPC_32BIT = 0x0010;
const unsigned IP_UNIXTHREAD_OFFSET_PPC_64BIT = 0x0010;
const unsigned IP_UNIXTHREAD_OFFSET_X86_32BIT = 0x0038;
const unsigned IP_UNIXTHREAD_OFFSET_X86_64BIT = 0x0090;
const unsigned IP_UNIXTHREAD_OFFSET_ARM_32BIT = 0x004C;
const unsigned IP_UNIXTHREAD_OFFSET_ARM_64BIT = 0x0110;
// The following constants are currently unused, so comment them out to prevent
// emission of compiler warnings. If you need them, feel free to uncomment them.
// const unsigned IP_UNIXTHREAD_OFFSET_M86_32BIT = 0x0054;
// const unsigned IP_UNIXTHREAD_OFFSET_M88_32BIT = 0x008C;
// const unsigned IP_UNIXTHREAD_OFFSET_SPR_32BIT = 0x0014;
// const unsigned IP_UNIXTHREAD_OFFSET_SPR_64BIT = 0x0098;

const std::map<std::string, SecSeg::Type> segmentTypeMap =
{
	{"__PAGEZERO", SecSeg::Type::UNDEFINED_SEC_SEG},
	{"__TEXT", SecSeg::Type::CODE_DATA},
	{"__DATA", SecSeg::Type::DATA},
	{"__OBJC", SecSeg::Type::DATA},
	{"__LINKEDIT", SecSeg::Type::INFO}
};

/**
 * Retrives version of OS in format X.Y.Z from version byte
 * @param version DWord to retrieve information from
 */
std::string getVersionFromDWord(const std::uint32_t version)
{
	unsigned z = version & 0xFF;
	unsigned y = (version >> 8) & 0xFF;
	unsigned x = (version >> 16) & 0xFFFF;
	return std::to_string(x) + "." + std::to_string(y) + "." + std::to_string(z);
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToFile Path to input file
 * @param loadFlags Load flags
 */
MachOFormat::MachOFormat(std::string pathToFile, LoadFlags loadFlags) : FileFormat(pathToFile, loadFlags),
	fileBuffer(MemoryBuffer::getFile(Twine(filePath))), file(nullptr), fatFile(nullptr)
{
	initStructures();
}

/**
 * Destructor
 */
MachOFormat::~MachOFormat()
{
}

/**
 * As LLVM constructor needs information about bit-width and endianness
 * we must read magic number before calling LLVM constructor
 */
void MachOFormat::setWidthAndEndianness()
{
	unsigned char magic[4];
	fileStream.read(reinterpret_cast<char*>(&magic), 4);
	fileStream.seekg(0, std::ios_base::beg);
	if(magic[0] == 0xCA)
	{
		// Endianness and bit-width will be set later
		isFat = true;
	}
	else if(magic[0] == 0xFE)
	{
		isLittle = false;
		is32 = (magic[3] == 0xCE);
	}
	else
	{
		isLittle = true;
		is32 = (magic[0] == 0xCE);
	}
}

/**
 * Choose architecture from universal binary
 * @param itr Iterator of selected architecture
 * @return @c true if selected architecture is available, @c false otherwise
 */
bool MachOFormat::chooseArchitecture(const llvm::object::MachOUniversalBinary::object_iterator &itr)
{
	auto object = itr->getAsObjectFile();

	if(object)
	{
		file = std::move(object.get());
		is32 = !file->is64Bit();
		isLittle = file->isLittleEndian();

		chosenArchOffset = itr->getOffset();
		chosenArchSize = itr->getSize();
		chosenArchBytes.assign(getLoadedBytes().begin() + chosenArchOffset, getLoadedBytes().begin() + chosenArchOffset + chosenArchSize);
		return true;
	}

	// Call consumeError in case of error to "handle" it
	// Unhandled errors cause abort()
	consumeError(object.takeError());

	return false;
}

/**
 * Create instance of MachOObjectFile
 * @return @c true on success, @c false otherwise
 */
bool MachOFormat::constructMachO()
{
	if(fileBuffer && !fileBuffer.getError())
	{
		auto result = MachOObjectFile::create(fileBuffer.get()->getMemBufferRef(), isLittle, !is32);
		if(result)
		{
			file = std::move(result.get());
			return true;
		}

		// Call consumeError in case of error to "handle" it
		// Unhandled errors cause abort()
		consumeError(result.takeError());
	}

	return false;
}

/**
 * Create instance of MachOUniversalBinary and MachOObjectFile
 * @return @c true on success, @c false otherwise
 */
bool MachOFormat::constructFatMachO()
{
	if(fileBuffer && !fileBuffer.getError())
	{
		auto result = MachOUniversalBinary::create(fileBuffer.get()->getMemBufferRef());
		if(!result || !result.get()->getNumberOfObjects())
		{
			consumeError(result.takeError());
			return false;
		}

		auto firstObj = result.get()->begin_objects();
		if (firstObj == result.get()->end_objects())
		{
			return false;
		}
		auto firstData = reinterpret_cast<const char*>(getBytesData() + firstObj->getOffset());
		if (std::strncmp("!<arch>", firstData, 7) == 0)
		{
			isStaticLib = true;
			return false;
		}

		fatFile = std::move(result.get());

		/// @todo strange order of prefered architectures - ppc64 before x64??
		if(chooseArchitecture(CPU_TYPE_X86))
		{
			return true;
		}
		else if(chooseArchitecture(CPU_TYPE_ARM))
		{
			return true;
		}
		else if(chooseArchitecture(CPU_TYPE_ARM64))
		{
			return true;
		}
		else if(chooseArchitecture(CPU_TYPE_POWERPC))
		{
			return true;
		}
		else if(chooseArchitecture(CPU_TYPE_POWERPC64))
		{
			return true;
		}
		else if(chooseArchitecture(CPU_TYPE_X86_64))
		{
			return true;
		}
		else if(chooseArchitecture(CPU_TYPE_SPARC))
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	return false;
}

/**
 * Init internal structures
 */
void MachOFormat::initStructures()
{
	// Read magic
	setWidthAndEndianness();
	// Create parser
	stateIsValid = (isFat ? constructFatMachO() : constructMachO());
	if(stateIsValid)
	{
		if(is32)
		{
			header32 = file->getHeader();
		}
		else
		{
			header64 = file->getHeader64();
		}
		fileFormat = Format::MACHO;
		loadCommands();
		loadStrings();
		loadImpHash();
		loadExpHash();
	}
}

/**
 * Get section or segment name
 * @param secSegName 16 byte long array with section or segment name
 * @return Name of the section or segment
 */
std::string MachOFormat::getSecSegName(const char *secSegName) const
{
	if(!secSegName)
	{
		return "";
	}

	std::string result;

	for(std::size_t i = 0; i < 16 && secSegName[i]; ++i)
	{
		result += secSegName[i];
	}

	return result;
}

/**
 * Get segment type
 * @param segName Name of segment
 * @return Segment type
 *
 * There is no information about type of segment in Mach-O,
 * this is just best guess based on names used by Apple's standard tools
 */
SecSeg::Type MachOFormat::getSegmentType(const char *segName) const
{
	const auto segConName = getSecSegName(segName);
	if(hasItem(segmentTypeMap, segConName))
	{
		return segmentTypeMap.at(segConName);
	}

	return SecSeg::Type::UNDEFINED_SEC_SEG;
}

/**
 * Get section type
 * @param flags Section flags
 * @param name Section name
 * @return Section type
 *
 * This is my best guess based on very little information
 * provided by Apple docs, especially the switch part
 */
SecSeg::Type MachOFormat::getSectionType(std::uint32_t flags, const std::string &name) const
{
	if((flags & S_ATTR_PURE_INSTRUCTIONS))
	{
		return SecSeg::Type::CODE;
	}
	else if((flags & S_ATTR_DEBUG))
	{
		return SecSeg::Type::DEBUG;
	}
	else if((flags & S_ATTR_SOME_INSTRUCTIONS))
	{
		return SecSeg::Type::CODE_DATA;
	}

	switch(flags & 0xFF)
	{
		case S_REGULAR:
		case S_SYMBOL_STUBS:
			return SecSeg::Type::CODE_DATA;
		case S_ZEROFILL:
		case S_GB_ZEROFILL:
		case S_NON_LAZY_SYMBOL_POINTERS:
		case S_LAZY_SYMBOL_POINTERS:
		case S_LAZY_DYLIB_SYMBOL_POINTERS:
		case S_MOD_INIT_FUNC_POINTERS:
		case S_MOD_TERM_FUNC_POINTERS:
		case S_THREAD_LOCAL_REGULAR:
		case S_THREAD_LOCAL_ZEROFILL:
		case S_THREAD_LOCAL_VARIABLES:
		case S_THREAD_LOCAL_VARIABLE_POINTERS:
		case S_THREAD_LOCAL_INIT_FUNCTION_POINTERS:
		case S_INTERPOSING:
		case S_COALESCED:
			return (name == "__bss") ? SecSeg::Type::BSS : SecSeg::Type::DATA;
		case S_CSTRING_LITERALS:
		case S_4BYTE_LITERALS:
		case S_8BYTE_LITERALS:
		case S_16BYTE_LITERALS:
		case S_LITERAL_POINTERS:
			return SecSeg::Type::CONST_DATA;
		case S_DTRACE_DOF:
			return SecSeg::Type::INFO;
		default:
			return SecSeg::Type::UNDEFINED_SEC_SEG;
	}
}

/**
 * Create relocation mask according to Mach-O specific length information
 * @param length Length information as stored in relocation_info structure
 * @return Relocation mask
 */
std::vector<std::uint8_t> MachOFormat::createRelocationMask(unsigned length) const
{
	switch (length)
	{
		case 0:
			return std::vector<std::uint8_t>{ 0xFF };
		case 1:
			return std::vector<std::uint8_t>{ 0xFF, 0xFF };
		case 2:
		case 3:
			return std::vector<std::uint8_t>{ 0xFF, 0xFF, 0xFF, 0xFF };
		default:
			return std::vector<std::uint8_t>();
	}
}

/**
 * Handle one Mach-O scattered relocation data structure
 *
 * Function assumes that it is only called during section structure processing
 * as it uses sectionCounter for setting valid relocation section links
 *
 * @param firstDword First DWORD of relocation_info struct
 * @param tabPtr Pointer to relocation table (destination)
 */
void MachOFormat::handleScatteredRelocation(std::uint32_t firstDword, RelocationTable *tabPtr)
{
	// Should be same for both little and big endian (see OS X ABI Mach-O File Format Reference)
	unsigned rType = (firstDword & 0x0F000000) >> 24;
	unsigned rLength = (firstDword & 0x30000000) >> 28;
	unsigned rAddress = firstDword & 0x00FFFFFF;

	if ((is32 || isPowerPc()) && rType == GENERIC_RELOC_PAIR)
	{
		// Ignore pair relocations
		return;
	}

	Relocation relocation;
	relocation.setType(rType);
	relocation.setLinkToSection(sectionCounter);
	relocation.setMask(createRelocationMask(rLength));
	if (isObjectFile())
	{
		// In object files this is section offset
		relocation.setSectionOffset(rAddress);
	}
	else
	{
		relocation.setAddress(rAddress);
	}
	tabPtr->addRelocation(relocation);
}

/**
 * Handle one Mach-O relocation data structure
 *
 * Function assumes that it is only called during section structure processing
 * as it uses sectionCounter for setting valid relocation section links
 *
 * @param firstDword First DWORD of relocation_info struct
 * @param secondDword Second DWORD of relocation_info struct
 * @param tabPtr Pointer to relocation table (destination)
 */
void MachOFormat::handleRelocation(std::uint32_t firstDword, std::uint32_t secondDword, RelocationTable *tabPtr)
{
	// This should read bitfield in a correct way (see OS X ABI Mach-O File Format Reference)
	unsigned rLink = isLittle ? secondDword & 0x00FFFFFF : (secondDword & 0xFFFFFF00) >> 8;
	unsigned rType = isLittle ? (secondDword & 0xF0000000) >> 28 : secondDword & 0x0000000F;
	unsigned rExtern = isLittle ? (secondDword & 0x08000000) >> 27 : (secondDword & 0x00000010) >> 4;
	unsigned rLength =  isLittle ? (secondDword & 0x06000000) >> 25 : (secondDword & 0x00000060) >> 5;

	if ((is32 || isPowerPc()) && rType == GENERIC_RELOC_PAIR)
	{
		// Ignore pair relocations
		return;
	}

	Relocation relocation;
	relocation.setLinkToSection(sectionCounter);
	relocation.setType(rType);
	relocation.setMask(createRelocationMask(rLength));
	// If link is link to symbol
	if (rExtern)
	{
		relocation.setLinkToSymbol(rLink);
		// It is not guaranteed that symbol table is loaded at this time so we will use LLVM getters
		auto errOrName = file->getSymbolName(file->getSymbolByIndex(rLink)->getRawDataRefImpl());
		if (errOrName)
		{
			relocation.setName(errOrName.get());
		}
		// Unhandled errors cause abort()
		consumeError(errOrName.takeError());
	}
	if (isObjectFile())
	{
		// In object files first DWORD is section offset
		relocation.setSectionOffset(firstDword);
	}
	else
	{
		// In image files first DWORD is virtual address
		relocation.setAddress(firstDword);
	}
	tabPtr->addRelocation(relocation);
}

/**
 * Load relocations for specific section
 *
 * Function assumes that it is only called during section structure processing
 * as it uses sectionCounter for setting valid relocation section links
 *
 * @param offset Offset of relocation table
 * @param count Number of relocations
 */
void MachOFormat::loadSectionRelocations(std::size_t offset, std::size_t count)
{
	if (count)
	{
		auto *tabPtr = new RelocationTable;
		tabPtr->setLinkToSymbolTable(0);
		// Load relocations
		auto *buffPtr = getBufferStart() + offset;
		for (std::size_t i = 0; i < count; ++i)
		{
			// Load relocation info struct as 2 times 4 bytes and swap endianness if necessary
			std::int32_t rInfo[2];
			memcpy(rInfo, buffPtr + i * 8, 8);
			if(isLittle != sys::IsLittleEndianHost)
			{
				sys::swapByteOrder(rInfo[0]);
				sys::swapByteOrder(rInfo[1]);
			}
			// Check if relocation is scattered relocation
			if (rInfo[0] & llvm::MachO::R_SCATTERED)
			{
				handleScatteredRelocation(rInfo[0], tabPtr);
				continue;
			}
			// Normal relocations
			handleRelocation(rInfo[0], rInfo[1], tabPtr);
		}
		relocationTables.push_back(tabPtr);
	}
}

/**
 * Load section
 * @param section 32/64-bit section structure reference
 */
template<typename T> void MachOFormat::loadSection(const T &section)
{
	auto *secPtr = new MachOSection;
	secPtr->setName(getSecSegName(section.sectname));
	secPtr->setType(getSectionType(section.flags, secPtr->getName()));
	secPtr->setIndex(sectionCounter);
	secPtr->setOffset(section.offset + chosenArchOffset);
	secPtr->setSizeInFile(section.size);
	secPtr->setAddress(section.addr);
	secPtr->setSizeInMemory(section.size);
	secPtr->setMemory(section.size);
	secPtr->setSegmentName(getSecSegName(section.segname));
	secPtr->setAlignment(section.align);
	secPtr->setRelocationOffset(section.reloff);
	secPtr->setNumberOfRelocations(section.nreloc);
	secPtr->setMachOFlags(section.flags);
	secPtr->setReserved1(section.reserved1);
	secPtr->setReserved2(section.reserved2);
	if(section.size)
	{
		secPtr->load(this);
	}
	sections.push_back(secPtr);
	loadSectionRelocations(section.reloff, section.nreloc);
	++sectionCounter;
}

/**
 * Load segment
 * @param segment 32/64-bit segment structure reference
 * @return Pointer to created segment
 */
template<typename T> Segment* MachOFormat::loadSegment(const T &segment)
{
	Segment *segPtr = new Segment;
	segPtr->setName(getSecSegName(segment.segname));
	segPtr->setType(getSegmentType(segment.segname));
	segPtr->setIndex(segmentCounter);
	segPtr->setOffset(segment.fileoff + chosenArchOffset);
	segPtr->setSizeInFile(segment.filesize);
	segPtr->setAddress(segment.vmaddr);
	segPtr->setSizeInMemory(segment.vmsize);
	// Only segments with at least one section are loaded
	if(segment.nsects)
	{
		segPtr->setMemory(true);
		segPtr->load(this);
	}
	segments.push_back(segPtr);
	++segmentCounter;
	return segPtr;
}

/**
 * Handle 32-bit segment command
 * @param commandInfo LoadCommandInfo reference
 */
void MachOFormat::segmentCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo)
{
	MachO::segment_command command = file->getSegmentLoadCommand(commandInfo);
	auto *segPtr = loadSegment(command);
	MachO::section secTmp;

	// If no name given, get name from section
	if(segPtr->getName().empty() && command.nsects)
	{
		secTmp = file->getSection(commandInfo, 0);
		segPtr->setName(getSecSegName(secTmp.segname));
		segPtr->setType(getSegmentType(secTmp.segname));
	}

	for(std::uint32_t i = 0; i < command.nsects; ++i)
	{
		secTmp = file->getSection(commandInfo, i);
		loadSection(secTmp);
	}
}

/**
 * Handle 64-bit segment command
 * @param commandInfo LoadCommandInfo reference
 */
void MachOFormat::segment64Command(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo)
{
	MachO::segment_command_64 command = file->getSegment64LoadCommand(commandInfo);
	auto *segPtr = loadSegment(command);
	MachO::section_64 secTmp;

	if(segPtr->getName().empty() && command.nsects)
	{
		secTmp = file->getSection64(commandInfo, 0);
		segPtr->setName(getSecSegName(secTmp.segname));
		segPtr->setType(getSegmentType(secTmp.segname));
	}

	for(std::uint32_t i = 0; i < command.nsects; ++i)
	{
		secTmp = file->getSection64(commandInfo, i);
		loadSection(secTmp);
	}
}

/**
 * Set entry point address and its file offset (LC_MAIN Mac OS 10.8+)
 * @param commandInfo LoadCommandInfo reference
 */
void MachOFormat::entryPointCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo)
{
	auto command = file->getEntryPointCommand(commandInfo);
	hasEntryPoint = true;
	entryPointOffset = command.entryoff + chosenArchOffset;
	entryPointAddr = offsetToAddress(entryPointOffset);
}

/**
 * Set entry point address and its file offset (LC_UNIXTHREAD before Mac OS 10.8)
 * @param commandInfo LoadCommandInfo reference
 */
void MachOFormat::oldEntryPointCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo)
{
	// LC_MAIN command is preferred source of this information
	if(hasEntryPoint)
	{
		return;
	}

	const char *lcOffset = commandInfo.Ptr;
	switch(getTargetArchitecture())
	{
		case Architecture::X86:
			lcOffset += IP_UNIXTHREAD_OFFSET_X86_32BIT;
			break;
		case Architecture::X86_64:
			lcOffset += IP_UNIXTHREAD_OFFSET_X86_64BIT;
			break;
		case Architecture::ARM:
			lcOffset += is32 ? IP_UNIXTHREAD_OFFSET_ARM_32BIT : IP_UNIXTHREAD_OFFSET_ARM_64BIT;
			break;
		case Architecture::POWERPC:
			lcOffset += is32 ? IP_UNIXTHREAD_OFFSET_PPC_32BIT : IP_UNIXTHREAD_OFFSET_PPC_64BIT;
			break;
		default:
			return;
	}

	entryPointAddr = is32 ? get32Bit(lcOffset) : get64Bit(lcOffset);

	// Get file offset from address
	for(const auto &segment : segments)
	{
		if((entryPointAddr >= segment->getAddress()) && (entryPointAddr < segment->getEndAddress()))
		{
			entryPointOffset = segment->getOffset() + (entryPointAddr - segment->getAddress());
			break;
		}
	}

	hasEntryPoint = true;
}

/**
 * Handle LC_LOAD_DYLIB command
 * @param commandInfo LoadCommandInfo reference
 */
void MachOFormat::loadDylibCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo)
{
	auto command = file->getDylibIDLoadCommand(commandInfo);
	std::string name = commandInfo.Ptr + command.dylib.name;
	// Try to get short name
	StringRef sufix;
	bool isFramework;
	const std::string shortName = file->guessLibraryShortName(name, isFramework, sufix).str();

	if(!importTable)
	{
		importTable = new ImportTable;
	}

	if(shortName.empty())
	{
		importTable->addLibrary(name);
	}
	else
	{
		importTable->addLibrary(shortName + sufix.str());
	}
}

/**
 * Load symbol table
 */
void MachOFormat::symtabCommand()
{
	auto command = file->getSymtabLoadCommand();
	const char *strPtr = fileBuffer.get()->getBufferStart() + command.stroff + chosenArchOffset;
	const char *endPtr = chosenArchSize ? fileBuffer.get()->getBufferStart() + chosenArchOffset + chosenArchSize : fileBuffer.get()->getBufferEnd();
	if(strPtr >= endPtr)
	{
		return;
	}

	auto *symbolTable = new SymbolTable();
	llvm::StringRef strTable = llvm::StringRef(strPtr, endPtr - strPtr);
	const char *ptr = fileBuffer.get()->getBufferStart() + command.symoff + chosenArchOffset;

	for(std::uint32_t i = 0; i < command.nsyms; ++i)
	{
		MachOSymbol machoSymbol;
		if(is32)
		{
			if(ptr + sizeof(MachO::nlist) >= endPtr)
			{
				break;
			}

			MachO::nlist res;
			memcpy(&res, ptr, sizeof(MachO::nlist));
			if(isLittle != sys::IsLittleEndianHost)
			{
				MachO::swapStruct(res);
			}
			ptr += sizeof(MachO::nlist);
			machoSymbol.setAllValues(res, strTable, i);
			symbols.push_back(machoSymbol);
		}
		else
		{
			if(ptr + sizeof(MachO::nlist_64) >= endPtr)
			{
				break;
			}

			MachO::nlist_64 res;
			memcpy(&res, ptr, sizeof(MachO::nlist_64));
			if(isLittle != sys::IsLittleEndianHost)
			{
				MachO::swapStruct(res);
			}
			ptr += sizeof(MachO::nlist_64);
			machoSymbol.setAllValues(res, strTable, i);
			symbols.push_back(machoSymbol);
		}

		machoSymbol.makeFunction(this);
		symbolTable->addSymbol(machoSymbol.getAsSymbol());
	}

	if(symbolTable->hasSymbols())
	{
		symbolTables.push_back(symbolTable);
	}
}

/**
 * Get section with lazy symbols
 * @return __la_symbol_ptrs section pointer
 */
MachOSection* MachOFormat::getLazySymbolsSection() const
{
	for(auto *section : sections)
	{
		MachOSection *res = static_cast<MachOSection*>(section);
		if((res->getMachOFlags() & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS)
		{
			return res;
		}
	}

	return nullptr;
}

/**
 * Get section with non-lazy symbols
 * @return __nl_symbol_ptrs section pointer
 */
MachOSection* MachOFormat::getNonLazySymbolsSection() const
{
	for(auto *section : sections)
	{
		MachOSection *res = static_cast<MachOSection*>(section);
		if((res->getMachOFlags() & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS)
		{
			return res;
		}
	}

	return nullptr;
}

/**
 * Get all imports from symbol section
 * @param secPtr Section pointer
 *
 * importTable and indirectTable have to be available
 */
void MachOFormat::getImportsFromSection(const MachOSection *secPtr)
{
	if(!secPtr || !importTable)
	{
		return;
	}

	unsigned long long sectionAddress = secPtr->getAddress();
	unsigned long long tableIndex = secPtr->getReserved1();
	unsigned long long count = 0;
	unsigned align = is32 ? 4 : 8;

	if(secPtr->getSizeInMemory(count) && tableIndex)
	{
		count /= align;
		for(auto i = tableIndex; i < tableIndex + count; ++i)
		{
			// true index is retrieved from indirect table
			if(i >= indirectTable.size() || symbols.size() < indirectTable[i])
			{
				continue;
			}

			auto import = symbols[indirectTable[i]].getAsImport();
			import->setAddress(sectionAddress);
			importTable->addImport(std::move(import));
			sectionAddress += align;
		}
	}
}

/**
 * Parse indirect table
 * @param offset Indirect table file offset
 * @param size Indirect table size
 */
void MachOFormat::parseIndirectTable(std::uint32_t offset, std::uint32_t size)
{
	const char *tablePtr = fileBuffer.get()->getBufferStart() + offset + chosenArchOffset;
	const char* endPtr = chosenArchSize ? fileBuffer.get()->getBufferStart() + chosenArchOffset + chosenArchSize : fileBuffer.get()->getBufferEnd();

	for(std::uint32_t i = 0; i < size && tablePtr < endPtr; ++i, tablePtr += 4)
	{
		indirectTable.push_back(get32Bit(tablePtr));
	}
}

/**
 * Load exports and imports from LC_DYSYMTAB
 */
void MachOFormat::dySymtabCommand()
{
	if(isDyld)
	{
		// LC_DYLD_INFO is preferred source of this information
		return;
	}

	const dysymtab_command com = file->getDysymtabLoadCommand();
	// Defined external symbols (exports)
	if(com.nextdefsym)
	{
		if(!exportTable)
		{
			exportTable = new ExportTable;
		}
		Export exportSym;

		for(auto i = com.iextdefsym; i < (com.iextdefsym + com.nextdefsym); ++i)
		{
			if(i >= symbols.size())
			{
				break;
			}

			exportSym = symbols[i].getAsExport();
			exportTable->addExport(exportSym);
		}
	}

	// Undefined external symbols (imports)
	if(com.nundefsym && com.nindirectsyms)
	{
		if(!importTable)
		{
			importTable = new ImportTable;
		}
		parseIndirectTable(com.indirectsymoff, com.nindirectsyms);
		// Lazy imports
		getImportsFromSection(getLazySymbolsSection());
		// Non-lazy imports
		getImportsFromSection(getNonLazySymbolsSection());
	}
}

/**
 * Load exports and imports from LC_DYLD_INFO (Mac OS 10.6+)
 */
void MachOFormat::dyldInfoCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo)
{
	isDyld = true;
	auto command = file->getDyldInfoLoadCommand(commandInfo);
	const char* startPtr = fileBuffer.get()->getBufferStart() + chosenArchOffset;
	const char* endPtr = chosenArchSize ? fileBuffer.get()->getBufferStart() + chosenArchOffset + chosenArchSize : fileBuffer.get()->getBufferEnd();

	// Exports
	if(startPtr + command.export_off + command.export_size <= endPtr)
	{
		if(!exportTable)
		{
			exportTable = new ExportTable;
		}
		Export exportSym;

		for(auto &exportRef : file->exports())
		{
			exportSym.setAddress(offsetToAddress(exportRef.address()));
			exportSym.invalidateOrdinalNumber();
			std::string name = exportRef.name().str();
			if(name.empty())
			{
				exportSym.setName("exported_function_" + numToStr(exportRef.address(), std::hex));
			}
			else
			{
				exportSym.setName(name);
			}

			exportTable->addExport(exportSym);
		}
	}

	// Imports
	if(!importTable)
	{
		importTable = new ImportTable;
	}

	if(startPtr + command.bind_off + command.bind_size <= endPtr)
	{
		for(const auto &importRef : file->bindTable())
		{
			auto importSym = getImportFromBindEntry(importRef);
			if(!importSym)
			{
				break;
			}

			importTable->addImport(std::move(importSym));
		}
	}

	if(startPtr + command.lazy_bind_off + command.lazy_bind_size <= endPtr)
	{
		for(const auto &importRef : file->lazyBindTable())
		{
			auto importSym = getImportFromBindEntry(importRef);
			if(!importSym)
			{
				break;
			}

			importTable->addImport(std::move(importSym));
		}
	}

	if(startPtr + command.weak_bind_off + command.weak_bind_size <= endPtr)
	{
		for(const auto &importRef : file->weakBindTable())
		{
			auto importSym = getImportFromBindEntry(importRef);
			if(!importSym)
			{
				break;
			}

			importTable->addImport(std::move(importSym));
		}
	}
}

/**
 * Convert MachOBindEntry to import
 * @param input Source entry
 * @return Import
 *
 * Segments have to be loaded before calling this function
 */
std::unique_ptr<Import> MachOFormat::getImportFromBindEntry(const llvm::object::MachOBindEntry &input)
{
	if(input.malformed() || input.segmentIndex() >= getDeclaredNumberOfSegments())
	{
		return nullptr;
	}

	auto result = std::make_unique<Import>();
	result->setName(input.symbolName());
	result->setLibraryIndex(input.ordinal() - 1);
	result->invalidateOrdinalNumber();
	result->setAddress(getSegment(input.segmentIndex())->getAddress() + input.segmentOffset());
	return result;
}

/**
 * Get number of load commands
 * @return Number of load commands
 */
std::uint32_t MachOFormat::getNumberOfCommands() const
{
	return is32 ? header32.ncmds : header64.ncmds;
}

/**
 * Get file offset of first load command
 * @return First command file offset
 */
std::uint32_t MachOFormat::getFirstCommandOffset() const
{
	const std::uint32_t headerSize = is32 ? sizeof(llvm::MachO::mach_header) : sizeof(llvm::MachO::mach_header_64);
	return headerSize + chosenArchOffset;
}

/**
 * Functions iterates over Mach-O load commands and loads useful information
 * from supported commands
 */
void MachOFormat::loadCommands()
{
	for(const auto &command : file->load_commands())
	{
		switch(command.C.cmd)
		{
			case MachO::LC_SEGMENT:
				segmentCommand(command);
				break;

			case MachO::LC_SEGMENT_64:
				segment64Command(command);
				break;

			case MachO::LC_MAIN:
				entryPointCommand(command);
				break;

			case MachO::LC_UNIXTHREAD:
				oldEntryPointCommand(command);
				break;

			case MachO::LC_SYMTAB:
				symtabCommand();
				break;

			case MachO::LC_LOAD_DYLIB:
			case MachO::LC_PREBOUND_DYLIB:
				loadDylibCommand(command);
				break;

			// Imports and exports before Mac OS 10.6
			case MachO::LC_DYSYMTAB:
				dySymtabCommand();
				break;

			// Imports and exports Mac OS 10.6+
			case LC_DYLD_INFO:
			case LC_DYLD_INFO | LC_REQ_DYLD:
				dyldInfoCommand(command);
				break;

			default:
				break;
		}
	}
}

void MachOFormat::dumpCommands(std::ostream &outStream)
{
	outStream << "Load command information:\n";
	for (const auto &command : file->load_commands())
	{
		outStream << std::hex << "Type: 0x" << command.C.cmd
				<< ". Size: 0x" << command.C.cmdsize << ".\n";
	}
}

/**
 * Interpret 32 bits of memory
 * @param ptr Pointer to memory
 * @return Interpreted value
 */
unsigned long long MachOFormat::get32Bit(const char *ptr) const
{
	if(!ptr)
	{
		return 0;
	}

	std::uint32_t result = 0;
	memcpy(&result, ptr, 4);
	if(isLittle != sys::IsLittleEndianHost)
	{
		sys::swapByteOrder(result);
	}

	return result;
}

/**
 * Interpret 64 bits of memory
 * @param ptr Pointer to memory
 * @return Interpreted value
 */
unsigned long long MachOFormat::get64Bit(const char *ptr) const
{
	if(!ptr)
	{
		return 0;
	}

	std::uint64_t result = 0;
	memcpy(&result, ptr, 8);
	if(isLittle != sys::IsLittleEndianHost)
	{
		sys::swapByteOrder(result);
	}

	return result;
}

/**
 * Convert file offset to virtual address
 * @param offset Offset in file
 * @return Address in memory or zero when no address found
 *
 * Segments have to be loaded before calling this function
 */
unsigned long long MachOFormat::offsetToAddress(unsigned long long offset) const
{
	unsigned long long address = 0;

	for(const auto *segment : segments)
	{
		unsigned long long segOff = segment->getOffset();
		if((offset >= segOff) && (offset < (segOff + segment->getSizeInFile())))
		{
			address = segment->getAddress() + (offset - segOff);
			break;
		}
	}

	return address;
}

/**
 * Get target architecture
 * @param cpuType Mach-O specific CPU type field
 * @return Target architecture
 */
Architecture MachOFormat::getTargetArchitecture(std::uint32_t cpuType) const
{
	switch(cpuType)
	{
		case MachO::CPU_TYPE_X86:
			return Architecture::X86;
		case MachO::CPU_TYPE_X86_64:
			return Architecture::X86_64;
		case MachO::CPU_TYPE_MC98000: // Old Motorola PowerPC
		case MachO::CPU_TYPE_POWERPC:
		case MachO::CPU_TYPE_POWERPC64:
			return Architecture::POWERPC;
		case MachO::CPU_TYPE_ARM:
		case MachO::CPU_TYPE_ARM64:
			return Architecture::ARM;
		case MachO::CPU_TYPE_SPARC:
		default:
			return Architecture::UNKNOWN;
	}
}

std::vector<std::string> MachOFormat::getMachOUniversalArchitectures() const
{
	std::vector<std::string> result;
	if(!isFat)
	{
		return result;
	}

	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		std::string archName = i->getArchTypeName();
		if(archName.empty())
		{
			archName = "unknown subtype ";
			switch(i->getCPUType())
			{
				case CPU_TYPE_X86:
					archName += "x86";
					break;
				case CPU_TYPE_X86_64:
					archName += "x86_64";
					break;
				case CPU_TYPE_MC98000:
					archName = "mc98000";
					break;
				case CPU_TYPE_ARM:
					archName += "arm";
					break;
				case CPU_TYPE_ARM64:
					archName += "arm64";
					break;
				case CPU_TYPE_SPARC:
					archName += "sparc";
					break;
				case CPU_TYPE_POWERPC:
					archName += "ppc";
					break;
				case CPU_TYPE_POWERPC64:
					archName += "ppc64";
					break;
				default:
					archName = "unknown";
					break;
			}
		}
		result.push_back(archName);
	}

	return result;
}

/**
 * Get pointer to LLVM buffer with file content.
 * @return Pointer to buffer
 */
const char *MachOFormat::getBufferStart() const
{
	return fileBuffer.get()->getBufferStart();
}

/**
 * Clear all loaded commands
 */
void MachOFormat::clearCommands()
{
	clear();
	segmentCounter = 0;
	sectionCounter = 0;
	hasEntryPoint = false;
	entryPointAddr = 0;
	entryPointOffset = 0;
	symbols.clear();
}

retdec::utils::Endianness MachOFormat::getEndianness() const
{
	return isLittle ? Endianness::LITTLE : Endianness::BIG;
}

std::size_t MachOFormat::getBytesPerWord() const
{
	return is32 ? 4 : 8;
}

bool MachOFormat::hasMixedEndianForDouble() const
{
	return false;
}

std::string MachOFormat::getFileFormatName() const
{
	if(isFat)
	{
		std::string result = "Mach-O Universal Binary:";
		for(auto archName : getMachOUniversalArchitectures())
		{
			result += " [" + archName + "]";
		}
		return result;
	}

	return FileFormat::getFileFormatName();
}

bool MachOFormat::areSectionsValid() const
{
	return true;
}

bool MachOFormat::isObjectFile() const
{
	return file->isRelocatableObject();
}

bool MachOFormat::isDll() const
{
	const std::uint32_t filetype = is32 ? header32.filetype : header64.filetype;
	return filetype == MachO::MH_DYLIB || filetype == MachO::MH_BUNDLE;
}

bool MachOFormat::isExecutable() const
{
	std::uint32_t filetype = is32 ? header32.filetype : header64.filetype;
	return filetype == MachO::MH_EXECUTE || filetype == MachO::MH_PRELOAD;
}

bool MachOFormat::getMachineCode(unsigned long long &result) const
{
	is32 ? result = static_cast<unsigned long long>(header32.cputype) : result = static_cast<unsigned long long>(header64.cputype);
	return true;
}

bool MachOFormat::getAbiVersion(unsigned long long &result) const
{
	return false;
}

bool MachOFormat::getImageBaseAddress(unsigned long long &imageBase) const
{
	return false;
}

bool MachOFormat::getEpAddress(unsigned long long &result) const
{
	if(hasEntryPoint)
	{
		result = static_cast<unsigned long long>(entryPointAddr);
		return true;
	}

	return false;
}

bool MachOFormat::getEpOffset(unsigned long long &epOffset) const
{
	if(hasEntryPoint)
	{
		epOffset = static_cast<unsigned long long>(entryPointOffset);
		return true;
	}

	return false;
}

Architecture MachOFormat::getTargetArchitecture() const
{
	return getTargetArchitecture(is32 ? header32.cputype : header64.cputype);
}

std::size_t MachOFormat::getDeclaredNumberOfSections() const
{
	return sectionCounter;
}

std::size_t MachOFormat::getDeclaredNumberOfSegments() const
{
	return segmentCounter;
}

/// @todo Implement
std::size_t MachOFormat::initSectionTableHashOffsets()
{
	return 0;
}

/// @todo Implement
std::size_t MachOFormat::getSectionTableOffset() const
{
	return 0;
}

/// @todo Implement
std::size_t MachOFormat::getSectionTableEntrySize() const
{
	return 0;
}

/// @todo Implement
std::size_t MachOFormat::getSegmentTableOffset() const
{
	return 0;
}

/// @todo Implement
std::size_t MachOFormat::getSegmentTableEntrySize() const
{
	return 0;
}

/**
 * Bit-width detection method
 * @return @c true if architecture is 32-bit, @c false otherwise
 */
bool MachOFormat::is32Bit() const
{
	return is32;
}

/**
 * Fat binary detection method
 * @return @c true if binary is universal, @c false otherwise
 */
bool MachOFormat::isFatBinary() const
{
	return isFat;
}

/**
 * Static library detection
 * @return @c true if file contains static signatures, @c false otherwise
 */
bool MachOFormat::isStaticLibrary() const
{
	return isStaticLib;
}

/**
 * Returns binary target OS
 * @param name String describing OS name
 * @param version String describing OS version
 * @return @c true if OS is detectable, @c false otherwise
 */
bool MachOFormat::getTargetOs(std::string &name, std::string &version) const
{
	name.clear();
	version.clear();
	version_min_command verCommand;

	for(const auto &command : file->load_commands())
	{
		switch(command.C.cmd)
		{
			case LC_VERSION_MIN_MACOSX:
				verCommand = file->getVersionMinLoadCommand(command);
				name = "OS X";
				version = getVersionFromDWord(verCommand.version);
				return true;
			case LC_VERSION_MIN_IPHONEOS:
				verCommand = file->getVersionMinLoadCommand(command);
				name = "iOS";
				version = getVersionFromDWord(verCommand.version);
				return true;
			case LC_VERSION_MIN_TVOS:
				verCommand = file->getVersionMinLoadCommand(command);
				name = "tvOS";
				version = getVersionFromDWord(verCommand.version);
				return true;
			case LC_VERSION_MIN_WATCHOS:
				verCommand = file->getVersionMinLoadCommand(command);
				name = "watchOS";
				version = getVersionFromDWord(verCommand.version);
				return true;
			default:
				continue;
		}
	}

	return false;
}

/**
 * Get information about used encryption
 * @param off Encrypted information file offset
 * @param size Encrypted infromation file size
 * @param id Encryption algorithm used
 * @return @c true if encryption was used, @c false otherwise
 */
bool MachOFormat::getEncryptionInfo(unsigned long &off, unsigned long &size, unsigned long &id)
{
	for(const auto &command : file->load_commands())
	{
		if(command.C.cmd == LC_ENCRYPTION_INFO)
		{
			encryption_info_command enComm = file->getEncryptionInfoCommand(command);
			// zero cryptid means no encryption
			if(enComm.cryptid)
			{
				off = enComm.cryptoff;
				size = enComm.cryptsize;
				id = enComm.cryptid;
				return true;
			}
		}
		else if(command.C.cmd == LC_ENCRYPTION_INFO_64)
		{
			encryption_info_command_64 enComm = file->getEncryptionInfoCommand64(command);
			if(enComm.cryptid)
			{
				off = enComm.cryptoff;
				size = enComm.cryptsize;
				id = enComm.cryptid;
				return true;
			}
		}
	}

	return false;
}

/**
 * Get format specific file type
 * @return File type
 */
std::uint32_t MachOFormat::getFileType() const
{
	return is32 ? header32.filetype : header64.filetype;
}

/**
 * Get size of all load commands
 * @return Size of commands
 */
std::uint32_t MachOFormat::getSizeOfCommands() const
{
	return is32 ? header32.sizeofcmds : header64.sizeofcmds;
}

/**
 * Choose architecture from universal binary
 * @param cpuType Type of selected architecture
 * @return @c true if selected architecture is available, @c false otherwise
 */
bool MachOFormat::chooseArchitecture(std::uint32_t cpuType)
{
	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i)
	{
		if(cpuType == i->getCPUType())
		{
			return chooseArchitecture(i);
		}
	}

	return false;
}

/**
 * Choose architecture from universal binary at specified index
 * @param index Index of the selected architecture
 * @return @c true if selected architecture is available, @c false otherwise
 */
bool MachOFormat::chooseArchitectureAtIndex(std::uint32_t index)
{
	if(!isFat || index >= fatFile->getNumberOfObjects())
	{
		return false;
	}

	std::uint32_t counter = 0;

	for(auto i = fatFile->begin_objects(), e = fatFile->end_objects(); i != e; ++i, ++counter)
	{
		if(index == counter && chooseArchitecture(i))
		{
			clearCommands();
			// Update underlying structures
			if(is32)
			{
				header32 = file->getHeader();
			}
			else
			{
				header64 = file->getHeader64();
			}
			loadCommands();
			return true;
		}
	}

	return false;
}

/**
 * Get offset of the chosen architecture
 * @return Offset of the architecture
 */
std::uint32_t MachOFormat::getChosenArchitectureOffset() const
{
	return chosenArchOffset;
}

} // namespace fileformat
} // namespace retdec
