/**
 * @file src/fileinfo/file_detector/elf_detector.cpp
 * @brief Methods of ElfDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/array.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/symbol_table/elf_symbol.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_detector/elf_detector.h"

using namespace retdec::utils;
using namespace ELFIO;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const unsigned long long ELF_32_FLAGS_SIZE = 32, ELF_64_FLAGS_SIZE = 64;

/**
 * Detect of segment type
 * @param segment File segment
 * @return Segment type
 *
 * If value of parameter @a segment is nullptr, function will return empty string
 */
std::string getSegmentType(const ELFIO::segment *segment)
{
	if(!segment)
	{
		return "";
	}

	const unsigned long long type = segment->get_type();
	switch(type)
	{
		case PT_NULL:
			return "NULL";
		case PT_LOAD:
			return "LOADABLE";
		case PT_DYNAMIC:
			return "DYNAMIC";
		case PT_INTERP:
			return "INTERP";
		case PT_NOTE:
			return "NOTE";
		case PT_SHLIB:
			return "SHLIB";
		case PT_PHDR:
			return "PHDR";
		case PT_TLS:
			return "TLS";
		default:
			break;
	}

	if(type >= PT_LOOS && type <= PT_HIOS)
	{
		return "OS-specific";
	}
	else if(type >= PT_LOPROC && type <= PT_HIPROC)
	{
		return "Processor-specific";
	}

	return "";
}

/**
 * Detect of section type
 * @param section File section
 * @return Section type
 *
 * If value of parameter @a section is nullptr, function will return empty string
 */
std::string getSectionType(const ELFIO::section *section)
{
	if(!section)
	{
		return "";
	}

	const unsigned long long type = section->get_type();
	switch(type)
	{
		case SHT_NULL:
			return "NULL";
		case SHT_PROGBITS:
			return "PROGBITS";
		case SHT_SYMTAB:
			return "SYMTAB";
		case SHT_STRTAB:
			return "STRTAB";
		case SHT_RELA:
			return "RELA";
		case SHT_HASH:
			return "HASH";
		case SHT_DYNAMIC:
			return "DYNAMIC";
		case SHT_NOTE:
			return "NOTE";
		case SHT_NOBITS:
			return "NOBITS";
		case SHT_REL:
			return "REL";
		case SHT_SHLIB:
			return "SHLIB";
		case SHT_DYNSYM:
			return "DYNSYM";
		case SHT_INIT_ARRAY:
			return "INIT_ARRAY";
		case SHT_FINI_ARRAY:
			return "FINI_ARRAY";
		case SHT_PREINIT_ARRAY:
			return "PREINIT_ARRAY";
		case SHT_GROUP:
			return "GROUP";
		case SHT_SYMTAB_SHNDX:
			return "SYMTAB_SHNDX";
		default:
			break;
	}

	if(type >= SHT_LOOS && type <= SHT_HIOS)
	{
		return "OS-specific";
	}
	else if(type >= SHT_LOPROC && type <= SHT_HIPROC)
	{
		return "Processor-specific";
	}
	else if(type >= SHT_LOUSER && type <= SHT_HIUSER)
	{
		return "Application-specific";
	}

	return "";
}

/**
 * Detect of symbol type
 * @param symbolType Symbol type as number
 * @return Symbol type as text information
 */
std::string getSymbolType(unsigned long long symbolType)
{
	switch(symbolType)
	{
		case STT_NOTYPE:
			return "NOTYPE";
		case STT_OBJECT:
			return "DATA OBJECT";
		case STT_FUNC:
			return "FUNCTION";
		case STT_SECTION:
			return "SECTION";
		case STT_FILE:
			return "FILE";
		case STT_COMMON:
			return "COMMON";
		case STT_TLS:
			return "TLS";
		default:
			break;
	}

	if(symbolType >= STT_LOOS && symbolType <= STT_HIOS)
	{
		return "OS-specific";
	}
	else if(symbolType >= STT_LOPROC && symbolType <= STT_HIPROC)
	{
		return "Processor-specific";
	}

	return "";
}

/**
 * Detect of symbol bind
 * @param symbolBind Symbol bind as number
 * @return Symbol bind as text information
 */
std::string getSymbolBind(unsigned long long symbolBind)
{
	switch(symbolBind)
	{
		case STB_LOCAL:
			return "LOCAL";
		case STB_GLOBAL:
			return "GLOBAL";
		case STB_WEAK:
			return "WEAK";
		default:
			break;
	}

	if(symbolBind >= STB_LOOS && symbolBind <= STB_HIOS)
	{
		return "OS-specific";
	}
	else if(symbolBind >= STB_LOPROC && symbolBind <= STB_HIPROC)
	{
		return "Processor-specific";
	}

	return "";
}

/**
 * Get other information about symbol
 * @param other Other information about symbol as number
 * @return Other information about symbol as string
 */
std::string getSymbolOtherInformation(unsigned long long other)
{
	switch(other)
	{
		case STV_DEFAULT:
			return "Default visibility";
		case STV_INTERNAL:
			return "Internal visibility";
		case STV_HIDDEN:
			return "Hidden visibility";
		case STV_PROTECTED:
			return "Protected visibility";
		default:
			return "";
	}
}

/**
 * Get link to symbol section
 * @param link Link to section in number representation
 * @return Link to section in string representation
 */
std::string getSymbolLinkToSection(unsigned long long link)
{
	switch(link)
	{
		case SHN_ABS:
			return "ABSOLUTE";
		case SHN_COMMON:
			return "COMMON";
		case SHN_UNDEF:
			return "UNDEFINED";
		case SHN_XINDEX:
			return "XINDEX";
		default:
			return numToStr(link);
	}
}

/**
 * Get type of dynamic entry
 * @param dynamicTag Type of dynamic entry in number representation
 * @return Type of dynamic entry in string representation
 */
std::string getDynamicEntryType(unsigned long long dynamicTag)
{
	switch(dynamicTag)
	{
		case DT_NULL:
			return "End of _DYNAMIC array (DT_NULL)";
		case DT_NEEDED:
			return "String table offset of name of needed library (DT_NEEDED)";
		case DT_PLTRELSZ:
			return "DT_PLTRELSZ";
		case DT_PLTGOT:
			return "DT_PLTGOT";
		case DT_HASH:
			return "Address of symbol hash table (DT_HASH)";
		case DT_STRTAB:
			return "Address of string table (DT_STRTAB)";
		case DT_SYMTAB:
			return "Address of symbol table (DT_SYMBTAB)";
		case DT_RELA:
			return "Address of relocation table with explicit addends (DT_RELA)";
		case DT_RELASZ:
			return "Size in bytes of DT_RELA relocation table (DT_RELASZ)";
		case DT_RELAENT:
			return "Size in bytes of DT_RELA relocation entry (DT_RELAENT)";
		case DT_STRSZ:
			return "Size in bytes of string table (DT_STRSZ)";
		case DT_SYMENT:
			return "Size in bytes of symbol table entry (DT_SYMENT)";
		case DT_INIT:
			return "Address of initialization function (DT_INIT)";
		case DT_FINI:
			return "Address of termination function (DT_FINI)";
		case DT_SONAME:
			return "String table offset of name of shared object (DT_SONAME)";
		case DT_RPATH:
			return "String table offset of search library search path string (DT_RPATH)";
		case DT_SYMBOLIC:
			return "DT_SYMBOLIC";
		case DT_REL:
			return "Address of relocation table without explicit addends (DT_REL)";
		case DT_RELSZ:
			return "Size in bytes of DT_REL relocation table (DT_RELSZ)";
		case DT_RELENT:
			return "Size in bytes of DT_REL relocation entry (DT_RELENT)";
		case DT_PLTREL:
			return "DT_PLTREL";
		case DT_DEBUG:
			return "DT_DEBUG";
		case DT_TEXTREL:
			return "DT_TEXTREL";
		case DT_JMPREL:
			return "DT_JMPREL";
		case DT_BIND_NOW:
			return "DT_BIND_NOW";
		case DT_INIT_ARRAY:
			return "DT_INIT_ARRAY";
		case DT_FINI_ARRAY:
			return "DT_FINI_ARRAY";
		case DT_INIT_ARRAYSZ:
			return "DT_INIT_ARRAYSZ";
		case DT_FINI_ARRAYSZ:
			return "DT_FINI_ARRAYSZ";
		case DT_RUNPATH:
			return "String table offset of library search path string (DT_RUNPATH)";
		case DT_FLAGS:
			return "DT_FLAGS";
		case DT_PREINIT_ARRAY:
			return "DT_PREINIT_ARRAY";
		case DT_PREINIT_ARRAYSZ:
			return "DT_PREINIT_ARRAYSZ";
		case DT_MAXPOSTAGS:
			return "Number of positive dynamic array tag values (DT_MAXPOSTAGS)";
		case 0x6ffffef5:
			return "DT_GNU_HASH";
		case 0x6ffffff0:
			return "DT_VERSYM";
		case 0x6ffffff9:
			return "DT_RELACOUNT";
		case 0x6ffffffe:
			return "DT_VERNEED";
		case 0x6fffffff:
			return "DT_VERNEEDNUM";
		default:
			break;
	}

	if(dynamicTag >= DT_LOOS && dynamicTag <= DT_HIOS)
	{
		return "OS-specific";
	}
	else if(dynamicTag >= DT_LOPROC && dynamicTag <= DT_HIPROC)
	{
		return "Processor-specific";
	}

	return "";
}

/**
 * Create new relocation with given parameters
 * @param name Name of symbol being relocated
 * @param offset Offset of symbol being relocated
 * @param value Value of relocation
 * @param type Type of relocation
 * @param addend Relocation addend
 * @param calc Calculated value
 * @return new relocation
 */
Relocation createRelocation(const std::string &name, std::uint64_t offset,
	std::uint64_t value, std::uint32_t type, std::int64_t addend, std::int64_t calc)
{
	Relocation relocation;

	relocation.setSymbolName(name);
	relocation.setOffset(offset);
	relocation.setSymbolValue(value);
	relocation.setRelocationType(type);
	relocation.setAddend(addend);
	relocation.setCalculatedValue(calc);

	return relocation;
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToInputFile Path to input file
 * @param finfo Instance of class for storing information about file
 * @param searchPar Parameters for detection of used compiler (or packer)
 * @param loadFlags Load flags
 */
ElfDetector::ElfDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags) :
	FileDetector(pathToInputFile, finfo, searchPar, loadFlags)
{
	fileParser = elfParser = std::make_shared<ElfWrapper>(fileInfo.getPathToFile(), loadFlags);
	loaded = elfParser->isInValidState();
}

/**
 * Destructor
 */
ElfDetector::~ElfDetector()
{

}

/**
 * Get file version
 */
void ElfDetector::getFileVersion()
{
	fileInfo.setFileVersion(numToStr(elfParser->getFileVersion()));
}

/**
 * Get information about file header
 */
void ElfDetector::getFileHeaderInfo()
{
	fileInfo.setFileHeaderVersion(numToStr(elfParser->getFileHeaderVersion()));
	fileInfo.setFileHeaderSize(elfParser->getFileHeaderSize());
}

/**
 * Get information about file flags
 */
void ElfDetector::getFlags()
{
	fileInfo.setFileFlagsSize(ELF_32_FLAGS_SIZE);
	fileInfo.setFileFlags(elfParser->getFileFlags());
}

/**
 * Get information about file segments
 */
void ElfDetector::getSegments()
{
	const unsigned long long noOfSegments = elfParser->getDeclaredNumberOfSegments();
	fileInfo.setNumberOfDeclaredSegments(noOfSegments);
	fileInfo.setSegmentTableOffset(elfParser->getSegmentTableOffset());
	fileInfo.setSegmentTableEntrySize(elfParser->getSegmentTableEntrySize());
	fileInfo.setSegmentTableSize(elfParser->getSegmentTableSize());

	const unsigned long long flagMasks[] = {PF_R, PF_W, PF_X, PF_MASKOS, PF_MASKPROC};
	const auto flagsSize = arraySize(flagMasks);
	const std::string flagsDesc[flagsSize] = {"readable", "writable", "executable", "operating system-specific flags", "processor-specific flags"};
	const std::string flagsAbbv[flagsSize] = {"r", "w", "x", "o", "p"};
	unsigned long long flags;
	FileSegment fseg;
	fseg.setFlagsSize(ELF_32_FLAGS_SIZE);

	for(unsigned long long i = 0; i < noOfSegments; ++i)
	{
		const auto *seg = elfParser->getFileSegment(i);
		if(!seg)
		{
			continue;
		}
		fseg.setType(getSegmentType(seg));
		fseg.setIndex(seg->get_index());
		fseg.setOffset(seg->get_offset());
		fseg.setVirtualAddress(seg->get_virtual_address());
		fseg.setPhysicalAddress(seg->get_physical_address());
		fseg.setSizeInFile(seg->get_file_size());
		fseg.setSizeInMemory(seg->get_memory_size());
		fseg.setAlignment(seg->get_align());
		flags = seg->get_flags();
		fseg.setFlags(flags);
		fseg.clearFlagsDescriptors();
		for(unsigned long long j = 0; j < flagsSize; ++j)
		{
			if(flags & flagMasks[j])
			{
				fseg.addFlagsDescriptor(flagsDesc[j], flagsAbbv[j]);
			}
		}
		const auto *auxSeg = elfParser->getSegment(seg->get_index());
		if(auxSeg)
		{
			fseg.setCrc32(auxSeg->getCrc32());
			fseg.setMd5(auxSeg->getMd5());
			fseg.setSha256(auxSeg->getSha256());
		}
		fileInfo.addSegment(fseg);
	}
}

/**
 * Get information about symbol table
 */
void ElfDetector::getSymbolTable()
{
	// specific analysis for ARM architecture
	unsigned long long machineType;
	const bool isArm = elfParser->getMachineCode(machineType) && machineType == EM_ARM;
	SpecialInformation specInfo("instruction set", "iset");

	Symbol symbol;
	for (const auto& st : elfParser->getSymbolTables())
	{
		SymbolTable symbolTable;
		symbolTable.setNumberOfDeclaredSymbols(st->getNumberOfSymbols());
		symbolTable.setTableName(st->getName());

		for (const auto& sym : *st)
		{
			auto elfSym = std::static_pointer_cast<ElfSymbol>(sym);

			unsigned long long sectionLink = 0, address = 0, size = 0;
			elfSym->getLinkToSection(sectionLink);
			elfSym->getAddress(address);
			elfSym->getSize(size);

			symbol.setIndex(elfSym->getIndex());
			symbol.setName(elfSym->getName());
			symbol.setType(getSymbolType(elfSym->getElfType()));
			symbol.setBind(getSymbolBind(elfSym->getElfBind()));
			symbol.setOther(getSymbolOtherInformation(elfSym->getElfOther()));
			symbol.setValue(address);
			symbol.setSize(size);
			symbol.setLinkToSection(getSymbolLinkToSection(sectionLink));
			symbolTable.addSymbol(symbol);

			if(isArm)
			{
				if(elfSym->getElfType() == STT_FUNC)
				{
					(address & 1) ? specInfo.addValue("THUMB") : specInfo.addValue("ARM");
				}
				else
				{
					specInfo.addValue("");
				}
			}
		}

		if(isArm)
		{
			symbolTable.addSpecialInformation(specInfo);
		}
		fileInfo.addSymbolTable(symbolTable);
	}
}

/**
 * Get information about relocation table
 * @param sec File section
 */
void ElfDetector::getRelocationTable(const ELFIO::section *sec)
{
	relocation_section_accessor *relocations = elfParser->getRelocationTable(sec->get_index());
	if(!relocations)
	{
		return;
	}
	RelocationTable relocationTable;
	Relocation relocation;
	std::string symbolName;
	Elf64_Addr offset = 0, symbolValue = 0;
	Elf_Word relType = 0;
	Elf_Sxword addend = 0, calcValue = 0;
	const ELFIO::section *otherSec;

	relocationTable.setNumberOfDeclaredRelocations(relocations->get_entries_num());
	unsigned long long secLink = sec->get_link();
	relocationTable.setAssociatedSymbolTableIndex(secLink);
	if((otherSec = elfParser->getFileSection(secLink)))
	{
		relocationTable.setAssociatedSymbolTableName(otherSec->get_name());
	}
	secLink = sec->get_info();
	relocationTable.setAppliesSectionIndex(secLink);
	if((otherSec = elfParser->getFileSection(secLink)))
	{
		relocationTable.setAppliesSectionName(otherSec->get_name());
	}

	for(unsigned long long i = 0, e = relocations->get_loaded_entries_num(); i < e; ++i)
	{
		if (elfParser->isMips() && elfParser->getElfClass() == ELFCLASS64)
		{
			Elf_Word index = 0;
			Elf64_Byte value = 0;
			Elf64_Byte type[3] = {0, 0, 0};
			relocations->mips64_get_entry(i, offset, index, value, type[2], type[1], type[0], addend);

			Elf_Xword size;
			Elf_Half section;
			unsigned char bind, symbolType, other;
			auto* symbols = elfParser->getSymbolTable(sec->get_link());
			if (symbols)
			{
				symbols->get_symbol(index, symbolName, symbolValue, size, bind, symbolType, section, other);
			}
			else
			{
				symbolName = std::string();
				symbolValue = 0;
			}

			for (int i = 0; i < 3; ++i)
			{
				if (type[i])
				{
					relocation = createRelocation(symbolName, offset, symbolValue, type[i], addend, calcValue);
					relocationTable.addRelocation(relocation);
				}
			}
		}
		else
		{
			relocations->get_entry(i, offset, symbolValue, symbolName, relType, addend, calcValue);
			relocation = createRelocation(symbolName, offset, symbolValue, relType, addend, calcValue);
			relocationTable.addRelocation(relocation);
		}
	}
	relocationTable.setTableName(sec->get_name());
	fileInfo.addRelocationTable(relocationTable);
	delete relocations;
}

/**
 * Get information about dynamic section
 * @param sec File section
 */
void ElfDetector::getDynamicSection(const ELFIO::section *sec)
{
	const dynamic_section_accessor *dynamic = elfParser->getDynamicSection(sec->get_index());
	if(!dynamic)
	{
		return;
	}
	DynamicSection dynamicSection;
	DynamicEntry dynamicEntry;
	std::string str;
	Elf_Xword tag = 0, dynValue = 0;

	dynamicSection.setNumberOfDeclaredEntries(dynamic->get_entries_num());
	const unsigned long long flagMasks[] = {DF_ORIGIN, DF_SYMBOLIC, DF_TEXTREL, DF_BIND_NOW, DF_STATIC_TLS};
	const unsigned long long flagsSize = arraySize(flagMasks);
	const std::string flagsDesc[flagsSize] = {"DF_ORIGIN", "DF_SYMBOLIC", "DF_TEXTREL", "DF_BIND_NOW",
												"file contains code using a static thread-local storage scheme (DF_STATIC_TLS)"};
	const std::string flagsAbbv[flagsSize] = {"o", "s", "r", "b", "t"};

	for(unsigned long long i = 0, e = dynamic->get_loaded_entries_num(); i < e; ++i)
	{
		dynamic->get_entry(i, tag, dynValue, str);
		dynamicEntry.setValue(dynValue);
		dynamicEntry.setDescription(str);
		dynamicEntry.setType(getDynamicEntryType(tag));
		dynamicEntry.clearFlagsDescriptors();
		if(tag == DT_FLAGS)
		{
			dynamicEntry.setFlagsSize(ELF_64_FLAGS_SIZE);
			dynamicEntry.setFlags(dynValue);
			for(unsigned long long j = 0; j < flagsSize; ++j)
			{
				if(dynValue & flagMasks[j])
				{
					dynamicEntry.addFlagsDescriptor(flagsDesc[j], flagsAbbv[j]);
				}
			}
		}
		else
		{
			dynamicEntry.setFlagsSize(0);
			dynamicEntry.setFlags(0);
		}
		dynamicSection.addEntry(dynamicEntry);
	}
	dynamicSection.setSectionName(sec->get_name());
	fileInfo.addDynamicSection(dynamicSection);
	delete dynamic;
}

/**
 * Get information about sections
 */
void ElfDetector::getSections()
{
	const unsigned long long storedNoOfSections = elfParser->getNumberOfSections();
	const unsigned long long declNoOfSections = elfParser->getDeclaredNumberOfSections();
	fileInfo.setNumberOfDeclaredSections(declNoOfSections);
	fileInfo.setSectionTableOffset(elfParser->getSectionTableOffset());
	fileInfo.setSectionTableEntrySize(elfParser->getSectionTableEntrySize());
	fileInfo.setSectionTableSize(elfParser->getSectionTableSize());

	const unsigned long long flagMasks[] = {SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_MERGE, SHF_STRINGS, SHF_INFO_LINK, SHF_LINK_ORDER,
											SHF_OS_NONCONFORMING, SHF_GROUP, SHF_TLS, SHF_COMPRESSED, SHF_MASKOS, SHF_MASKPROC};
	const unsigned long long flagsSize = arraySize(flagMasks);
	unsigned long long flags;
	const std::string flagsDesc[flagsSize] = {"writable", "allocated", "executable", "merged data", "section consists of null-terminated strings",
												"SHF_INFO_LINK", "SHF_LINK_ORDER", "section requires special operating system-specific processing beyond the standard linking rules",
												"section is a member of a section group", "thread-local storage", "section containing compressed data",
												"operating system-specific flags", "processor-specific flags"};
	const std::string flagsAbbv[flagsSize] = {"w", "a", "x", "m", "n",
												"i", "l", "s",
												"g", "t", "c", "o", "p"};
	FileSection fs;
	fs.setFlagsSize(ELF_32_FLAGS_SIZE);

	for(unsigned long long i = 0; i < storedNoOfSections; ++i)
	{
		const auto *sec = elfParser->getFileSection(i);
		if(!sec)
		{
			continue;
		}
		fs.setName(sec->get_name());
		fs.setType(getSectionType(sec));
		fs.setIndex(sec->get_index());
		fs.setOffset(sec->get_offset());
		fs.setSizeInFile(sec->get_size());
		fs.setEntrySize(sec->get_entry_size());
		fs.setStartAddress(sec->get_address());
		fs.setMemoryAlignment(sec->get_addr_align());
		fs.setLinkToAnotherSection(sec->get_link());
		fs.setExtraInfo(sec->get_info());
		flags = sec->get_flags();
		fs.setFlags(flags);
		fs.clearFlagsDescriptors();
		for(unsigned long long j = 0; j < flagsSize; ++j)
		{
			if(flags & flagMasks[j])
			{
				fs.addFlagsDescriptor(flagsDesc[j], flagsAbbv[j]);
			}
		}
		const auto *auxSec = elfParser->getSection(sec->get_index());
		if(auxSec)
		{
			fs.setCrc32(auxSec->getCrc32());
			fs.setMd5(auxSec->getMd5());
			fs.setSha256(auxSec->getSha256());
		}
		fileInfo.addSection(fs);
		switch(sec->get_type())
		{
			//case SHT_SYMTAB:
			//case SHT_DYNSYM:
			//	getSymbolTable(sec);
			//	break;
			case SHT_RELA:
			case SHT_REL:
				getRelocationTable(sec);
				break;
			case SHT_DYNAMIC:
				getDynamicSection(sec);
				break;
			default:
				break;
		}
	}
}

/**
 * Get information about operating system or ABI extension
 */
void ElfDetector::getOsAbiInfo()
{
	std::string abi;
	const unsigned long long osAbi = elfParser->getOsOrAbi(), abiVersion = elfParser->getOsOrAbiVersion();
	switch(osAbi)
	{
		case ELFOSABI_NONE:
			abi = "No extensions or unspecified";
			break;
		case ELFOSABI_LINUX:
			abi = "GNU";
			break;
		case ELFOSABI_HPUX:
			abi = "Hewlett-Packard HP-UX";
			break;
		case ELFOSABI_NETBSD:
			abi = "NetBSD";
			break;
		case ELFOSABI_SOLARIS:
			abi = "Sun Solaris";
			break;
		case ELFOSABI_AIX:
			abi = "AIX";
			break;
		case ELFOSABI_IRIX:
			abi = "IRIX";
			break;
		case ELFOSABI_FREEBSD:
			abi = "FreeBSD";
			break;
		case ELFOSABI_TRU64:
			abi = "Compaq TRU64 UNIX";
			break;
		case ELFOSABI_MODESTO:
			abi = "Novell Modesto";
			break;
		case ELFOSABI_OPENBSD:
			abi = "Open BSD";
			break;
		case ELFOSABI_OPENVMS:
			abi = "Open VMS";
			break;
		case ELFOSABI_NSK:
			abi = "Hewlett-Packard Non-Stop Kernel";
			break;
		case ELFOSABI_AROS:
			abi = "Amiga Research OS";
			break;
		case ELFOSABI_FENIXOS:
			abi = "The FenixOS highly scalable multi-core OS";
			break;
		default:
			break;
	}

	if(osAbi >= 64 && osAbi <= 255)
	{
		abi = "Architecture-specific ABI extension";
	}
	fileInfo.setOsAbi(abi);
	fileInfo.setOsAbiVersion(numToStr(abiVersion));
}

void ElfDetector::detectFileClass()
{
	switch(elfParser->getElfClass())
	{
		case ELFCLASS32:
			fileInfo.setFileClass("32-bit");
			break;
		case ELFCLASS64:
			fileInfo.setFileClass("64-bit");
			break;
		default:;
	}
}

void ElfDetector::detectArchitecture()
{
	unsigned long long machineType = 0;
	if(!elfParser->getMachineCode(machineType))
	{
		return;
	}
	std::string result;

	// Check the newest version: http://www.sco.com/developers/gabi/latest/ch4.eheader.html#e_machine
	switch(machineType)
	{
		// x86/x64/ia64-based
		case EM_386:
		case EM_486:
			result = "x86 (or later and compatible)";
			break;
		case EM_X86_64:
			result = "x86-64";
			break;
		case EM_IA_64:
			result = "IA-64 (Intel Itanium)";
			break;
		case EM_860:
			result = "Intel 80860";
			break;
		case EM_960:
			result = "Intel 80960";
			break;

		// Intel (other)
		case EM_8051:
			result = "Intel 8051 and variants";
			break;
		case EM_L1OM:
			result = "Intel L1OM";
			break;

		// MIPS
		// The official e_machine number for MIPS is now #8, regardless of
		// endianness. The second number (#10) will be deprecated later.
		case EM_MIPS:
			result = "MIPS (MIPS I Architecture)";
			break;
		case EM_MIPS_RS3_LE:
			result = "MIPS (RS3000 - little endian)";
			break;
		case EM_MIPS_X:
			result = "MIPS (Stanford MIPS-X)";
			break;

		// ARM
		case EM_ARM:
			result = "ARM";
			break;
		case EM_AARCH64:
			result = "ARM AARCH64";
			break;

		// nVidia
		case EM_CUDA:
			result = "NVIDIA CUDA architecture";
			break;

		// Hitachi
		case EM_SH:
			/* SuperH */
			result = "Hitachi SH";
			break;
		case EM_H8_300:
			result = "Hitachi H8/300";
			break;
		case EM_H8_300H:
			result = "Hitachi H8/300H";
			break;
		case EM_H8S:
			result = "Hitachi H8S";
			break;
		case EM_H8_500:
			result = "Hitachi H8/500";
			break;

		// Renesas
		case EM_M16C:
			result = "Renesas M16C series microprocessors";
			break;
		case EM_M32C:
			result = "Renesas M32C series microprocessors";
			break;
		case EM_R32C:
			result = "Renesas R32C series microprocessors";
			break;
		case EM_RX:
			result = "Renesas RX family";
			break;

		// Power PC
		case EM_PPC:
			result = "PowerPC";
			break;
		case EM_PPC64:
			result = "PPC64 (PowerPC 64-bit)";
			break;

		// Alpha
		case EM_OLD_ALPHA:
		case 0x9026:
			result = "ALPHA";
			break;

		// Motorola
		case EM_68K:
			result = "Motorola 68000";
			break;
		case EM_88K:
			result = "Motorola 88000";
			break;
		case EM_MCORE:
			result = "Motorola RCE (or Fujitsu MMA)";
			break;
		case EM_COLDFIRE:
			result = "Motorola ColdFire";
			break;
		case EM_68HC12:
			result = "Motorola M68HC12";
			break;
		case EM_STARCORE:
			result = "Motorola Star*Core processor";
			break;
		case EM_68HC16:
			result = "Motorola MC68HC16 Microcontroller";
			break;
		case EM_68HC11:
			result = "Motorola MC68HC11 Microcontroller";
			break;
		case EM_68HC08:
			result = "Motorola MC68HC08 Microcontroller";
			break;
		case EM_68HC05:
			result = "Motorola MC68HC05 Microcontroller";
			break;
		case EM_XGATE:
			result = "Motorola XGATE embedded processor";
			break;

		// STMicroelectronics
		case EM_ST100:
			result = "STMicroelectronics ST100 processor";
			break;
		case EM_ST9PLUS:
			result = "STMicroelectronics ST9+ 8/16 bit microcontroller";
			break;
		case EM_ST7:
			result = "STMicroelectronics ST7 8-bit microcontroller";
			break;
		case EM_ST19:
			result = "STMicroelectronics ST19 8-bit microcontroller";
			break;
		case EM_ST200:
			result = "STMicroelectronics ST200 microcontroller";
			break;
		case EM_MMDSP_PLUS:
			result = "STMicroelectronics 64bit VLIW Data Signal Processor";
			break;
		case EM_STXP7X:
			result = "STMicroelectronics STxP7x family";
			break;
		case EM_STM8:
			result = "STMicroeletronics STM8 8-bit microcontroller";
			break;

		// IBM
		case EM_S370:
			result = "IBM System/370 Processor (Amdahl)";
			break;
		case 11:
			result = "IBM RS6000";
			break;
		case EM_S390:
		case 0xa390:
			result = "IBM System/390 Processor";
			break;

		// Fujitsu
		case EM_VPP550:
			result = "Fujitsu VPP500";
			break;
		case EM_FR20:
			result = "Fujitsu FR20";
			break;
		case EM_MMA:
			result = "Fujitsu MMA Multimedia Accelerator";
			break;
		case EM_FR30:
			result = "Fujitsu FR30";
			break;
		case EM_F2MC16:
			result = "Fujitsu F2MC16";
			break;

		// SPARC
		case EM_SPARC:
			result = "SPARC";
			break;
		case EM_SPARC32PLUS:
			result = "Enhanced instruction set SPARC (SPARC32PLUS)";
			break;
		case EM_SPARCV9:
			result = "SPARC (v9)";
			break;

		// Siemens
		case EM_TRICORE:
			result = "Siemens TriCore embedded processor";
			break;
		case EM_PCP:
			result = "Siemens PCP";
			break;
		case EM_FX66:
			result = "Siemens FX66 microcontroller";
			break;

		// Sony
		case EM_NCPU:
			result = "Sony nCPU embedded RISC processor";
			break;
		case EM_PDSP:
			result = "Sony DSP Processor";
			break;

		// Mitsubishi
		case EM_D10V:
			result = "Mitsubishi D10V";
			break;
		case EM_D30V:
			result = "Mitsubishi D30V";
			break;
		case EM_M32R:
			result = "Mitsubishi M32R";
			break;

		// Matsushita
		case EM_MN10300:
			result = "Matsushita MN10300";
			break;
		case EM_MN10200:
			result = "Matsushita MN10200";
			break;

		// Tilera
		case EM_TILE64:
			result = "Tilera TILE64 multicore architecture family";
			break;
		case EM_TILEPRO:
			result = "Tilera TILEPro multicore architecture family";
			break;
		case 191:
			result = "Tilera TILE-Gx";
			break;

		// PDP
		case EM_PDP10:
			result = "Digital Equipment Corp. PDP-10";
			break;
		case EM_PDP11:
			result = "Digital Equipment Corp. PDP-11";
			break;

		// Infineon
		case EM_JAVELIN:
			result = "Infineon Technologies 32-bit embedded processor";
			break;
		case EM_C166:
			result = "Infineon C16x/XC16x processor";
			break;
		case EM_SLE9X:
			result = "Infineon Technologies SLE9X core";
			break;

		// Atmel
		case EM_AVR:
			result = "Atmel AVR 8-bit microcontroller";
			break;
		case EM_AVR32:
			result = "Atmel Corporation 32-bit microprocessor family";
			break;

		// National Semiconductor
		case EM_NS32K:
			result = "National Semiconductor 32000 series";
			break;
		case EM_CR:
			result = "National Semiconductor CompactRISC";
			break;
		case EM_CRX:
			result = "National Semiconductor CRX";
			break;
		case EM_CR16:
			result = "National Semiconductor CompactRISC 16-bit processor";
			break;

		// Freescale
		case EM_CE:
			result = "Freescale Communication Engine RISC core";
			break;
		case EM_RS08:
			result = "Freescale RS08 embedded processor";
			break;
		case EM_ETPU:
			result = "Freescale Extended Time Processing Unit";
			break;

		// Sunplus
		case EM_SCORE:
			result = "Sunplus Score / Sunplus S+core7 RISC processor";
			break;

		// Videocore
		case EM_VIDEOCORE:
			result = "Alphamosaic VideoCore processor";
			break;
		case EM_VIDEOCORE3:
			result = "Broadcom VideoCore III processor";
			break;

		// Texas Instruments
		case EM_TI_C6000:
			result = "Texas Instruments TMS320C6000 DSP family";
			break;
		case EM_TI_C2000:
			result = "Texas Instruments TMS320C2000 DSP family";
			break;
		case EM_TI_C5500:
			result = "Texas Instruments TMS320C55x DSP family";
			break;

		// Microblaze
		case EM_MICROBLAZE:
			result = "Xilinx MicroBlaze RISC soft processor core";
			break;
		case 0xbaab:
			result = "MicroBlaze";
			break;

		// Cyan Technology
		case EM_ECOG2:
			result = "Cyan Technology eCOG2 microprocessor";
			break;
		case EM_ECOG1:
			result = "Cyan Technology eCOG1X family";
			break;
		case EM_ECOG16:
			result = "Cyan Technology eCOG16 family";
			break;

		// New Japan Radio
		case EM_DSP24:
			result = "New Japan Radio (NJR) 24-bit DSP Processor";
			break;
		case EM_XIMO16:
			result = "New Japan Radio (NJR) 16-bit DSP Processor";
			break;

		// META
		case EM_METAG:
			result = "Imagination Technologies META processor architecture";
			break;

		// Other
		case EM_SPU:
			result = "SPU (Sony/Toshiba/IBM)";
			break;
		case EM_M32:
			result = "AT&T WE32100";
			break;
		case EM_PARISC:
			result = "Hewlett-Packard PA-RISC";
			break;
		case 16:
			result = "nCUBE";
			break;
		case EM_V800:
			result = "NEC V800";
			break;
		case EM_RH32:
			result = "TRW RH-32";
			break;
		case EM_ARC:
			result = "Argonaut RISC Core, Argonaut Technologies Inc.";
			break;
		case EM_NDR1:
			result = "Denso NDR1 microprocessor";
			break;
		case EM_ME16:
			result = "Toyota ME16 processor";
			break;
		case EM_TINYJ:
			result = "Advanced Logic Corp. TinyJ embedded processor family";
			break;
		case EM_SVX:
			result = "Silicon Graphics SVx";
			break;
		case EM_VAX:
			result = "Digital VAX";
			break;
		case EM_CRIS:
			result = "Axis Communications 32-bit embedded processor";
			break;
		case EM_FIREPATH:
			result = "Element 14 64-bit DSP Processor";
			break;
		case EM_ZSP:
			result = "LSI Logic 16-bit DSP Processor";
			break;
		case EM_MMIX:
			result = "MMIX - Donald Knuth's educational 64-bit processor";
			break;
		case EM_HUANY:
			result = "Harvard University machine-independent object files";
			break;
		case EM_PRISM:
			result = "SiTera Prism";
			break;
		case EM_V850:
			result = "NEC v850";
			break;
		case EM_PJ:
			result = "picoJava";
			break;
		case EM_OPENRISC:
			result = "OpenRISC 32-bit embedded processor";
			break;
		case EM_ARC_A5:
			result = "ARC Cores Tangent-A5";
			break;
		case EM_XTENSA:
			result = "Tensilica Xtensa Architecture";
			break;
		case EM_TMM_GPP:
			result = "Thompson Multimedia General Purpose Processor";
			break;
		case EM_TPC:
			result = "Tenor Network TPC processor";
			break;
		case EM_SNP1K:
			result = "Trebia SNP 1000 processor";
			break;
		case EM_IP2K:
			result = "Ubicom IP2022 micro controller";
			break;
		case EM_MAX:
			result = "MAX Processor";
			break;
		case EM_MSP430:
			result = "TI msp430 micro controller";
			break;
		case EM_BLACKFIN:
			result = "Analog Devices Blackfin";
			break;
		case EM_SE_C33:
			result = "S1C33 Family of Seiko Epson processors";
			break;
		case EM_SEP:
			result = "Sharp embedded microprocessor";
			break;
		case EM_ARCA:
			result = "Arca RISC Microprocessor";
			break;
		case EM_UNICORE:
			result = "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University";
			break;
		case EM_EXCESS:
			result = "eXcess: 16/32/64-bit configurable embedded CPU";
			break;
		case EM_DXP:
			result = "Icera Semiconductor Inc. Deep Execution Processor";
			break;
		case EM_ALTERA_NIOS2:
			result = "Altera Nios II soft-core processor";
			break;
		case EM_DSPIC30F:
			result = "Microchip Technology dsPIC30F Digital Signal Controller";
			break;
		case EM_TSK3000:
			result = "Altium TSK3000 core";
			break;
		case EM_LATTICEMICO32:
			result = "RISC processor for Lattice FPGA architecture";
			break;
		case EM_SE_C17:
			result = "Seiko Epson C17 family";
			break;
		case EM_CYPRESS_M8C:
			result = "Cypress M8C microprocessor";
			break;
		case EM_TRIMEDIA:
			result = "NXP Semiconductors TriMedia architecture family";
			break;
		case EM_QDSP6:
			result = "QUALCOMM DSP6 Processor";
			break;
		case EM_NDS32:
			result = "Andes Technology compact code size embedded RISC processor family";
			break;
		case EM_MAXQ30:
			result = "Dallas Semiconductor MAXQ30 Core Micro-controllers";
			break;
		case EM_MANIK:
			result = "M2000 Reconfigurable RISC Microprocessor";
			break;
		case EM_CRAYNV2:
			result = "Cray Inc. NV2 vector architecture";
			break;
		case EM_MCST_ELBRUS:
			result = "MCST Elbrus general purpose hardware architecture";
			break;
		case 0x18ad:
			result = "AVR32";
			break;
		case 0x3426:
		case 0x8472:
			result = "OpenRISC";
			break;
		case EM_NONE:
			if(elfParser->isWiiPowerPc())
			{
				result = "PowerPC";
			}
			break;
		default:;
	}
	if(result.empty())
	{
		std::stringstream sstm;
		sstm << "Unknown machine type (" << machineType << ")";
		result = sstm.str();
	}
	fileInfo.setTargetArchitecture(result);
}

void ElfDetector::detectFileType()
{
	std::string fileType;
	const unsigned long long type = elfParser->getTypeOfFile();
	switch(type)
	{
		case ET_EXEC:
			fileType = "Executable file";
			break;
		case ET_DYN:
			fileType = "DLL";
			break;
		case ET_REL:
			fileType = "Relocatable file";
			break;
		case ET_CORE:
			fileType = "Core file";
			break;
		default:
			break;
	}

	if(type >= ET_LOOS && type <= ET_HIOS)
	{
		fileType = "Operation system-specific file";
	}
	else if(type >= ET_LOPROC && type <= ET_HIPROC)
	{
		fileType = "Processor-specific file";
	}

	fileInfo.setFileType(fileType);
}

void ElfDetector::getAdditionalInfo()
{
	getFileVersion();
	getFileHeaderInfo();
	getOsAbiInfo();
	getFlags();
	getSegments();
	getSections();
	getSymbolTable();
}

/**
 * Pointer to detector is dynamically allocated and must be released (otherwise there is a memory leak)
 * More detailed description of this method is in the super class
 */
retdec::cpdetect::CompilerDetector* ElfDetector::createCompilerDetector() const
{
	return new ElfCompiler(*elfParser, cpParams, fileInfo.toolInfo);
}

} // namespace fileinfo
