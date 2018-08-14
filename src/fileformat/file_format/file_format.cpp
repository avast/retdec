/**
 * @file src/fileformat/file_format/file_format.cpp
 * @brief Methods of FileFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <climits>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>

#include <pelib/PeLibInc.h>

#include "retdec/crypto/crypto.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/file_io.h"
#include "retdec/utils/string.h"
#include "retdec/utils/system.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/fileformat/types/strings/character_iterator.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/file_io.h"
#include "retdec/fileformat/utils/other.h"

using namespace retdec::utils;
using namespace PeLib;

namespace retdec {
namespace fileformat {

namespace
{

const std::size_t DefaultMinStringLength = 4;

/**
 * Decide whether @a offset is part of region (section or segment) @a newRegion
 * @param actualRegion Region to which is offset currently assigned (may be @c nullptr)
 * @param newRegion Currently examined region
 * @param offset Offset in file
 * @return @c true if @a offset is in range of @a newRegion and @a actualRegion is
 *    @c nullptr or @a newRegion is subset of @a actualRegion, @c false otherwise
 */
bool isOffsetFromRegion(const SecSeg *actualRegion, const SecSeg *newRegion, std::size_t offset)
{
	if(!newRegion)
	{
		return false;
	}

	const auto newRegionSize = newRegion->getSizeInFile();
	const auto actualRegionSize = (actualRegion ? actualRegion->getSizeInFile() : 0);
	if(offset >= newRegion->getOffset() && offset - newRegion->getOffset() < newRegionSize)
	{
		if(!actualRegion || (newRegion->getOffset() > actualRegion->getOffset() ||
			(newRegion->getOffset() == actualRegion->getOffset() && newRegionSize < actualRegionSize)))
		{
			return true;
		}
	}

	return false;
}

/**
 * Decide whether @a address is part of region (section or segment) @a newRegion
 * @param actualRegion Region to which is address currently assigned (may be @c nullptr)
 * @param newRegion Currently examined region
 * @param address Address in memory
 * @return @c true if @a address is in range of @a newRegion and @a actualRegion is
 *    @c nullptr or @a newRegion is subset of @a actualRegion, @c false otherwise
 */
bool isAddressFromRegion(const SecSeg *actualRegion, const SecSeg *newRegion, std::size_t address)
{
	if(!newRegion)
	{
		return false;
	}

	unsigned long long newRegionSize;
	if(!newRegion->getSizeInMemory(newRegionSize))
	{
		newRegionSize = newRegion->getSizeInFile();
	}

	unsigned long long actualRegionSize = 0;
	if(actualRegion)
	{
		if(!actualRegion->getSizeInMemory(actualRegionSize))
		{
			actualRegionSize = actualRegion->getSizeInFile();
		}
	}

	if(newRegion->getMemory() && address >= newRegion->getAddress() && address - newRegion->getAddress() < newRegionSize)
	{
		if(!actualRegion || (newRegion->getAddress() > actualRegion->getAddress() ||
			(newRegion->getAddress() == actualRegion->getAddress() && newRegionSize < actualRegionSize)))
		{
			return true;
		}
	}

	return false;
}

} // anonymous namespace

/**
 * Constructor
 * @param inputStream Stream which represents input file
 * @param loadFlags Load flags
 */
FileFormat::FileFormat(std::istream &inputStream, LoadFlags loadFlags) : loadedBytes(&bytes),
	loadFlags(loadFlags), fileStream(inputStream), _ldrErrInfo()
{
	stateIsValid = !inputStream.fail();
	init();
}

/**
 * Constructor
 * @param pathToFile Path to input file
 * @param loadFlags Load flags
 */
FileFormat::FileFormat(std::string pathToFile, LoadFlags loadFlags) : loadedBytes(&bytes),
	loadFlags(loadFlags), filePath(pathToFile), fileStream(auxStream), _ldrErrInfo()
{
	auxStream.open(filePath, std::ifstream::binary);
	stateIsValid = auxStream.is_open();
	init();
}

/**
 * Destructor
 */
FileFormat::~FileFormat()
{
	clear();
}

/**
 * Init internal structures
 */
void FileFormat::init()
{
	importTable = nullptr;
	exportTable = nullptr;
	resourceTable = nullptr;
	resourceTree = nullptr;
	richHeader = nullptr;
	pdbInfo = nullptr;
	certificateTable = nullptr;
	elfCoreInfo = nullptr;
	fileFormat = Format::UNDETECTABLE;
	stateIsValid = readFile(fileStream, bytes) && stateIsValid;
	if (getLoadFlags() & LoadFlags::NO_FILE_HASHES)
	{
		crc32.clear();
		md5.clear();
		sha256.clear();
	}
	else
	{
		crc32 = retdec::crypto::getCrc32(bytes.data(), bytes.size());
		md5 = retdec::crypto::getMd5(bytes.data(), bytes.size());
		sha256 = retdec::crypto::getSha256(bytes.data(), bytes.size());
	}
	initStream();
}

/**
 * Initialize internal state of member @c fileStream
 */
void FileFormat::initStream()
{
	fileStream.clear();
	fileStream.seekg(0);
}

/**
 * Provides architecture information for formats which do not store such information eg. Intel HEX
 * @param derivedPtr Pointer to derived FileFormat class
 * @param arch Architecture information
 */
template<typename T> void FileFormat::initFormatArch(T derivedPtr, const retdec::config::Architecture &arch)
{
	if(!derivedPtr)
	{
		return;
	}

	derivedPtr->setBytesPerWord(arch.getByteSize());

	if(arch.isEndianLittle())
	{
		derivedPtr->setEndianness(Endianness::LITTLE);
	}
	else if(arch.isEndianBig())
	{
		derivedPtr->setEndianness(Endianness::BIG);
	}

	if(arch.isX86())
	{
		derivedPtr->setTargetArchitecture(Architecture::X86);
	}
	if(arch.isArmOrThumb())
	{
		derivedPtr->setTargetArchitecture(Architecture::ARM);
	}
	if(arch.isPpc())
	{
		derivedPtr->setTargetArchitecture(Architecture::POWERPC);
	}
	if(arch.isMips())
	{
		derivedPtr->setTargetArchitecture(Architecture::MIPS);
	}
	if(arch.isPic32())
	{
		derivedPtr->setTargetArchitecture(Architecture::MIPS);
	}
}

/**
 * @fn std::size_t FileFormat::initSectionTableHashOffsets()
 * Init offsets for calculation of section table hashes
 * @return Number of offsets in offsets vector after initialization
 */

/**
 * Clear all internal structures
 */
void FileFormat::clear()
{
	delete importTable;
	delete exportTable;
	delete resourceTable;
	delete resourceTree;
	delete richHeader;
	delete pdbInfo;
	delete certificateTable;
	delete elfCoreInfo;

	for(auto *item : sections)
	{
		delete item;
	}

	for(auto *item : segments)
	{
		delete item;
	}

	for(auto *item : symbolTables)
	{
		delete item;
	}

	for(auto *item : relocationTables)
	{
		delete item;
	}

	for(auto *item : dynamicTables)
	{
		delete item;
	}

	sections.clear();
	segments.clear();
	symbolTables.clear();
	relocationTables.clear();
	dynamicTables.clear();
}

/**
 * Compute hashes of section table. This method must be called after
 * sections are loaded.
 */
void FileFormat::computeSectionTableHashes()
{
	if (getLoadFlags() & LoadFlags::NO_VERBOSE_HASHES)
	{
		return;
	}

	if(!initSectionTableHashOffsets() || secHashInfo.empty())
	{
		return;
	}

	std::vector<unsigned char> data;

	for(std::size_t i = 0, e = sections.size(); i < e; ++i)
	{
		if(!sections[i])
		{
			continue;
		}
		auto baseOffset = getSectionTableOffset() + i * getSectionTableEntrySize();
		std::string actHashStr;
		if(std::all_of(secHashInfo.begin(), secHashInfo.end(),
			[&] (const auto &item)
			{
				std::string act;
				if(item.second && this->getNTBSOffset(baseOffset + item.first, act, item.second))
				{
					actHashStr += act;
					return true;
				}
				return false;
			}
		))
		{
			for(const auto c : actHashStr)
			{
				data.push_back(static_cast<unsigned char>(c));
			}
		}
	}

	if(!data.empty())
	{
		sectionCrc32 = retdec::crypto::getCrc32(data.data(), data.size());
		sectionMd5 = retdec::crypto::getMd5(data.data(), data.size());
		sectionSha256 = retdec::crypto::getSha256(data.data(), data.size());
	}
}

/**
 * Set pointer to loaded serialized bytes of input file. In binary file formats
 * (e.g. ELF, PE, COFF) it is not necessary to call this method. In text file
 * formats (e.g. Intel HEX) it is necessary to call this method.
 * @param lBytes Pointer to serialized bytes
 */
void FileFormat::setLoadedBytes(std::vector<unsigned char> *lBytes)
{
	loadedBytes = lBytes;
}

/**
 * If fileformat is Intel HEX or raw binary then it does not contain
 * critical information like architecture, endianness or word size.
 * However, fileformat users expect it to contain this information.
 * Therefore, this method needs to be called to set these critical information.
 * @param config Config information
 */
void FileFormat::initFromConfig(const retdec::config::Config& config)
{
	if(IntelHexFormat *ihex = dynamic_cast<IntelHexFormat*>(this))
	{
		initFormatArch(ihex, config.architecture);
	}
	else if(RawDataFormat *raw = dynamic_cast<RawDataFormat*>(this))
	{
		initFormatArch(raw, config.architecture);
		// Set section address
		Address tmpAddr = config.getSectionVMA();
		if(tmpAddr.isDefined())
		{
			raw->setBaseAddress(tmpAddr);
		}
		// Set entry point
		tmpAddr = config.getEntryPoint();
		if(tmpAddr.isDefined())
		{
			raw->setEntryPoint(tmpAddr);
		}
	}
}

/**
 * Load strings from data sections
 */
void FileFormat::loadStrings()
{
	if (!(getLoadFlags() & LoadFlags::DETECT_STRINGS))
		return;

	loadStrings(StringType::Ascii, 1);
	loadStrings(StringType::Wide, 2);

	// Sort and remove duplicates
	std::sort(strings.begin(), strings.end());
	auto endItr = std::unique(strings.begin(), strings.end());
	strings.erase(endItr, strings.end());
}

/**
 * Load strings of specified type and with specified character size.
 * @param type Type of the strings.
 * @param charSize Character size.
 */
void FileFormat::loadStrings(StringType type, std::size_t charSize)
{
	if (!sections.empty())
	{
		for (const auto* sec : sections)
		{
			if (!sec->isSomeData() && !sec->isDebug())
				continue;

			loadStrings(type, charSize, sec);
		}
	}
	else
	{
		for (const auto* seg : segments)
		{
			if (!seg->isSomeData() && !seg->isDebug())
				continue;

			loadStrings(type, charSize, seg);
		}
	}
}

void FileFormat::loadStrings(StringType type, std::size_t charSize, const SecSeg* secSeg)
{
	CharacterEndianness endian = isLittleEndian() ? CharacterEndianness::Little : CharacterEndianness::Big;

	for (auto begin = secSeg->getBytes().begin(), end = secSeg->getBytes().end(), itr = begin; itr != end;)
	{
		if (makeCharacterIterator(itr, begin, end, charSize).pointsToValidCharacter(endian))
		{
			auto stringBeginItr = makeCharacterIterator(itr, begin, end, charSize);
			auto stringDataEndItr = makeCharacterIterator(end, begin, end, charSize);
			auto stringEndItr = stringBeginItr + 1;
			while (stringEndItr != stringDataEndItr && stringEndItr.pointsToValidCharacter(endian))
				++stringEndItr;

			if (static_cast<std::size_t>(stringEndItr - stringBeginItr) >= DefaultMinStringLength)
				strings.emplace_back(type, secSeg->getOffset() + (itr - begin), secSeg->getName(), std::string{stringBeginItr, stringEndItr});

			itr = stringEndItr.getUnderlyingIterator();
		}
		else
			++itr;
	}
}

/**
 * Loads imphash from import table.
 */
void FileFormat::loadImpHash()
{
	if (!importTable || (loadFlags & LoadFlags::NO_VERBOSE_HASHES))
	{
		return;
	}

	importTable->computeHashes();
}

/**
 * Loads exphash from export table.
 */
void FileFormat::loadExpHash()
{
	if (!exportTable || (loadFlags & LoadFlags::NO_VERBOSE_HASHES))
	{
		return;
	}

	exportTable->computeHashes();
}

/**
 * Getter for state of instance
 * @return @c true if all is OK, @c false otherwise
 */
bool FileFormat::isInValidState() const
{
	return stateIsValid;
}

/**
 * Getter for load flags.
 * @return Load flags.
 */
LoadFlags FileFormat::getLoadFlags() const
{
	return loadFlags;
}

/**
 * Get section which is located at offset @a offset
 * @param offset Offset in file
 * @return @c Pointer to section which is located at offset @a offset or
 *    @c nullptr if there is no such section
 */
const Section* FileFormat::getSectionFromOffset(unsigned long long offset) const
{
	const Section *actSec = nullptr;

	for(const auto *item : sections)
	{
		if(isOffsetFromRegion(actSec, item, offset))
		{
			actSec = item;
		}
	}

	return actSec;
}

/**
 * Get segment which is located at offset @a offset
 * @param offset Offset in file
 * @return @c Pointer to segment which is located at offset @a offset or
 *    @c nullptr if there is no such segment
 */
const Segment* FileFormat::getSegmentFromOffset(unsigned long long offset) const
{
	const Segment *actSeg = nullptr;

	for(const auto *item : segments)
	{
		if(isOffsetFromRegion(actSeg, item, offset))
		{
			actSeg = item;
		}
	}

	return actSeg;
}

/**
 * Get section (preferentially) or segment (if no section) which is located at offset @a offset
 * @param offset Offset in file
 * @return @c Pointer to section or segment which is located at offset @a offset or
 *    @c nullptr if there is no such section or segment
 */
const SecSeg* FileFormat::getSectionOrSegmentFromOffset(unsigned long long offset) const
{
	const SecSeg *ret = getSectionFromOffset(offset);
	if(!ret)
	{
		ret = getSegmentFromOffset(offset);
	}

	return ret;
}

/**
 * Test if the given offset in valid section or segment
 * @param offset Offset to test
 * @return @c true if offset is valid, @c false otherwise
 */
bool FileFormat::haveSectionOrSegmentOnOffset(unsigned long long offset) const
{
	return getSectionOrSegmentFromOffset(offset);
}

/**
 * Test if there are some data on provided offset -- offset belongs
 *    to some section or segment.
 * @param offset Offset to test
 * @return @c true if there are data for offset, @c false otherwise
 * @note This will return false if offset is in BSS section.
 */
bool FileFormat::haveDataOnOffset(unsigned long long offset) const
{
	const auto *s = getSectionOrSegmentFromOffset(offset);
	return s && !s->isBss() && !s->isDebug();
}

/**
 * Get section which is located at address @a address
 * @param address Address in memory
 * @return @c Pointer to section which is located at address @a address or
 *    @c nullptr if there is no such section
 */
const Section* FileFormat::getSectionFromAddress(unsigned long long address) const
{
	const Section *actSec = nullptr;

	for(const auto *item : sections)
	{
		if(isAddressFromRegion(actSec, item, address))
		{
			actSec = item;
		}
	}

	return actSec;
}

/**
 * Get segment which is located at address @a address
 * @param address Address in memory
 * @return @c Pointer to segment which is located at address @a address or
 *    @c nullptr if there is no such segment
 */
const Segment* FileFormat::getSegmentFromAddress(unsigned long long address) const
{
	const Segment *actSeg = nullptr;

	for(const auto *item : segments)
	{
		if(isAddressFromRegion(actSeg, item, address))
		{
			actSeg = item;
		}
	}

	return actSeg;
}

/**
 * Get section (preferentially) or segment (if no section) which is located at address @a address
 * @param address Address in memory
 * @return @c Pointer to section or segment which is located at address @a address or
 *    @c nullptr if there is no such section or segment
 */
const SecSeg* FileFormat::getSectionOrSegmentFromAddress(unsigned long long address) const
{
	const SecSeg *ret = getSectionFromAddress(address);
	if(!ret)
	{
		ret = getSegmentFromAddress(address);
	}

	return ret;
}

/**
 * Test if the given address in valid section or segment
 * @param address Address to test
 * @return @c true if address is valid, @c false otherwise
 */
bool FileFormat::haveSectionOrSegmentOnAddress(unsigned long long address) const
{
	return getSectionOrSegmentFromAddress(address);
}

/**
 * Test if there are some data on provided address -- address belongs
 *    to some section or segment
 * @param address Address to test
 * @return @c true if there are data for address, @c false otherwise
 * @note This will return false if address is in BSS section.
 */
bool FileFormat::haveDataOnAddress(unsigned long long address) const
{
	const auto *s = getSectionOrSegmentFromAddress(address);
	return s && !s->isBss() && !s->isDebug();
}

/**
 * @brief Test if there are some read-only data on provided address -- address belongs
 * to some read-only section or segment
 * @param address Address to test
 * @return @c True if there are read-only data for address, @c false otherwise
 * @note This will return false if address is in BSS or debug section.
 */
bool FileFormat::haveReadOnlyDataOnAddress(unsigned long long address) const
{
	auto* s = getSectionOrSegmentFromAddress(address);
	return s && !s->isBss() && !s->isDebug() && s->isReadOnly();
}

/**
 * Get number of bits in one nibble
 * @return Number of bits in one nibble
 * @note This assumes architectures with 8-bit bytes and may break if some
 *    exotic architecture is encountered.
 */
std::size_t FileFormat::getNibbleLength() const
{
	//return isUnknownArch() ? 0 : 4;
	return 4;
}

/**
 * Get number of bits in one byte
 * @return Number of bits in one byte
 * @note This assumes architectures with 8-bit bytes and may break if some
 *    exotic architecture is encountered.
 */
std::size_t FileFormat::getByteLength() const
{
	//return isUnknownArch() ? 0 : 8;
	return 8;
}

/**
 * Get number of bits in one word
 * @return Number of bits in one word or zero if this feature is not
 *    supported for target architecture of input file.
 *
 * Supported architectures are defined as enumeration type Architecture.
 */
std::size_t FileFormat::getWordLength() const
{
	return getByteLength() * getBytesPerWord();
}

/**
 * Get number of nibbles in one byte
 * @return Number of nibbles in one byte or zero if this feature is not
 *    supported for target architecture of input file.
 *
 * Supported architectures are defined as enumeration type Architecture.
 */
std::size_t FileFormat::getNumberOfNibblesInByte() const
{
	return !getNibbleLength() ? 0 : !(getByteLength() % getNibbleLength()) ? getByteLength() / getNibbleLength() : 0;
}

/**
* Get reference to the loader error info
* @return The LoaderErrorInfo structire
*/
const LoaderErrorInfo & FileFormat::getLoaderErrorInfo() const
{
	return _ldrErrInfo;
}

/**
 * Find out if target architecture is x86
 * @return @c true if target architecture is x86, @c false otherwise
 */
bool FileFormat::isX86() const
{
	return getTargetArchitecture() == Architecture::X86;
}

/**
 * Find out if target architecture is x86_64
 * @return @c true if target architecture is x86_64, @c false otherwise
 */
bool FileFormat::isX86_64() const
{
	return getTargetArchitecture() == Architecture::X86_64;
}

/**
 * Find out if target architecture is x86 or x86_64
 * @return @c true if target architecture is x86 or x86_64, @c false otherwise
 */
bool FileFormat::isX86OrX86_64() const
{
	return isX86() || isX86_64();
}

/**
 * Find out if target architecture is ARM
 * @return @c true if target architecture is ARM, @c false otherwise
 */
bool FileFormat::isArm() const
{
	return getTargetArchitecture() == Architecture::ARM;
}

/**
 * Find out if target architecture is PowerPC
 * @return @c true if target architecture is PowerPC, @c false otherwise
 */
bool FileFormat::isPowerPc() const
{
	return getTargetArchitecture() == Architecture::POWERPC;
}

/**
 * Find out if target architecture is MIPS
 * @return @c true if target architecture is MIPS, @c false otherwise
 */
bool FileFormat::isMips() const
{
	return getTargetArchitecture() == Architecture::MIPS;
}

/**
 * Find out if target architecture is unknown
 * @return @c true if target architecture is unknown, @c false otherwise
 */
bool FileFormat::isUnknownArch() const
{
	return getTargetArchitecture() == Architecture::UNKNOWN;
}

/**
 * Find out if file format is PE
 * @return @c true if file format is PE, @c false otherwise
 */
bool FileFormat::isPe() const
{
	return getFileFormat() == Format::PE;
}

/**
 * Find out if file format is ELF
 * @return @c true if file format is ELF, @c false otherwise
 */
bool FileFormat::isElf() const
{
	return getFileFormat() == Format::ELF;
}

/**
 * Find out if file format is COFF
 * @return @c true if file format is COFF, @c false otherwise
 */
bool FileFormat::isCoff() const
{
	return getFileFormat() == Format::COFF;
}

/**
 * Find out if file format is Macho
 * @return @c true if file format is Macho, @c false otherwise
 */
bool FileFormat::isMacho() const
{
	return getFileFormat() == Format::MACHO;
}

/**
 * Find out if file format is Intel HEX
 * @return @c true if file format is Intel HEX, @c false otherwise
 */
bool FileFormat::isIntelHex() const
{
	return getFileFormat() == Format::INTEL_HEX;
}

/**
 * Find out if file format is Raw Data
 * @return @c true if file format is Raw Data, @c false otherwise
 */
bool FileFormat::isRawData() const
{
	return getFileFormat() == Format::RAW_DATA;
}

/**
 * Find out if file format is unknown
 * @return @c true if file format is unknown, @c false otherwise
 */
bool FileFormat::isUnknownFormat() const
{
	return getFileFormat() == Format::UNDETECTABLE || getFileFormat() == Format::UNKNOWN;
}

/**
 * Find out if file is Windows driver
 * @return @c true if binary is PE windows driver -- it imports certain libs, @c false otherwise
 */
bool FileFormat::isWindowsDriver() const
{
	if(!importTable || !isPe())
	{
		return false;
	}

	return importTable->getNumberOfImportsInLibraryCaseInsensitive("ntoskrnl.exe")
		|| importTable->getNumberOfImportsInLibraryCaseInsensitive("HAL.dll")
		|| importTable->getNumberOfImportsInLibraryCaseInsensitive("NDIS.SYS");
}

/**
 * Check if CRC32 was computed
 * @return @c true if CRC32 was computed, @c false otherwise
 */
bool FileFormat::hasCrc32() const
{
	return !crc32.empty();
}

/**
 * Check if MD5 was computed
 * @return @c true if MD5 was computed, @c false otherwise
 */
bool FileFormat::hasMd5() const
{
	return !md5.empty();
}

/**
 * Check if SHA256 was computed
 * @return @c true if SHA256 was computed, @c false otherwise
 */
bool FileFormat::hasSha256() const
{
	return !sha256.empty();
}

/**
 * Check if CRC32 of section table was computed
 * @return @c true if CRC32 of section table was computed, @c false otherwise
 */
bool FileFormat::hasSectionTableCrc32() const
{
	return !sectionCrc32.empty();
}

/**
 * Check if MD5 of section table was computed
 * @return @c true if MD5 of section table was computed, @c false otherwise
 */
bool FileFormat::hasSectionTableMd5() const
{
	return !sectionMd5.empty();
}

/**
 * Check if SHA256 of section table was computed
 * @return @c true if SHA256 of section table was computed, @c false otherwise
 */
bool FileFormat::hasSectionTableSha256() const
{
	return !sectionSha256.empty();
}

/**
 * Get CRC32
 * @return CRC32 of file content
 */
std::string FileFormat::getCrc32() const
{
	return crc32;
}

/**
 * Get MD5
 * @return MD5 of file content
 */
std::string FileFormat::getMd5() const
{
	return md5;
}

/**
 * Get SHA256
 * @return SHA256 of file content
 */
std::string FileFormat::getSha256() const
{
	return sha256;
}

/**
 * Get section table CRC32
 * @return CRC32 of section table
 */
std::string FileFormat::getSectionTableCrc32() const
{
	return sectionCrc32;
}

/**
 * Get section table MD5
 * @return MD5 of section table
 */
std::string FileFormat::getSectionTableMd5() const
{
	return sectionMd5;
}

/**
 * Get section table SHA256
 * @return SHA256 of section table
 */
std::string FileFormat::getSectionTableSha256() const
{
	return sectionSha256;
}

/**
 * Get path to input file
 * @return Path to input file
 */
std::string FileFormat::getPathToFile() const
{
	return filePath;
}

/**
 * Get stream of input file
 * @return Stream of input file
 */
std::istream& FileFormat::getFileStream()
{
	return fileStream;
}

/**
 * Get file format
 * @return File format of input file
 * @retval Format::UNDETECTABLE Instance is not in consistent state
 *    (file format cannot be unambiguously determined)
 */
Format FileFormat::getFileFormat() const
{
	return fileFormat;
}

/**
 * Get number of sections in file
 * @return Number of sections in file
 */
std::size_t FileFormat::getNumberOfSections() const
{
	return sections.size();
}

/**
 * Get number of segments in file
 * @return Number of segments in file
 */
std::size_t FileFormat::getNumberOfSegments() const
{
	return segments.size();
}

/**
 * Get number of symbol tables in file
 * @return Number of symbol tables in file
 */
std::size_t FileFormat::getNumberOfSymbolTables() const
{
	return symbolTables.size();
}

/**
 * Get number of relocation tables in file
 * @return Number of relocation tables in file
 */
std::size_t FileFormat::getNumberOfRelocationTables() const
{
	return relocationTables.size();
}

/**
 * Get number of dynamic tables in file
 * @return Number ofo dynamic tables in file
 */
std::size_t FileFormat::getNumberOfDynamicTables() const
{
	return dynamicTables.size();
}

/**
 * Get real length of file. This lenght may be shorter or longer than declared length of file.
 * @return Real length of input file
 */
std::size_t FileFormat::getFileLength() const
{
	return bytes.size();
}

/**
 * Get real length of serialized content of input file.
 * @return Real length of serialized content of input file
 */
std::size_t FileFormat::getLoadedFileLength() const
{
	return loadedBytes->size();
}

/**
 * Get size of overlay. This may be zero. If size of overlay is non-zero, overlay starts
 *    at offset which is identical with result of method @a getDeclaredFileLength().
 * @return Size of overlay
 */
std::size_t FileFormat::getOverlaySize() const
{
	const auto declSize = getDeclaredFileLength();
	const auto realSize = getLoadedFileLength();
	return (realSize > declSize) ? realSize - declSize : 0;
}

/**
 * Count number of nibbles from number of bytes
 * @param bytes Number of bytes
 * @return Number of nibbles
 */
std::size_t FileFormat::nibblesFromBytes(std::size_t bytes) const
{
	return bytes * getNumberOfNibblesInByte();
}

/**
 * Count number of bytes from number of nibbles
 * @param nibbles Number of nibbles
 * @return Number of bytes
 */
std::size_t FileFormat::bytesFromNibbles(std::size_t nibbles) const
{
	const auto nibblesInBytes = getNumberOfNibblesInByte();
	return !nibblesInBytes ? 0 : nibbles / nibblesInBytes;
}

/**
 * Count number of bytes from number of nibbles and round up
 * @param nibbles Number of nibbles
 * @return Number of bytes rounded up
 */
std::size_t FileFormat::bytesFromNibblesRounded(std::size_t nibbles) const
{
	const auto nibblesInBytes = getNumberOfNibblesInByte();
	return !nibblesInBytes ? 0 : nibbles / nibblesInBytes + (nibbles % nibblesInBytes ? 1 : 0);
}

/**
 * Convert address to offset
 * @param result Into this parameter is stored resulted offset
 * @param address Address for conversion
 * @return @c true if address was successfully converted to offset, @c false otherwise
 *
 * If method returns @c false, @a result is left unchanged
 */
bool FileFormat::getOffsetFromAddress(unsigned long long &result, unsigned long long address) const
{
	const auto *secSeg = getSectionOrSegmentFromAddress(address);
	if(!secSeg)
	{
		return false;
	}

	result = secSeg->getOffset() + (address - secSeg->getAddress());
	return true;
}

/**
 * Convert offset to address
 * @param result Into this parameter is stored resulted address
 * @param offset Offset for conversion
 * @return @c true if offset was successfully converted to address, @c false otherwise
 *
 * If method returns @c false, @a result is left unchanged
 */
bool FileFormat::getAddressFromOffset(unsigned long long &result, unsigned long long offset) const
{
	const auto *secSeg = getSectionOrSegmentFromOffset(offset);
	if(!secSeg)
	{
		return false;
	}

	result = secSeg->getAddress() + (offset - secSeg->getOffset());
	return true;
}

/**
 * Get bytes from entry point
 * @param result Read bytes
 * @param offset Start offset for read
 * @param numberOfBytes Number of bytes for read
 * @return Status of operation (@c true if all is OK)
 */
bool FileFormat::getBytes(std::vector<std::uint8_t> &result, unsigned long long offset, unsigned long long numberOfBytes) const
{
	if (offset >= getLoadedFileLength())
	{
		return false;
	}

	numberOfBytes = offset + numberOfBytes > getLoadedFileLength() ? getLoadedFileLength() - offset : numberOfBytes;
	result.clear();
	result.reserve(numberOfBytes);
	std::copy(loadedBytes->begin() + offset, loadedBytes->begin() + offset + numberOfBytes, std::back_inserter(result));
	return true;
}

/**
 * Get bytes from entry point
 * @param result Read bytes
 * @param numberOfBytes Number of bytes for read
 * @return Status of operation (@c true if all is OK)
 *
 * If file has no entry point or entry point has not detected, method returns @c false
 *
 * If file has entry point but detection of entry point offset is failed or an error
 * occurs while reading bytes from file, instance method @a isInValidState() returns
 * @c false after its invocation.
 */
bool FileFormat::getEpBytes(std::vector<std::uint8_t> &result, unsigned long long numberOfBytes) const
{
	unsigned long long epOffset;
	if(stateIsValid && getEpOffset(epOffset))
	{
		return getBytes(result, epOffset, numberOfBytes);
	}

	return false;
}

/**
 * Get bytes from specified offset in hexadecimal string representation
 * @param result Read bytes in hexadecimal string representation
 * @param offset Start offset for read
 * @param numberOfBytes Number of bytes for read
 * @return Status of operation (@c true if all is OK)
 */
bool FileFormat::getHexBytes(std::string &result, unsigned long long offset, unsigned long long numberOfBytes) const
{
	bytesToHexString(*loadedBytes, result, offset, numberOfBytes);
	return offset < getLoadedFileLength();
}

/**
 * Get bytes from entry point in hexadecimal string representation
 * @param result Read bytes in hexadecimal string representation
 * @param numberOfBytes Number of bytes for read
 * @return Status of operation (@c true if all is OK)
 *
 * If file has no entry point or entry point has not detected, method returns @c false
 *
 * If file has entry point but detection of entry point offset is failed or an error
 * occurs while reading bytes from file, instance method @a isInValidState() returns
 * @c false after its invocation.
 */
bool FileFormat::getHexEpBytes(std::string &result, unsigned long long numberOfBytes) const
{
	unsigned long long epOffset;
	if(stateIsValid && getEpOffset(epOffset))
	{
		return getHexBytes(result, epOffset, numberOfBytes);
	}

	// file has no entry point or some error
	return false;
}

/**
 * Get bytes from end of file in hexadecimal string representation
 * @param result Parameter for store the result
 * @param numberOfBytes Number of bytes for read
 * @return @c true if operation went OK, @c false otherwise
 *
 * If length of file is smaller than @a numberOfBytes, as many bytes as possible are read.
 */
bool FileFormat::getHexBytesFromEnd(std::string &result, unsigned long long numberOfBytes) const
{
	numberOfBytes = std::min(numberOfBytes, static_cast<unsigned long long>(getLoadedFileLength()));
	return getHexBytes(result, getLoadedFileLength() - numberOfBytes, numberOfBytes);
}

/**
 * Get bytes from specified offset as plain string
 * @param result Parameter for store the result
 * @param offset Start offset for read
 * @param numberOfBytes Number of bytes for read
 * @return Status of operation (@c true if all is OK)
 */
bool FileFormat::getString(std::string &result, unsigned long long offset, unsigned long long numberOfBytes) const
{
	bytesToString(*loadedBytes, result, offset, numberOfBytes);
	return offset < getLoadedFileLength();
}

/**
 * Get bytes from end of file as plain string
 * @param result Parameter for store the result
 * @param numberOfBytes Number of bytes for read
 * @return @c true if operation went OK, @c false otherwise
 *
 * If length of file is smaller than @a numberOfBytes, as many bytes as possible are read.
 */
bool FileFormat::getStringFromEnd(std::string &result, unsigned long long numberOfBytes) const
{
	numberOfBytes = std::min(numberOfBytes, static_cast<unsigned long long>(getLoadedFileLength()));
	return getString(result, getLoadedFileLength() - numberOfBytes, numberOfBytes);
}

/**
 * Get information about section containing entry point
 * @return Pointer to EP section if file has entry point and EP section was detected, @c nullptr otherwise
 */
const Section* FileFormat::getEpSection()
{
	unsigned long long ep;
	if(!getEpOffset(ep))
	{
		return nullptr;
	}

	return getSectionFromOffset(ep);
}

/**
 * Get information about section with name @a secName
 * @param secName Name of section
 * @return Pointer to section or @c nullptr if section was not found
 *
 * If file has more sections with name equal to @a secName, then is returned first such section.
 */
const Section* FileFormat::getSection(const std::string &secName) const
{
	for(const auto *item : sections)
	{
		if(item && item->getName() == secName)
		{
			return item;
		}
	}

	return nullptr;
}

/**
 * Get information about section with index @a secIndex
 * @param secIndex Index of section (indexed from 0)
 * @return Pointer to section or @c nullptr if section was not detected
 */
const Section* FileFormat::getSection(unsigned long long secIndex) const
{
	if(secIndex >= getNumberOfSections())
	{
		return nullptr;
	}

	const auto *iSec = sections[secIndex];
	if(iSec && iSec->getIndex() == secIndex)
	{
		return iSec;
	}

	for(const auto *sec : sections)
	{
		if(sec && sec->getIndex() == secIndex)
		{
			return sec;
		}
	}

	return nullptr;
}

/**
 * Get information about last section
 * @return Pointer to last section or @c nullptr if section is not detected
 */
const Section* FileFormat::getLastSection() const
{
	const auto secSize = getNumberOfSections();
	return secSize ? sections[secSize - 1] : nullptr;
}

/**
 * Get information about last but one section
 * @return Pointer to last but one section or @c nullptr if section is not detected
 */
const Section* FileFormat::getLastButOneSection() const
{
	const auto secSize = getNumberOfSections();
	return secSize > 1 ? sections[secSize - 2] : nullptr;
}

/**
 * Get information about segment containing entry point
 * @return Pointer to EP segment if file has entry point and EP segment was detected, @c nullptr otherwise
 */
const Segment* FileFormat::getEpSegment()
{
	unsigned long long epAddress;
	if(!getEpAddress(epAddress))
	{
		return nullptr;
	}

	return getSegmentFromAddress(epAddress);
}

/**
 * Get information about segment with name @a segName
 * @param segName Name of segment
 * @return Pointer to segment or @c nullptr if segment was not found
 *
 * If file has more segments with name equal to @a segName, then is returned first such segment.
 */
const Segment* FileFormat::getSegment(const std::string &segName) const
{
	for(const auto *item : segments)
	{
		if(item && item->getName() == segName)
		{
			return item;
		}
	}

	return nullptr;
}

/**
 * Get information about segment with index @a segIndex
 * @param segIndex Index of segment (indexed from 0)
 * @return Pointer to segment or @c nullptr if segment was not detected
 */
const Segment* FileFormat::getSegment(unsigned long long segIndex) const
{
	if(segIndex >= getNumberOfSegments())
	{
		return nullptr;
	}

	const auto *iSeg = segments[segIndex];
	if(iSeg && iSeg->getIndex() == segIndex)
	{
		return iSeg;
	}

	for(const auto *seg : segments)
	{
		if(seg && seg->getIndex() == segIndex)
		{
			return seg;
		}
	}

	return nullptr;
}

/**
 * Get information about last segment
 * @return Pointer to last segment or @c nullptr if segment is not detected
 */
const Segment* FileFormat::getLastSegment() const
{
	const auto size = getNumberOfSegments();
	return size ? segments[size - 1] : nullptr;
}

/**
 * Get information about last but one segment
 * @return Pointer to last but one segment or @c nullptr if segment is not detected
 */
const Segment* FileFormat::getLastButOneSegment() const
{
	const auto size = getNumberOfSegments();
	return size > 1 ? segments[size - 2] : nullptr;
}

/**
 * Get information about symbol table
 * @param tabIndex Index of selected symbol table (indexed from 0)
 * @return Pointer to symbol table or @c nullptr if index of table is invalid
 */
const SymbolTable* FileFormat::getSymbolTable(unsigned long long tabIndex) const
{
	return (tabIndex < getNumberOfSymbolTables()) ? symbolTables[tabIndex] : nullptr;
}

/**
 * Get information about relocation table
 * @param tabIndex Index of selected relocation table (indexed from 0)
 * @return Pointer to relocation table or @c nullptr if index of table is invalid
 */
const RelocationTable* FileFormat::getRelocationTable(unsigned long long tabIndex) const
{
	return (tabIndex < getNumberOfRelocationTables()) ? relocationTables[tabIndex] : nullptr;
}

/**
 * Get information about dynamic table
 * @param tabIndex Index of selected dynamic table (indexed from 0)
 * @return Pointer to dynamic table or @c nullptr if index of table is invalid
 */
const DynamicTable* FileFormat::getDynamicTable(unsigned long long tabIndex) const
{
	return (tabIndex < getNumberOfDynamicTables()) ? dynamicTables[tabIndex] : nullptr;
}

/**
 * Get information about import table
 * @return Pointer to import table or @c nullptr if file has no imports
 */
const ImportTable* FileFormat::getImportTable() const
{
	return importTable;
}

/**
 * Get information about export table
 * @return Pointer to export table or @c nullptr if file has no exports
 */
const ExportTable* FileFormat::getExportTable() const
{
	return exportTable;
}

/**
 * Get information about resources
 * @return Pointer to resource table or @c nullptr if file has no resources
 */
const ResourceTable* FileFormat::getResourceTable() const
{
	return resourceTable;
}

/**
 * Get information about structure of resource tree
 * @return Pointer to resource tree or @c nullptr if file has no resources
 */
const ResourceTree* FileFormat::getResourceTree() const
{
	return resourceTree;
}

/**
 * Get information about rich header
 * @return Pointer to rich header or @c nullptr if file has no rich header
 */
const RichHeader* FileFormat::getRichHeader() const
{
	return richHeader;
}

/**
 * Get information about related PDB file
 * @return Pointer to information about related PDB file or @c nullptr if file has no such information
 */
const PdbInfo* FileFormat::getPdbInfo() const
{
	return pdbInfo;
}

/**
 * Get information about certificate table
 * @return Pointer to certificate table of @c nullptr if file has no certificates
 */
const CertificateTable* FileFormat::getCertificateTable() const
{
	return certificateTable;
}

/**
 * Get information about ELF core file
 * @return Pointer to ELF core info of @c nullptr if file has no certificates
 */
const ElfCoreInfo* FileFormat::getElfCoreInfo() const
{
	return elfCoreInfo;
}

/**
 * Get symbol with name @a name
 * @param name Name of symbol to get
 * @return Pointer to symbol with name @a name or @c nullptr if such symbol is not found
 */
const Symbol* FileFormat::getSymbol(const std::string &name) const
{
	for(const auto *table : getSymbolTables())
	{
		if(table)
		{
			const auto *item = table->getSymbol(name);
			if(item)
			{
				return item;
			}
		}
	}

	return nullptr;
}

/**
 * Get symbol with address @a address
 * @param address Address of symbol to get
 * @return Pointer to symbol with address @a address or @c nullptr if such symbol is not found
 */
const Symbol* FileFormat::getSymbol(unsigned long long address) const
{
	for(const auto *table : getSymbolTables())
	{
		if(table)
		{
			const auto *item = table->getSymbolOnAddress(address);
			if(item)
			{
				return item;
			}
		}
	}

	return nullptr;
}

/**
 * Get relocation with name @a name
 * @param name Name of relocation to get
 * @return Pointer to relocation with name @a name or @c nullptr if such relocation is not found
 */
const Relocation* FileFormat::getRelocation(const std::string &name) const
{
	for(const auto *table : getRelocationTables())
	{
		if(table)
		{
			const auto *item = table->getRelocation(name);
			if(item)
			{
				return item;
			}
		}
	}

	return nullptr;
}

/**
 * Get relocation with address @a address
 * @param address Address of relocation to get
 * @return Pointer to relocation with address @a address or @c nullptr if such relocation is not found
 */
const Relocation* FileFormat::getRelocation(unsigned long long address) const
{
	for(const auto *table : getRelocationTables())
	{
		if(table)
		{
			const auto *item = table->getRelocationOnAddress(address);
			if(item)
			{
				return item;
			}
		}
	}

	return nullptr;
}

/**
 * Get import with name @a name
 * @param name Name of import to get
 * @return Pointer to import with name @a name or @c nullptr if such import is not found
 */
const Import* FileFormat::getImport(const std::string &name) const
{
	return importTable ? importTable->getImport(name) : nullptr;
}

/**
 * Get import on address @a address
 * @param address Address of import to get
 * @return Pointer to import with address @a address or @c nullptr if such import is not found
 */
const Import* FileFormat::getImport(unsigned long long address) const
{
	return importTable ? importTable->getImportOnAddress(address) : nullptr;
}

/**
 * Get export with name @a name
 * @param name Name of export to get
 * @return Pointer to export with name @a name or @c nullptr if such export is not found
 */
const Export* FileFormat::getExport(const std::string &name) const
{
	return exportTable ? exportTable->getExport(name) : nullptr;
}

/**
 * Get export on address @a address
 * @param address Address of export to get
 * @return Pointer to export with address @a address or @c nullptr if such export is not found
 */
const Export* FileFormat::getExport(unsigned long long address) const
{
	return exportTable ? exportTable->getExportOnAddress(address) : nullptr;
}

/**
 * Get resource that represents side-by-side assembly manifest
 * @return Pointer to manifest resource or @c nullptr if such resource is not found
 */
const Resource* FileFormat::getManifestResource() const
{
	return resourceTable ? resourceTable->getResourceWithType(PELIB_RT_MANIFEST) : nullptr;
}

/**
 * Get resource that represents version information
 * @return Pointer to version resource or @c nullptr if such resource is not found
 */
const Resource* FileFormat::getVersionResource() const
{
	return resourceTable ? resourceTable->getResourceWithType(PELIB_RT_VERSION) : nullptr;
}

/**
 * Get whether the signature is present in the file
 * @return @c true if present, otherwise @c false.
 */
bool FileFormat::isSignaturePresent() const
{
	return signatureVerified.isDefined();
}

/**
 * Get whether the signature is verified
 * @return @c true if present, otherwise @c false.
 */
bool FileFormat::isSignatureVerified() const
{
	return signatureVerified.isDefined() && signatureVerified.getValue();
}

/**
 * Get non-decodable address ranges.
 * @return Non-decodable address ranges.
 */
const retdec::utils::RangeContainer<std::uint64_t>& FileFormat::getNonDecodableAddressRanges() const
{
	return nonDecodableRanges;
}

/**
 * Get all sections
 * @return Reference to sections
 */
const std::vector<Section*>& FileFormat::getSections() const
{
	return sections;
}

/**
 * Get selected sections
 * @param secs Names of selected sections
 * @return Selected sections
 */
const std::vector<Section*> FileFormat::getSections(std::initializer_list<std::string> secs) const
{
	std::vector<Section*> result;

	for(auto *region : sections)
	{
		if(region && std::any_of(secs.begin(), secs.end(),
			[&] (const auto &name)
			{
				return region->getName() == name;
			}
		))
		{
			result.push_back(region);
		}
	}

	return result;
}

/**
 * Get all segments
 * @return Reference to segments
 */
const std::vector<Segment*>& FileFormat::getSegments() const
{
	return segments;
}

/**
 * Get selected segments
 * @param segs Name of selected segments
 * @return Selected segments
 */
const std::vector<Segment*> FileFormat::getSegments(std::initializer_list<std::string> segs) const
{
	std::vector<Segment*> result;

	for(auto *region : segments)
	{
		if(region && std::any_of(segs.begin(), segs.end(),
			[&] (const auto &name)
			{
				return region->getName() == name;
			}
		))
		{
			result.push_back(region);
		}
	}

	return result;
}

/**
 * Get all symbol tables
 * @return Reference to symbol tables
 */
const std::vector<SymbolTable*>& FileFormat::getSymbolTables() const
{
	return symbolTables;
}

/**
 * Get all relocation tables
 * @return Reference to relocation tables
 */
const std::vector<RelocationTable*>& FileFormat::getRelocationTables() const
{
	return relocationTables;
}

/**
 * Get all dynamic tables
 * @return Reference to dynamic tables
 */
const std::vector<DynamicTable*>& FileFormat::getDynamicTables() const
{
	return dynamicTables;
}

/**
 * Get content of input file as bytes
 * @return Content of input file as bytes
 */
const std::vector<unsigned char>& FileFormat::getBytes() const
{
	return bytes;
}

/**
 * Get serialized loaded content of input file as bytes
 * @return Serialized content of input file as bytes
 */
const std::vector<unsigned char>& FileFormat::getLoadedBytes() const
{
	return *loadedBytes;
}

/**
 * Get content of input file as constant pointer to bytes
 * @return Content of input file as constant pointer to bytes
 */
const unsigned char* FileFormat::getBytesData() const
{
	return bytes.data();
}

/**
 * Get serialized loaded content of input file as constant pointer to bytes
 * @return Serialized content of input file as constant pointer to bytes
 */
const unsigned char* FileFormat::getLoadedBytesData() const
{
	return loadedBytes->data();
}

/**
 * Get all detected strings
 * @return Reference to strings
 */
const std::vector<String>& FileFormat::getStrings() const
{
	return strings;
}

/**
 * Get all detected notes
 * @return Reference to notes
 */
const std::vector<ElfNoteSecSeg>&FileFormat::getElfNoteSecSegs() const
{
	return noteSecSegs;
}

const std::set<std::uint64_t> &FileFormat::getUnknownRelocations() const
{
	return unknownRelocs;
}

/**
 * Get integer (@a x bytes) located at provided address using the specified endian or default file endian
 * @param address Address to get integer from
 * @param x Number of bytes for conversion
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getXByte(std::uint64_t address, std::uint64_t x, std::uint64_t &res, retdec::utils::Endianness e) const
{
	const auto *secSeg = getSectionOrSegmentFromAddress(address);
	if(!secSeg || x * getByteLength() > sizeof(res) * CHAR_BIT)
	{
		return false;
	}
	else if(!x)
	{
		res = 0;
		return true;
	}

	const auto secOffset = address - secSeg->getAddress();
	const auto offset = secSeg->getOffset() + secOffset;
	return (secOffset + x > secSeg->getLoadedSize() || offset + x > getLoadedFileLength()) ?
		false : createValueFromBytes(*loadedBytes, res, e, offset, x);
}

/**
 * Get @a x bytes long byte array from specified address
 * @param address Address to get array from
 * @param x Number of bytes for get
 * @param res Result array
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getXBytes(std::uint64_t address, std::uint64_t x, std::vector<std::uint8_t> &res) const
{
	res.clear();
	const auto *secSeg = getSectionOrSegmentFromAddress(address);
	return secSeg && secSeg->getBytes(res, address - secSeg->getAddress(), x) && res.size() == x;
}

bool FileFormat::setXByte(std::uint64_t address, std::uint64_t x, std::uint64_t val, retdec::utils::Endianness e/* = retdec::utils::Endianness::UNKNOWN*/)
{
	return false;
}

bool FileFormat::setXBytes(std::uint64_t address, const std::vector<std::uint8_t> &val)
{
	return false;
}

/**
 * Find out, if there is a pointer (valid address) on the provided address
 * @param address Address to check
 * @param[out] pointer If provided (not @c nullptr) it is filled with pointer's
 *                     value on the provided address
 * @return @c true if pointer on address, @c false otherwise
 */
bool FileFormat::isPointer(unsigned long long address, std::uint64_t* pointer) const
{
	std::uint64_t val = 0;
	if (getWord(address, val) && haveDataOnAddress(val))
	{
		if (pointer)
		{
			*pointer = val;
		}
		return true;
	}
	return false;
}

/**
 * Get integer (1B) located at provided offset using the specified endian or default file endian
 * @param offset Offset to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::get1ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e) const
{
	return getXByteOffset(offset, 1, res, e);
}

/**
 * Get integer (2B) located at provided offset using the specified endian or default file endian
 * @param offset Offset to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::get2ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e) const
{
	return getXByteOffset(offset, 2, res, e);
}

/**
 * Get integer (4B) located at provided offset using the specified endian or default file endian
 * @param offset Offset to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::get4ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e) const
{
	return getXByteOffset(offset, 4, res, e);
}

/**
 * Get integer (8B) located at provided offset using the specified endian or default file endian
 * @param offset Offset to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::get8ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e) const
{
	return getXByteOffset(offset, 8, res, e);
}

/**
 * Get long double from the specified offset
 * If system has 80-bit (10-byte) long double, copy data directly.
 * Else convert 80-bit (10-byte) long double into 64-bit (8-byte) double.
 * @param offset Offset to get double from
 * @param res Result double
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::get10ByteOffset(std::uint64_t offset, long double &res) const
{
	std::vector<std::uint8_t> d10;
	if(!getXBytesOffset(offset, 10, d10))
	{
		return false;
	}

	if (!get10ByteImpl(d10, res))
	{
		return false;
	}

	return true;
}

/**
 * Get integer (@a x bytes) located at provided offset using the specified endian or default file endian
 * @param offset Offset to get integer from
 * @param x Number of bytes for conversion
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getXByteOffset(std::uint64_t offset, std::uint64_t x, std::uint64_t &res, retdec::utils::Endianness e) const
{
	if(offset + x > getLoadedFileLength() || x * getByteLength() > sizeof(res) * CHAR_BIT)
	{
		return false;
	}
	else if(!x)
	{
		res = 0;
		return true;
	}

	return createValueFromBytes(*loadedBytes, res, e, offset, x);
}

/**
 * Get @a x bytes long byte array from specified offset
 * @param offset Offset to get array from
 * @param x Number of bytes for get
 * @param res Result array
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getXBytesOffset(std::uint64_t offset, std::uint64_t x, std::vector<std::uint8_t> &res) const
{
	res.clear();
	if(offset + x <= getLoadedFileLength())
	{
		res.assign(loadedBytes->begin() + offset, loadedBytes->begin() + offset + x);
		return res.size() == x;
	}

	return false;
}

/**
 * Get word located at provided offset using the specified endian or default file endian
 * @param offset Offset to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getWordOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e) const
{
	return getXByteOffset(offset, getBytesPerWord(), res, e);
}

/**
 * Get NTBS (null-terminated byte string) from specified offset
 * @param offset Offset to get string from
 * @param res Result string
 * @param size Requested size of string (if @a size is zero, read until zero byte)
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getNTBSOffset(std::uint64_t offset, std::string &res, std::size_t size) const
{
	using namespace std::placeholders;

	GetNByteFn get1ByteFn = std::bind(&FileFormat::get1ByteOffset, this, _1, _2, _3);
	return getNTBSImpl(get1ByteFn, offset, res, size);
}

/**
 * Get NTWS (null-terminated wide string) from specified offset
 * @param offset Offset to get string from
 * @param width Byte width of one character
 * @param res Result character array
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool FileFormat::getNTWSOffset(std::uint64_t offset, std::size_t width, std::vector<std::uint64_t> &res) const
{
	using namespace std::placeholders;

	GetXByteFn getXByteFn = std::bind(&FileFormat::getXByteOffset, this, _1, _2, _3, _4);
	return getNTWSImpl(getXByteFn, offset, width, res);
}

/**
 * Get name of file format as string
 * @return Name of file format in which is input file
 */
std::string FileFormat::getFileFormatName() const
{
	return getFileFormatNameFromEnum(fileFormat);
}

/**
 * Get declared length of file. This length may be shorter or longer than real length of file.
 * @return Declared length of file
 *
 * This method takes into account only offset and size of each file section and segment.
 * This is not valid for some file formats (e.g. ELF, PE, COFF), therefore, this method
 * is virtual and can be replaced in subclass.
 */
std::size_t FileFormat::getDeclaredFileLength() const
{
	std::size_t declSize = 0;

	for(const auto *item : sections)
	{
		if(item && item->getType() != Section::Type::BSS)
		{
			declSize = std::max(declSize, static_cast<std::size_t>(item->getOffset() + item->getSizeInFile()));
		}
	}

	for(const auto *item : segments)
	{
		if(item)
		{
			declSize = std::max(declSize, static_cast<std::size_t>(item->getOffset() + item->getSizeInFile()));
		}
	}

	return declSize;
}

/**
 * Determine if loaded sections are OK to use for decompilation purposes.
 * We want at least one valid section which may hold code.
 * @return @c true if sections are to be used, @c false otherwise (use segments).
 */
bool FileFormat::areSectionsValid() const
{
	return std::any_of(sections.begin(), sections.end(),
		[this] (const auto *s)
		{
			return s && s->isSomeCode() && s->isValid(this);
		}
	);
}

/**
 * @fn bool FileFormat::isObjectFile() const
 * @return @c true if file is object file, @c false otherwise
 */

/**
 * @fn bool FileFormat::isDll() const
 * @return @c true if file id dynamic linked library, @c false otherwise
 */

/**
 * @fn bool FileFormat::isExecutable() const
 * @return @c true if input file is executable file, @c false otherwise
 */

/**
 * @fn bool FileFormat::getMachineCode(unsigned long long &result) const
 * Get file format-dependent number representing code of target architecture of file
 * @param result Parameter for store the result
 * @return @c true if method went OK, @c false otherwise
 */

/**
 * @fn bool FileFormat::getAbiVersion(unsigned long long &result) const
 * Get file format-dependent version of used ABI
 * @param result Parameter for store the result
 * @return @c true if method went OK, @c false otherwise
 */

/**
 * @fn bool FileFormat::getImageBaseAddress(unsigned long long &imageBase) const
 * Get image base address of file
 * @param imageBase Into this parameter the resulting number is stored
 * @return @c true if file has image base address and this address was successfully detected, @c false otherwise
 *
 * If file has no image base, @a imageBase is left unchanged
 */

/**
 * @fn bool FileFormat::getEpAddress(unsigned long long &result) const
 * Get virtual address of entry point
 * @param result Parameter for store the result
 * @return @c true if file has entry point and entry point address is successfully detected, @c false otherwise
 *
 * If file has no associated entry point, @a result is left unchanged.
 *
 * If file has entry point but detection of entry point address is failed, instance method
 * @a isInValidState() returns @c false after its invocation.
 */

/**
 * @fn bool FileFormat::getEpOffset(unsigned long long &epOffset) const
 * Get offset of entry point
 * @param epOffset Into this parameter the resulting number is stored
 * @return @c true if file has entry point and entry point offset is successfully detected, @c false otherwise
 *
 * If file has no associated entry point, @a epOffset is left unchanged.
 *
 * If file has entry point but detection of entry point offset is failed, instance method
 * @a isInValidState() returns @c false after its invocation.
 */

/**
 * @fn Architecture FileFormat::getTargetArchitecture() const
 * Get target architecture
 * @return Target architecture of input file
 * @retval Architecture::UNKNOWN Architecture is unknown
 */

/**
 * @fn std::size_t FileFormat::getDeclaredNumberOfSections() const
 * Get declared number of sections. This number may be different than real
 * number of sections in file
 * @return Declared number of sections
 */

/**
 * @fn std::size_t FileFormat::getDeclaredNumberOfSegments() const
 * Get declared number of segments. This number may be different than real
 * number of segments in file
 * @return Declared number of segments
 */

/**
 * @fn std::size_t FileFormat::getSectionTableOffset() const
 * Get section table offset or zero if section table does not exist
 * @return Section table offset
 */

/**
 * @fn std::size_t FileFormat::getSectionTableEntrySize() const
 * Get size of one record in section table or zero if section table does not exist
 * @return Size of one record in section table
 */

/**
 * @fn std::size_t FileFormat::getSegmentTableOffset() const
 * Get segment table offset or zero if segment table does not exist
 * @return Segment table offset
 */

/**
 * @fn std::size_t FileFormat::getSegmentTableEntrySize() const
 * Get size of one record in segment table or zero if segment table does not exist
 * @return Size of one record in segment table
 */

/**
 * Dump information about input file on standard output
 */
void FileFormat::dump()
{
	std::string output;
	dump(output);
	std::cout << output;
}

/**
 * Dump information about input file
 * @param dumpFile Into this parameter is stored dump of input file in an LLVM style
 */
void FileFormat::dump(std::string &dumpFile)
{
	std::stringstream ret;
	std::string sArch, sEndian, sType, sDump;

	switch(getTargetArchitecture())
	{
		case Architecture::X86:
			sArch = "x86";
			break;
		case Architecture::X86_64:
			sArch = "x86-64";
			break;
		case Architecture::ARM:
			sArch = "ARM";
			break;
		case Architecture::POWERPC:
			sArch = "PowerPC";
			break;
		case Architecture::MIPS:
			sArch = "MIPS";
			break;
		default:
			sArch = "unknown";
	}

	switch(getEndianness())
	{
		case Endianness::LITTLE:
			sEndian = "little";
			break;
		case Endianness::BIG:
			sEndian = "big";
			break;
		default:
			sEndian = "unknown";
	}

	if(isObjectFile())
	{
		sType = "object file";
	}
	else if(isDll())
	{
		sType = "DLL";
	}
	else if(isExecutable())
	{
		sType = "executable file";
	}
	else
	{
		sType = "unknown";
	}

	ret << "; ------------ Input file ------------\n";
	ret << "; Path to file: " << filePath << "\n";
	if(hasCrc32())
	{
		ret << "; CRC32: " << getCrc32() << "\n";
	}
	if(hasMd5())
	{
		ret << "; MD5: " << getMd5() << "\n";
	}
	if(hasSha256())
	{
		ret << "; SHA256: " << getSha256() << "\n";
	}
	if(hasSectionTableCrc32())
	{
		ret << "; Section CRC32: " << getSectionTableCrc32() << "\n";
	}
	if(hasSectionTableMd5())
	{
		ret << "; Section MD5: " << getSectionTableMd5() << "\n";
	}
	if(hasSectionTableSha256())
	{
		ret << "; Section SHA256: " << getSectionTableSha256() << "\n";
	}
	ret << "; Real size: " << getFileLength() << " bytes\n";
	ret << "; Loaded size: " << getLoadedFileLength() << " bytes\n";
	ret << "; Declared size: " << getDeclaredFileLength() << " bytes\n";
	ret << "; Overlay size: " << getOverlaySize() << " bytes\n";
	ret << "; File format: " << getFileFormatName() << "\n";
	ret << "; Architecture: " << sArch << "\n";
	ret << "; Endianness: " << sEndian << "\n";
	ret << "; Type: " << sType << "\n";

	unsigned long long addr;
	if(getEpAddress(addr))
	{
		ret << "; Entry point address: " << std::hex << addr << "\n";
	}

	unsigned long long offset;
	if(getEpOffset(offset))
	{
		ret << "; Entry point offset: " << offset << "\n";
	}

	ret << "; Bytes per word: " << std::dec << getBytesPerWord() << "\n";
	ret << "; Bits per word: " << getWordLength() << "\n";
	ret << "; Bits per byte: " << getByteLength() << "\n";
	ret << "; Bits per nibble: " << getNibbleLength() << "\n";
	ret << "; Nibbles per byte: " << getNumberOfNibblesInByte() << "\n";

	if(getNumberOfSections())
	{
		ret << "\n" << "; Number of sections: " << getNumberOfSections() << "\n";
	}

	for(const auto *item : getSections())
	{
		if(item)
		{
			item->dump(sDump);
			ret << sDump;
		}
	}

	if(getNumberOfSegments())
	{
		ret << "\n" << "; Number of segments: " << getNumberOfSegments() << "\n";
	}

	for(const auto *item : getSegments())
	{
		if(item)
		{
			item->dump(sDump);
			ret << sDump;
		}
	}

	if(getNumberOfSymbolTables())
	{
		ret << "\n" << "; Number of symbol tables: " << getNumberOfSymbolTables() << "\n";
	}

	for(const auto *item : getSymbolTables())
	{
		if(item)
		{
			item->dump(sDump);
			ret << sDump;
		}
	}

	if(getNumberOfRelocationTables())
	{
		ret << "\n" << "; Number of relocation tables: " << getNumberOfRelocationTables() << "\n";
	}

	for(const auto *item : getRelocationTables())
	{
		if(item)
		{
			item->dump(sDump);
			ret << sDump;
		}
	}

	if(getNumberOfDynamicTables())
	{
		ret << "\n" << "; Number of dynamic tables: " << getNumberOfDynamicTables() << "\n";
	}

	for(const auto *item : getDynamicTables())
	{
		if(item)
		{
			item->dump(sDump);
			ret << sDump;
		}
	}

	if(importTable && !importTable->empty())
	{
		getImportTable()->dump(sDump);
		ret << sDump;
	}

	if(exportTable && !exportTable->empty())
	{
		getExportTable()->dump(sDump);
		ret << sDump;
	}

	if(getRichHeader())
	{
		getRichHeader()->dump(sDump);
		ret << sDump;
	}

	if(getPdbInfo())
	{
		getPdbInfo()->dump(sDump);
		ret << sDump;
	}

	if(getResourceTable())
	{
		getResourceTable()->dump(sDump);
		ret << sDump;
	}

	dumpFile = ret.str();
}

/**
 * Dump information about validity of sections and segments on standard output
 */
void FileFormat::dumpRegionsValidity()
{
	std::string output;
	dumpRegionsValidity(output);
	std::cout << output;
}

/**
 * Dump information about validity of sections and segments
 * @param dumpStr Parameter for store the dump in LLVM format
 */
void FileFormat::dumpRegionsValidity(std::string &dumpStr)
{
	std::stringstream ret;
	ret << "; Are sections valid: " << areSectionsValid() << "\n";

	if(getNumberOfSections())
	{
		ret << "\n; ------------ Sections ------------\n";
	}

	for(const auto *s : sections)
	{
		ret << "; " << s->getIndex() << ": " << s->isValid(this) << "\n";
	}

	if(getNumberOfSegments())
	{
		ret << "\n; ------------ Segments ------------\n";
	}

	for(const auto *s : segments)
	{
		ret << "; " << s->getIndex() << ": " << s->isValid(this) << "\n";
	}

	dumpStr = ret.str();
}

/**
 * Dump information about structure of resource tree on standard output
 */
void FileFormat::dumpResourceTree()
{
	std::string output;
	dumpResourceTree(output);
	std::cout << output;
}

void FileFormat::dumpResourceTree(std::string &dumpStr)
{
	if(!resourceTree)
	{
		dumpStr.clear();
	}
	else
	{
		resourceTree->dump(dumpStr);
	}
}

} // namespace fileformat
} // namespace retdec
