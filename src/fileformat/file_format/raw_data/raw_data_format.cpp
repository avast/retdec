/**
 * @file src/fileformat/file_format/raw_data/raw_data_format.cpp
 * @brief Methods of RawDataFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <iomanip>
#include <string>

#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 * @param inputStream Input stream
 * @param loadFlags Load flags
 */
RawDataFormat::RawDataFormat(std::istream &inputStream, LoadFlags loadFlags) : FileFormat(inputStream, loadFlags)
{
	initStructures();
}

RawDataFormat::RawDataFormat(const std::string &filePath, LoadFlags loadFlags) : FileFormat(filePath, loadFlags)
{
	secName = ".text";
	secType = Section::Type::CODE;
	initStructures();
}

/**
 * Destructor
 */
RawDataFormat::~RawDataFormat()
{
}

/**
 * Init internal structures
 */
void RawDataFormat::initStructures()
{
	stateIsValid = true;
	fileFormat = Format::RAW_DATA;
	section = new Section;
	section->setName(secName);
	section->setType(secType);
	section->setIndex(0);
	section->setOffset(0);
	section->setAddress(0);
	section->setMemory(true);
	section->setSizeInFile(bytes.size());
	section->setSizeInMemory(bytes.size());
	section->load(this);
	sections.push_back(section);
	computeSectionTableHashes();
	loadStrings();
}

std::size_t RawDataFormat::initSectionTableHashOffsets()
{
	return 0;
}

/**
 * Check entry point information validity
 * @return @c false if EP is out of VA space, @c true otherwise
 */
bool RawDataFormat::isEntryPointValid() const
{
	if((epAddress >= section->getAddress()) && (epAddress < section->getAddress() + bytes.size()))
	{
		return true;
	}

	return false;
}

retdec::utils::Endianness RawDataFormat::getEndianness() const
{
	return endianness;
}

std::size_t RawDataFormat::getBytesPerWord() const
{
	return bytesPerWord;
}

std::size_t RawDataFormat::getByteLength() const
{
	return bytesLength;
}

bool RawDataFormat::hasMixedEndianForDouble() const
{
	return false;
}

std::size_t RawDataFormat::getDeclaredFileLength() const
{
	return getFileLength();
}

bool RawDataFormat::areSectionsValid() const
{
	return true;
}

bool RawDataFormat::isObjectFile() const
{
	return false;
}

bool RawDataFormat::isDll() const
{
	return false;
}

bool RawDataFormat::isExecutable() const
{
	return true;
}

bool RawDataFormat::getMachineCode(unsigned long long &result) const
{
	return false;
}

bool RawDataFormat::getAbiVersion(unsigned long long &result) const
{
	return false;
}

bool RawDataFormat::getImageBaseAddress(unsigned long long &imageBase) const
{
	return false;
}

bool RawDataFormat::getEpAddress(unsigned long long &result) const
{
	if(hasEntryPoint && isEntryPointValid())
	{
		result = epAddress;
	}
	else
	{
		result = section->getAddress();
	}
	return true;
}

bool RawDataFormat::getEpOffset(unsigned long long &result) const
{
	if(hasEntryPoint && isEntryPointValid())
	{
		// Compute offset
		result = epAddress - section->getAddress();
	}
	else
	{
		// Not set - decompilation will start from beginning
		result = 0x0;
	}
	return true;
}

Architecture RawDataFormat::getTargetArchitecture() const
{
	return architecture;
}

std::size_t RawDataFormat::getDeclaredNumberOfSections() const
{
	return getNumberOfSections();
}

std::size_t RawDataFormat::getDeclaredNumberOfSegments() const
{
	return getNumberOfSegments();
}

std::size_t RawDataFormat::getSectionTableOffset() const
{
	return 0;
}

std::size_t RawDataFormat::getSectionTableEntrySize() const
{
	return 0;
}

std::size_t RawDataFormat::getSegmentTableOffset() const
{
	return 0;
}

std::size_t RawDataFormat::getSegmentTableEntrySize() const
{
	return 0;
}

/**
 * Set binary code architecture
 * @param a Architecture
 */
void RawDataFormat::setTargetArchitecture(Architecture a)
{
	architecture = a;
}

/**
 * Set binary code endianness
 * @param e Endianness
 */
void RawDataFormat::setEndianness(Endianness e)
{
	endianness = e;
}

/**
 * Set word size
 * @param b Word size in bytes
 */
void RawDataFormat::setBytesPerWord(std::size_t b)
{
	bytesPerWord = b;
}

/**
 * Set byte length
 * @param l Byte length in bits
 */
void RawDataFormat::setBytesLength(std::size_t l)
{
	bytesLength = l;
}

/**
 * Set entry point address
 * @param entryPoint Entry point address
 */
void RawDataFormat::setEntryPoint(Address entryPoint)
{
	hasEntryPoint = true;
	epAddress = entryPoint;
}

/**
 * Set section base address
 * @param baseAddress Section base address
 */
void RawDataFormat::setBaseAddress(Address baseAddress)
{
	section->setAddress(baseAddress);
}

/**
 * Dump section data
 * @return Dump of section data
 */
std::string RawDataFormat::dumpData() const
{
	std::vector<unsigned char> d;
	if(!section || !section->getBytes(d))
	{
		return std::string();
	}

	std::stringstream ss;
	ss << section->getName()
		<< " @ " << section->getAddress()
		<< " has " << std::dec << d.size()
		<< " = 0x" << std::hex << d.size() << " bytes\n";

	const std::size_t lineLength = 8;
	std::size_t cntr = 0;
	std::string line;

	for(std::size_t i = 0, e = d.size(); i < e; ++i)
	{
		auto c = d[i];
		if(!cntr)
		{
			ss << std::hex << std::setfill('0')
				<< std::setw(8) << (section->getAddress() + i) << ": ";
		}
		ss << std::hex << std::setfill('0') << std::setw(2) << int(c);
		line += isprint(c) ? c : '.';
		++cntr;
		if(cntr == lineLength)
		{
			ss << "  |" << line << "|\n";
			cntr = 0;
			line.clear();
		}
		else if(i == (e - 1))
		{
			for (; cntr != lineLength; ++cntr)
			{
				ss << "   ";
				line += " ";
			}
			ss << "  |" << line << "|\n";
		}
		else
		{
			ss << " ";
		}
	}

	return ss.str();
}

} // namespace fileformat
} // namespace retdec
