/**
 * @file src/fileformat/file_format/intel_hex/intel_hex_format.cpp
 * @brief Definition of IntelHexFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <string>

#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 * @param pathToFile Path to input file
 * @param loadFlags Load flags
 */
IntelHexFormat::IntelHexFormat(std::string pathToFile, LoadFlags loadFlags) : FileFormat(pathToFile, loadFlags)
{
	initStructures();
}

/**
 * Constructor
 * @param inputStream Input stream
 * @param loadFlags Load flags
 */
IntelHexFormat::IntelHexFormat(std::istream &inputStream, LoadFlags loadFlags) : FileFormat(inputStream, loadFlags)
{
	initStructures();
}

/**
 * Destructor
 */
IntelHexFormat::~IntelHexFormat()
{

}

/**
 * Init internal structures
 */
void IntelHexFormat::initStructures()
{
	stateIsValid = parser.parseStream(fileStream);
	if(stateIsValid)
	{
		fileFormat = Format::INTEL_HEX;
		initializeSections();
		computeSectionTableHashes();
		loadStrings();
	}
}

/**
 * Copy sections from parser to @c IntelHexFormat representation
 */
void IntelHexFormat::initializeSections()
{
	for(auto &section : parser.sections)
	{
		auto *tmp = new Section;
		tmp->setName("ihex_section_" + std::to_string(section.index));
		tmp->setIndex(section.index);
		tmp->setAddress(section.address);
		tmp->setSizeInFile(section.data.size());
		tmp->setSizeInMemory(section.data.size());
		tmp->setMemory(true);
		tmp->setType(tmp->belong(parser.getEntryPoint()) ? SecSeg::Type::CODE : SecSeg::Type::CODE_DATA);
		sections.push_back(tmp);
	}

	std::sort(parser.sections.begin(), parser.sections.end());
	std::sort(sections.begin(), sections.end(),
		[] (const auto *a, const auto *b)
		{
			return a->getAddress() < b->getAddress();
		}
	);

	unsigned long long EIP = 0;
	if(parser.hasEntryPoint())
	{
		EIP = parser.getEntryPoint();
	}

	unsigned long long index = 0;
	unsigned long long sectionOffset = 0;

	for(const auto &section : parser.sections)
	{
		// Fill vector with serialized data
		serialized.insert(serialized.end(), section.data.begin(), section.data.end());
		// Set serialized offset of section
		sections[index]->setOffset(sectionOffset);
		// Set EP offset
		if(!epOffset && EIP && (EIP >= section.address && EIP < (section.address + section.data.size())))
		{
			epOffset = sectionOffset + (EIP - section.address);
		}
		sectionOffset += section.data.size();
		++index;
	}

	setLoadedBytes(&serialized);

	for(auto *section : sections)
	{
		section->load(this);
	}
}

std::size_t IntelHexFormat::initSectionTableHashOffsets()
{
	return 0;
}

retdec::utils::Endianness IntelHexFormat::getEndianness() const
{
	return endianness;
}

std::size_t IntelHexFormat::getBytesPerWord() const
{
	return bytesPerWord;
}

bool IntelHexFormat::hasMixedEndianForDouble() const
{
	return false;
}

std::size_t IntelHexFormat::getDeclaredFileLength() const
{
	return getLoadedFileLength();
}

bool IntelHexFormat::areSectionsValid() const
{
	return true;
}

bool IntelHexFormat::isObjectFile() const
{
	return false;
}

bool IntelHexFormat::isDll() const
{
	return false;
}

bool IntelHexFormat::isExecutable() const
{
	return true;
}

bool IntelHexFormat::getMachineCode(unsigned long long &result) const
{
	// Intel HEX does not provide such information
	return false;
}

bool IntelHexFormat::getAbiVersion(unsigned long long &result) const
{
	// Intel HEX does not provide such information
	return false;
}

bool IntelHexFormat::getImageBaseAddress(unsigned long long &imageBase) const
{
	// Intel HEX does not provide such information
	return false;
}

bool IntelHexFormat::getEpAddress(unsigned long long &result) const
{
	if(parser.hasEntryPoint())
	{
		result = parser.getEntryPoint();
		return true;
	}

	return false;
}

bool IntelHexFormat::getEpOffset(unsigned long long &epOffset) const
{
	if(parser.hasEntryPoint())
	{
		epOffset = this->epOffset;
		return true;
	}

	return false;
}

Architecture IntelHexFormat::getTargetArchitecture() const
{
	return architecture;
}

std::size_t IntelHexFormat::getDeclaredNumberOfSections() const
{
	return parser.sections.size();
}

std::size_t IntelHexFormat::getDeclaredNumberOfSegments() const
{
	// No segments in Intel HEX
	return 0;
}

std::size_t IntelHexFormat::getSectionTableOffset() const
{
	return 0;
}

std::size_t IntelHexFormat::getSectionTableEntrySize() const
{
	return 0;
}

std::size_t IntelHexFormat::getSegmentTableOffset() const
{
	return 0;
}

std::size_t IntelHexFormat::getSegmentTableEntrySize() const
{
	return 0;
}

/**
 * Set target architecture
 * @param a Target architecture
 */
void IntelHexFormat::setTargetArchitecture(Architecture a)
{
	architecture = a;
}

/**
 * Set endianness
 * @param e Endianness
 */
void IntelHexFormat::setEndianness(retdec::utils::Endianness e)
{
	endianness = e;
}

/**
 * Set bytes per word
 * @param b Bytes per word
 */
void IntelHexFormat::setBytesPerWord(std::size_t b)
{
	bytesPerWord = b;
}

} // namespace fileformat
} // namespace retdec
