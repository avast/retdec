/**
 * @file src/loader/loader/coff/coff_image.cpp
 * @brief Implementation of loadable PE image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>
#include <sstream>
#include <vector>

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader/coff/coff_image.h"
#include "retdec/loader/utils/range.h"

namespace retdec {
namespace loader {

CoffImage::CoffImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat) : Image(fileFormat)
{
}

CoffImage::~CoffImage()
{
}

/**
 * Virtual method overridden from retdec::loader::Image, which is used in image factory.
 * Loads the image using @c fileformat.
 *
 * @return True if loading was successful, otherwise false.
 */
bool CoffImage::load()
{
	const auto& sections = getFileFormat()->getSections();

	// If not sections present, just end with error.
	if (sections.empty())
		return false;

	// Do a reverse mapping, from section indices to symbols that link to that particular section.
	std::unordered_map<std::uint32_t, std::vector<retdec::fileformat::Symbol*>> secIndexToSyms;
	for (auto& symbolTable : getFileFormat()->getSymbolTables())
	{
		for (auto& symbol : *symbolTable)
		{
			unsigned long long sectionIndex;
			if (!symbol->getLinkToSection(sectionIndex))
				continue;

			secIndexToSyms[sectionIndex].push_back(symbol.get());
		}
	}

	std::uint64_t nextFreeAddress = 0;
	for (auto& section : sections)
	{
		std::uint64_t address = nextFreeAddress;

		// Fix symbol addresses to this section.
		auto itr = secIndexToSyms.find(section->getIndex());
		if (itr != secIndexToSyms.end())
		{
			for (auto& symbol : itr->second)
			{
				unsigned long long symbolAddress;
				if (!symbol->getAddress(symbolAddress))
					continue;

				symbol->setAddress(address + symbolAddress);
			}
		}

		// Skip BSS sections with absolutely no size
		if (section->isBss() && section->getLoadedSize() == 0)
			continue;

		if (!addSegment(section, address, section->getLoadedSize()))
			return false;

		// Next free address is now behind this section.
		nextFreeAddress = address + section->getLoadedSize();
	}

	applyRelocations();
	setBaseAddress(0);

	return true;
}

Segment* CoffImage::addSegment(const retdec::fileformat::Section* section, std::uint64_t address, std::uint64_t memSize)
{
	std::unique_ptr<SegmentDataSource> dataSource;
	// Do not load BSS sections from file.
	if (!section->isBss())
	{
		llvm::StringRef sectionContent = section->getBytes();
		dataSource.reset(new SegmentDataSource(sectionContent));
	}

	return insertSegment(std::make_unique<Segment>(section, address, memSize, std::move(dataSource)));
}

void CoffImage::applyRelocations()
{
	for (const auto* relTable : getFileFormat()->getRelocationTables())
	{
		if (relTable->getLinkToSymbolTable() >= getFileFormat()->getNumberOfSymbolTables())
			continue;

		const auto* symTab = getFileFormat()->getSymbolTable(relTable->getLinkToSymbolTable());
		for (const auto& rel : *relTable)
		{
			unsigned long long symbolIndex;
			if (!rel.getLinkToSymbol(symbolIndex))
				continue;

			const auto* sym = symTab->getSymbolWithIndex(symbolIndex);
			unsigned long long symbolAddress;
			if (!sym->getAddress(symbolAddress))
				continue;

			resolveRelocation(rel, *sym);
		}
	}
}

void CoffImage::resolveRelocation(const retdec::fileformat::Relocation& rel, const retdec::fileformat::Symbol& sym)
{
	unsigned long long symbolAddress;
	if (!sym.getAddress(symbolAddress))
		return;

	switch (getFileFormat()->getTargetArchitecture())
	{
		case retdec::fileformat::Architecture::X86:
		{
			switch (rel.getType())
			{
				case llvm::COFF::IMAGE_REL_I386_DIR32:
				case llvm::COFF::IMAGE_REL_I386_DIR32NB: // ImageBase is 0 for COFFs so we can use same relocation algorithm as DIR32
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symbolAddress;
					set4Byte(rel.getAddress(), value);
					break;
				}
				case llvm::COFF::IMAGE_REL_I386_REL32:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symbolAddress - (rel.getAddress() + 4);
					set4Byte(rel.getAddress(), value);
					break;
				}
				default:
					break;
			}
			break;
		}
		case retdec::fileformat::Architecture::ARM:
		{
			switch (rel.getType())
			{
				case llvm::COFF::IMAGE_REL_ARM_ADDR32:
				case llvm::COFF::IMAGE_REL_ARM_ADDR32NB: // ImageBase is 0 for COFFs so we can use same relocation algorithm as ADDR32
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symbolAddress;
					set4Byte(rel.getAddress(), value);
					break;
				}
				case llvm::COFF::IMAGE_REL_ARM_BRANCH24:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					std::uint64_t copy = value;
					// jumps/calls are on per-instruction level
					value += (symbolAddress - rel.getSectionOffset()) >> 2;
					// 24 bit relocation
					value = (copy & 0xFF000000) | (value & 0x00FFFFFF);
					set4Byte(rel.getAddress(), value);
					break;
				}
				default:
					break;
			}
			break;
		}
		default:
			break;
	}
}

} // namespace loader
} // namespace retdec
