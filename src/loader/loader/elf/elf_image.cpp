/**
 * @file src/loader/loader/elf/elf_image.cpp
 * @brief Implementation  of loadable ELF image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <functional>
#include <iterator>
#include <memory>
#include <sstream>
#include <vector>

#include <elfio/elfio.hpp>

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader/elf/elf_image.h"
#include "retdec/loader/utils/overlap_resolver.h"
#include "retdec/loader/utils/range.h"
#include "retdec/common/address.h"

#define R_AARCH64_CALL26 283
#define R_AARCH64_ADR_PRE 275
#define R_AARCH64_ADD_ABS 277

namespace retdec {
namespace loader {

ElfImage::ElfImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat) : Image(fileFormat)
{
}

/**
 * Virtual method overridden from retdec::loader::Image, which is used in image factory.
 * Loads the image using @c fileformat.
 *
 * @return True if loading was successful, otherwise false.
 */
bool ElfImage::load()
{
	// Can this even happen? Anyways, if we have no segments nor sections, there is nothing to load
	if (getFileFormat()->getSegments().empty() && getFileFormat()->getSections().empty())
		return false;

	// Object files are not generally loadable, but we will simulate loading of them
	bool ret = false;
	if (getFileFormat()->isObjectFile())
		ret = loadRelocatableFile();
	else
		ret = loadExecutableFile();

	if (!ret)
		return false;

	// This means no segments were loaded, we need to end, this is not OK
	if (getSegments().empty())
		return false;

	// Base address is determined by the address of first LOAD segment. The kernel does the same.
	setBaseAddress(getSegments().front()->getAddress());

	// Sort segment by their address
	sortSegments();

	// Fix sizes of BSS segments after we have loaded and sorted everything
	fixBssSegments();

	return true;
}

/**
 * Method to create segment containing extern functions.
 * Sets the correct attributes of newly created segment.
 */
void ElfImage::createExternSegment()
{
	// std::cout << "createExternSegment()" << std::endl;

	// Get the end address of last segment, we should expect that they are not sorted now.
	const auto& segments = getSegments();
	const auto last_segment = std::max_element(segments.begin(), segments.end(),
				  [](const auto& s1, const auto& s2) {
				      return s1->getEndAddress() < s2->getEndAddress(); });

	// Last segment not found
	if (last_segment == segments.end())
	{
		// Don't signal anything
		// std::cout << "createExternSegment: End address of last segment was not found." << std::endl;
		return;
	}
	// std::cout << "End address is: " << (*last_segment)->getEndAddress() << std::endl;

	// Get the size of ptr for this elf class
	const auto* elfInputFile = static_cast<const retdec::fileformat::ElfFormat*>(getFileFormat());
	// We are dealing with only 2 possibilities ELFCLASS{32, 64}, assume 8 byte default
	unsigned int cur_ptr_size = (elfInputFile->getElfClass() == ELFCLASS32) ? 4 : 8;

	std::uint64_t extern_function_index = 0;
	const auto* it = getFileFormat()->getImportTable();
	if (it == nullptr)
	{
		return;
	}

	// Iterate over imports and gather functions to be created
	for (const auto &imp : *it)
	{
		common::Address a = imp->getAddress();
		if (a.isUndefined())
		{
			continue;
		}

		if(_externFncTable.count(imp->getName()))
		{
			// std::cout << "Import " << imp->getName() << " already exists, skipping..." << std::endl;
			continue;
		}

		_externFncTable[imp->getName()] = (*last_segment)->getEndAddress() + extern_function_index;
		extern_function_index += cur_ptr_size;
	}

	std::uint64_t fake_segment_size = _externFncTable.size() * cur_ptr_size;
	//std::cout << "Fake segment size: " << fake_segment_size << std::endl;

	// for (const auto &s : _externFncTable)
	// {
	// 	std::cout << s.first << " @ " << std::showbase << std::hex << s.second << std::endl;
	// }

	retdec::fileformat::SecSeg *new_segment = new retdec::fileformat::ElfSegment();
	new_segment->setName(".EXTERN");
	new_segment->setType(retdec::fileformat::SecSeg::Type::DATA);

	// TODO(mato): For some reason decoder checks only physical size
	// This makes this segment size -> 1. Maybe it does not matter?
	new_segment->setSizeInMemory(fake_segment_size);
	new_segment->setSizeInFile(0);
	new_segment->setMemory(true);

	addSegment(new_segment, (*last_segment)->getEndAddress(), fake_segment_size);
}

bool ElfImage::loadExecutableFile()
{
	const auto* elfInputFile = static_cast<const retdec::fileformat::ElfFormat*>(getFileFormat());
	SegmentToSectionsTable segToSecsTable = createSegmentToSectionsTable();

	const auto& segments = elfInputFile->getSegments();
	for (const auto& segment : segments)
	{
		const auto* elfSegment = static_cast<const retdec::fileformat::ElfSegment*>(segment);

		// Skip non PT_LOAD segments
		if (elfSegment->getElfType() != PT_LOAD)
			continue;

		unsigned long long memSize;
		elfSegment->getSizeInMemory(memSize);
		std::uint64_t address = elfSegment->getAddress();

		// If both virtual and physical size are 0, ignore this segment
		if (elfSegment->getLoadedSize() == 0 && memSize == 0)
			continue;

		const auto& sectionsMapped = segToSecsTable[elfSegment];
		// No sections mapped to this segment, just map segment itself
		if (sectionsMapped.empty())
		{
			if (addSegment(elfSegment, address, memSize) == nullptr)
				return false;
		}
		else
		{
			if (sectionsMapped.size() == 1)
			{
				if (sectionsMapped[0]->isBss())
					setStatusMessage("Segment with single BSS section mapped to it. This may cause problems with instruction decoding.");
			}

			// Load sections instead of segment
			for (const auto& section : sectionsMapped)
			{
				// Calculate offset of the section relative to the start of the segment it is located in
				std::uint64_t inSegOffset = section->getAddress() - address;

				// For BSS sections, we still have to use getSizeInFile() because getLoadedSize() does not mean anything
				//   for these types of sections.
				std::uint64_t size = !section->isBss() ? section->getLoadedSize() : section->getSizeInFile();

				if (addSegment(section, address + inSegOffset, size) == nullptr)
					return false;
			}
		}
	}

	// In case we haven't loaded anything, try to fall back to loading it as relocatable file.
	// That means sections are considered as source of data for loader.
	if (getNumberOfSegments() == 0)
		return loadRelocatableFile();

	return true;
}

bool ElfImage::loadRelocatableFile()
{
	const auto* elfInputFile = static_cast<const retdec::fileformat::ElfFormat*>(getFileFormat());
	const auto& sections = getFileFormat()->getSections();

	// If sections are not loadable, we need to end here, no way to load this file
	if (!canLoadSections(sections))
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

	// If none of the sections has SHF_ALLOC flag, then just try to load all SHT_PROGBITS and SHT_NOBITS sections.
	std::function<bool(retdec::fileformat::ElfSection*)> canLoadSection = [](retdec::fileformat::ElfSection* elfSec) { return elfSec->getElfFlags() & SHF_ALLOC; };
	if (!std::any_of(sections.begin(), sections.end(), [&canLoadSection](retdec::fileformat::Section* sec) { return canLoadSection(static_cast<retdec::fileformat::ElfSection*>(sec)); }))
	{
		canLoadSection = [](retdec::fileformat::ElfSection* elfSec) { return (elfSec->getElfType() == SHT_PROGBITS || elfSec->getElfType() == SHT_NOBITS); };
	}

	for (auto& section : sections)
	{
		retdec::fileformat::ElfSection* elfSection = static_cast<retdec::fileformat::ElfSection*>(section);

		// This is the only thing we can rely on, even though it is not bullet proof solution
		if (!canLoadSection(elfSection))
			continue;

		// Fix section address
		// Use offset of the section instead
		std::uint64_t address = elfSection->getAddress();
		if (address == 0)
		{
			address = elfSection->getOffset() - elfInputFile->getBaseOffset();

			// Fix symbol addresses associated to this section
			auto itr = secIndexToSyms.find(elfSection->getIndex());
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
		}

		// For BSS sections, we still have to use getSizeInFile() because getLoadedSize() does not mean anything
		//   for these types of sections.
		std::uint64_t size = !section->isBss() ? section->getLoadedSize() : section->getSizeInFile();

		if (addSegment(section, address, size) == nullptr)
			return false;
	}

	createExternSegment();

	// Apply relocations
	applyRelocations();

	return true;
}

ElfImage::SegmentToSectionsTable ElfImage::createSegmentToSectionsTable()
{
	const auto& sections = getFileFormat()->getSections();
	const auto& segments = getFileFormat()->getSegments();

	SegmentToSectionsTable segToSecsTable;

	// Unable to do any mapping if sections are not loadable
	// Just create empty mapping with LOAD segments
	if (!canLoadSections(sections))
	{
		std::for_each(segments.begin(), segments.end(),
				[&segToSecsTable](retdec::fileformat::Segment* seg)
				{
					const auto* elfSeg = static_cast<const retdec::fileformat::ElfSegment*>(seg);
					if (elfSeg->getElfType() == PT_LOAD)
						segToSecsTable[elfSeg].clear();
				});
		return segToSecsTable;
	}

	for (const auto& seg : segments)
	{
		const auto* elfSeg = static_cast<const retdec::fileformat::ElfSegment*>(seg);

		// Mapping only for PT_LOAD segments
		if (elfSeg->getElfType() != PT_LOAD)
			continue;

		unsigned long long memSize;
		elfSeg->getSizeInMemory(memSize);
		std::uint64_t address = elfSeg->getAddress();
		std::uint64_t fileOffset = elfSeg->getOffset();
		std::uint64_t fileSize = elfSeg->getLoadedSize();
		std::uint64_t endAddress = address + (memSize ? memSize : 1);

		if (address > endAddress)
		{
			// Invalid data - return only partially loaded map
			return segToSecsTable;
		}

		retdec::common::Range<std::uint64_t> segRange = retdec::common::Range<std::uint64_t>(address, endAddress);

		for (const auto& sec : sections)
		{
			const retdec::fileformat::ElfSection* elfSec = static_cast<const retdec::fileformat::ElfSection*>(sec);

			// Skip SHT_NULL sections, they just populate address space with bogus values
			if (elfSec->getElfType() == SHT_NULL)
				continue;

			// Only sections with allocation flag
			if (!(elfSec->getElfFlags() & SHF_ALLOC))
				continue;

			// If section does not fall into physical range of segment and is not SHT_NOBITS sections, then skip this section
			// SHT_NOBITS sections have wrong offsets so we just assume they will work, even though we are not sure
			if ((elfSec->getElfType() != SHT_NOBITS) && ((elfSec->getOffset() < fileOffset) || (elfSec->getOffset() + elfSec->getLoadedSize() > fileOffset + fileSize)))
				continue;

			// There is something wrong with this section most probably. All offsets/addresses should be congruent.
			// Otherwise, assume that this section contains spurious data and do not use it.
			// Do not apply to SHT_NOBITS sections, which have basically the next free file offset set as their offset, so it does not
			//   always match this rule.
			if ((elfSec->getElfType() != SHT_NOBITS) && (address - elfSec->getAddress() != fileOffset - elfSec->getOffset()))
				continue;

			std::uint64_t start = elfSec->getAddress();
			std::uint64_t end = elfSec->getAddress() + (elfSec->getLoadedSize() ? elfSec->getLoadedSize() : 1);
			if (end < start)
			{
				continue;
			}

			auto overlapResult = OverlapResolver::resolve(segRange, retdec::common::Range<std::uint64_t>(start, end));
			switch (overlapResult.getOverlap())
			{
				// In case of no overlap, this section does not belong to the current segment, skip it
				case Overlap::None:
					continue;
				default:
					segToSecsTable[elfSeg].push_back(elfSec);
					break;
			}
		}

		// Sort sections by their starting virtual address
		std::stable_sort(segToSecsTable[elfSeg].begin(), segToSecsTable[elfSeg].end(),
				[](const retdec::fileformat::ElfSection* sec1, const retdec::fileformat::ElfSection* sec2)
				{
					return (sec1->getAddress() < sec2->getAddress());
				});
	}

	return segToSecsTable;
}

const Segment* ElfImage::addSegment(const retdec::fileformat::SecSeg* secSeg, std::uint64_t address, std::uint64_t memSize)
{
	std::unique_ptr<SegmentDataSource> dataSource;
	if (!secSeg->isBss())
	{
		llvm::StringRef secSegContent = secSeg->getBytes();
		dataSource = std::make_unique<SegmentDataSource>(secSegContent);
	}

	if (secSeg->getName() == ".EXTERN")
	{
		// std::vector<std::uint8_t> e(mem);
		unsigned long long mem;
		secSeg->getSizeInMemory(mem);
		_externFncData.resize(mem, 0);
		llvm::StringRef secSegContent = llvm::StringRef(reinterpret_cast<const char *>(_externFncData.data()), _externFncData.size());
		dataSource = std::make_unique<SegmentDataSource>(secSegContent);
	}

	std::uint64_t start = address;
	std::uint64_t end = memSize ? address + memSize : address + 1;

	if (start > end)
	{
		// This may happen with some broken binaries and may lead to abort
		return nullptr;
	}

	// Because we iterate over getSegments() here, we cannot afford to modify it during loop, it would break iterators.
	// We need to store what to add and remove and do it after the loop.
	// For removeList, we cannot use unique_ptr because we would move ownership of the object (segment) to removeList and
	// this would invalidate pointers in getSegments(). Theoretically, we could just then remove all segments from getSegments() that
	// point to nullptr, but this way, it is more intuitive and clear.
	std::vector<std::unique_ptr<Segment>> segmentsToInsert;
	std::vector<Segment*> segmentsToRemove;
	for (const auto& segment : getSegments())
	{
		auto overlapResult = OverlapResolver::resolve(segment->getAddressRange(), retdec::common::Range<std::uint64_t>(start, end));
		switch (overlapResult.getOverlap())
		{
			// In case of no overlap, just do nothing.
			case Overlap::None:
				break;
			// Full overlap means we completely overlapped existing segment and we are free to remove it.
			case Overlap::Full:
				segmentsToRemove.push_back(segment.get());
				break;
			// Shrink existing segment using the second range from the result.
			case Overlap::OverStart:
			{
				const retdec::common::Range<std::uint64_t>& newRange = overlapResult.getRanges()[1];
				segment->shrink(newRange.getStart(), newRange.getSize());
				break;
			}
			// Shrink existing segment using the first range from the result.
			case Overlap::OverEnd:
			{
				const retdec::common::Range<std::uint64_t>& newRange = overlapResult.getRanges()[0];
				segment->shrink(newRange.getStart(), newRange.getSize());
				break;
			}
			// Create copy of the existing segment and shrink the original one with the first range from the result.
			// Shrink the copied one with the third range from the result.
			case Overlap::InMiddle:
			{
				const retdec::common::Range<std::uint64_t>& newRange1 = overlapResult.getRanges()[0];
				const retdec::common::Range<std::uint64_t>& newRange2 = overlapResult.getRanges()[2];

				auto segmentCopy = std::make_unique<Segment>(*segment.get());
				segment->shrink(newRange1.getStart(), newRange1.getSize());
				segmentCopy->shrink(newRange2.getStart(), newRange2.getSize());

				segmentsToInsert.push_back(std::move(segmentCopy));
				break;
			}
			default:
				break;
		}
	}

	for (auto& segment : segmentsToRemove)
		removeSegment(segment);

	Segment* retSegment = insertSegment(std::make_unique<Segment>(secSeg, address, memSize, std::move(dataSource)));

	for (auto& segment : segmentsToInsert)
		insertSegment(std::move(segment));

	return retSegment;
}

bool ElfImage::canLoadSections(const std::vector<retdec::fileformat::Section*>& sections) const
{
	// First, filter out non-SHF_ALLOC sections
	std::vector<retdec::fileformat::Section*> allocSections;
	std::copy_if(sections.begin(), sections.end(), std::back_inserter(allocSections),
			[](const retdec::fileformat::Section* sec)
			{
				return (static_cast<const retdec::fileformat::ElfSection*>(sec)->getElfFlags() & SHF_ALLOC);
			});

	// If no SHF_ALLOC sections found, try to take all SHT_PROGBITS and SHT_NOBITS sections.
	if (allocSections.empty())
	{
		std::copy_if(sections.begin(), sections.end(), std::back_inserter(allocSections),
				[](const retdec::fileformat::Section* sec)
				{
					return (static_cast<const retdec::fileformat::ElfSection*>(sec)->getElfType() == SHT_PROGBITS ||
							static_cast<const retdec::fileformat::ElfSection*>(sec)->getElfType() == SHT_NOBITS);
				});
	}

	// Check whether all sections to be loaded have address and offset set to 0. If not, we cannot load this file properly.
	return !std::all_of(allocSections.begin(), allocSections.end(),
			[](const retdec::fileformat::Section* sec)
			{
				return (sec->getAddress() == 0 && sec->getOffset() == 0);
			});
}

void ElfImage::fixBssSegments()
{
	// We need to fix the size of BSS segments with size 0
	// We will fix it by resizing it to fill the gap between its end and the start of the next segment
	const auto& segments = getSegments();
	auto end = segments.end();
	for (auto itr = segments.begin(); itr != end; )
	{
		Segment* bssSegment = itr->get();

		// Only BSS segments with size of 0
		if (!bssSegment->getSecSeg()->isBss() || bssSegment->getSize() != 0)
		{
			++itr;
			continue;
		}

		// Move to the next segment
		++itr;

		// But current BSS segment can be last one
		if (itr == end)
		{
			// We need to find the segment in program headers such that this segment falls into its address range
			// But we may not have program headers in relocatable files -- at least resize it to the size of their alignment
			// There are not much things we can do about it
			const auto& programHeaders = getFileFormat()->getSegments();
			if (programHeaders.empty())
			{
				bssSegment->resize(static_cast<const retdec::fileformat::ElfSection*>(bssSegment->getSecSeg())->getElfAlign());
			}
			else
			{
				const retdec::fileformat::ElfSegment* programHeader = nullptr;
				for (const auto& phdr : programHeaders)
				{
					// Only PT_LOAD segments
					if (static_cast<const retdec::fileformat::ElfSegment*>(phdr)->getElfType() != PT_LOAD)
						continue;

					if (retdec::common::Range<std::uint64_t>(phdr->getAddress(), phdr->getEndAddress()).contains(bssSegment->getAddress()))
						programHeader = static_cast<const retdec::fileformat::ElfSegment*>(phdr);
				}

				// This BSS segment has size 0 for no apparent reason and should be kept its size
				if (programHeader == nullptr)
					continue;

				// Resize it up to the size of the whole segment
				unsigned long long phdrMemSize;
				programHeader->getSizeInMemory(phdrMemSize);
				bssSegment->resize(programHeader->getAddress() + phdrMemSize - bssSegment->getAddress());
			}

			continue;
		}
		// Otherwise just take the next one and resize
		else
		{
			const Segment* nextSegment = itr->get();
			bssSegment->resize(nextSegment->getAddress() - bssSegment->getAddress());
		}
	}
}

void ElfImage::applyRelocations()
{
	for (auto& relTable : getFileFormat()->getRelocationTables())
	{
		if (relTable->getLinkToSymbolTable() >= getFileFormat()->getNumberOfSymbolTables())
			continue;

		const auto* symTab = getFileFormat()->getSymbolTable(relTable->getLinkToSymbolTable());
		for (const auto& rel : *relTable)
		{
			unsigned long long symbolIndex;
			if (!rel.getLinkToSymbol(symbolIndex))
				continue;

			const auto* sym = symTab->getSymbol(symbolIndex);
			if (!sym)
				continue;

			unsigned long long symbolAddress;
			if (!sym->getAddress(symbolAddress))
				continue;

			// We are not able to handle EXTERN symbols relocation because they are not placed anywhere and it somehow causes problems in x86 decompilation
			// if (sym->getType() == retdec::fileformat::Symbol::Type::EXTERN)
			// 	continue;

			resolveRelocation(rel, *sym);
		}
	}
}

void ElfImage::resolveRelocation(const retdec::fileformat::Relocation& rel, const retdec::fileformat::Symbol& sym)
{
	unsigned long long symAddress;

	if (sym.getType() == retdec::fileformat::Symbol::Type::EXTERN)
	{
		const auto& extern_fnc_entry = getExternFncTable().find(sym.getName());
		if(extern_fnc_entry == getExternFncTable().end())
		{
			return;
		}
		else
		{
			symAddress = extern_fnc_entry->second;
		}
	}
	else
	{
		if (!sym.getAddress(symAddress))
		{
			return;
		}
	}

	// std::cout << std::showbase << "Processing relocation of "
	// 		  << sym.getName() << " @ " << std::hex << rel.getAddress()
	// 		  << " to " << symAddress << "+" << rel.getAddend() << std::endl;

	const auto* elfInputFile = static_cast<const retdec::fileformat::ElfFormat*>(getFileFormat());
	switch (getFileFormat()->getTargetArchitecture())
	{
		case retdec::fileformat::Architecture::X86:
		{
			switch (rel.getType())
			{
				case R_386_32:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symAddress + rel.getAddend();
					set4Byte(rel.getAddress(), value);
					break;
				}
				case R_386_PC32:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symAddress + rel.getAddend() - rel.getSectionOffset();
					set4Byte(rel.getAddress(), value);
					break;
				}
				// New - for extern segment
				case R_386_PLT32:
				{
					std::uint64_t value;
					value = symAddress - rel.getAddress() + rel.getAddend();
					set4Byte(rel.getAddress(), value);
					break;
				}
				default:
					return;
			}
			break;
		}
		case retdec::fileformat::Architecture::X86_64:
		{
			switch (rel.getType())
			{
				case R_X86_64_PC32:
				case R_X86_64_PLT32:
				{
					// These are needed for object files, they are probably wrong in the context of
					// linked executables
					if(getExternFncTable().size() == 0) break;
					std::uint64_t value;
					value = symAddress - rel.getAddress() + rel.getAddend();
					set4Byte(rel.getAddress(), value);
					break;
				}
				default:
					return;
			}
			break;
		}
		case retdec::fileformat::Architecture::ARM:
		{
			if (elfInputFile->getElfClass() == ELFCLASS32)
			{
				switch (rel.getType())
				{
					case R_ARM_ABS32:
					{
						std::uint64_t value;
						get4Byte(rel.getAddress(), value);
						value += symAddress + rel.getAddend();
						set4Byte(rel.getAddress(), value);
						break;
					}
					case R_ARM_CALL:
					{
						std::uint64_t value;
						get4Byte(rel.getAddress(), value);
						std::uint64_t copy = value;
						// jumps/calls are on per-instruction level
						value += (symAddress + rel.getAddend() - rel.getSectionOffset()) >> 2;
						// 24 bit relocation
						value = (copy & 0xFF000000) | (value & 0x00FFFFFF);
						set4Byte(rel.getAddress(), value);
						break;
					}
					default:
						return;
				}
			}
			else // AArch64 bit relocations
			{
				// These are needed for object files, they are probably wrong in the context of
				// linked executables
				switch (rel.getType())
				{
					case R_AARCH64_CALL26:
					{
						if(getExternFncTable().size() == 0) break;
						std::uint64_t value;
						get4Byte(rel.getAddress(), value);
						std::uint64_t copy = value;
						value += (symAddress + rel.getAddend() - rel.getSectionOffset()) >> 2;
						value = (copy & 0xFC000000) | (value & 0x03FFFFFF);
						set4Byte(rel.getAddress(), value);
						break;
					}
					case R_AARCH64_ADR_PRE:
					{
						if(getExternFncTable().size() == 0) break;
						std::uint64_t value;
						get4Byte(rel.getAddress(), value);
						std::uint64_t copy = value;
						value = ((symAddress + rel.getAddend() - rel.getSectionOffset()) >> 12 ) << 4;
						value = (copy & 0xFF00000F) | (value & 0x00FFFFF0);
						set4Byte(rel.getAddress(), value);
						break;
					}
					case R_AARCH64_ADD_ABS:
					{
						if(getExternFncTable().size() == 0) break;
						std::uint64_t value;
						get4Byte(rel.getAddress(), value);
						std::uint64_t copy = value;
						value = (symAddress + rel.getAddend()) << 10;
						value = (copy & 0xFFC000FF) | (value & 0x000FFF00);
						set4Byte(rel.getAddress(), value);
						break;
					}
					default:
						return;
				}
			}
			break;
		}
		case retdec::fileformat::Architecture::MIPS:
		{
			static const retdec::fileformat::Relocation* lastMipsHi16 = nullptr;
			static const retdec::fileformat::Relocation* prevMipsHi16 = nullptr;

			switch (rel.getType())
			{
				case R_MIPS_32:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symAddress + rel.getAddend();
					set4Byte(rel.getAddress(), value);
					break;
				}
				case R_MIPS_26:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					std::uint64_t copy = value;
					// 26 bit relocation with specific formula
					value += (symAddress + (rel.getAddend() | ((rel.getSectionOffset() + 4) & 0xF0000000))) >> 2;
					value = (copy & 0xFC000000) | (value & 0x03FFFFFF);
					set4Byte(rel.getAddress(), value);
					break;
				}
				case R_MIPS_HI16:
				{
					// Postpone this relocation until we find next R_MIPS_LO16 relocation
					lastMipsHi16 = &rel;
					break;
				}
				case R_MIPS_LO16:
				{
					// MIPS abi allows a single hi16 value to be used with multiple lo16 values
					// if lo16 is found without a matching hi16, use the previous hi16 value
					if (lastMipsHi16 == nullptr)
						lastMipsHi16 = prevMipsHi16;

					if (lastMipsHi16 == nullptr)
						return;

					std::uint64_t value, valueHi, valueLo;
					// +2 for operands of the instructions
					get2Byte(lastMipsHi16->getAddress() + 2, valueHi);
					get2Byte(rel.getAddress() + 2, valueLo);

					value = ((valueHi << 16) | valueLo) + rel.getAddend();
					value += symAddress;

					valueHi = (value >> 16) & 0xFFFF;
					valueLo = value & 0xFFFF;
					set2Byte(lastMipsHi16->getAddress() + 2, valueHi);
					set2Byte(rel.getAddress() + 2, valueLo);
					prevMipsHi16 = lastMipsHi16;
					lastMipsHi16 = nullptr;
					break;
				}
				default:
					return;
			}
			break;
		}
		case retdec::fileformat::Architecture::POWERPC:
		{
			static const retdec::fileformat::Relocation* lastPpcHi16 = nullptr;

			switch (rel.getType())
			{
				case R_PPC_ADDR32:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					value += symAddress + rel.getAddend();
					set4Byte(rel.getAddress(), value);
					break;
				}
				case R_PPC_ADDR16_HI:
				case R_PPC_ADDR16_HA:
				{
					// Postpone this relocation until we find next R_PPC_ADDR16_LO relocation
					lastPpcHi16 = &rel;
					break;
				}
				case R_PPC_ADDR16_LO:
				{
					if (lastPpcHi16 == nullptr)
						return;

					std::uint64_t value, valueHi, valueLo;
					get2Byte(lastPpcHi16->getAddress(), valueHi);
					get2Byte(rel.getAddress(), valueLo);

					// Handling of R_PPC_ADDR16_HA
					if (lastPpcHi16->getType() == R_PPC_ADDR16_HA)
						valueHi += (valueHi & 0x8000) ? 1 : 0;

					// Addend is ignored here because addend seems to be already written into valueLo
					value = (valueHi << 16) | valueLo;
					value += symAddress;

					valueHi = (value >> 16) & 0xFFFF;
					valueLo = value & 0xFFFF;
					set2Byte(lastPpcHi16->getAddress(), valueHi);
					set2Byte(rel.getAddress(), valueLo);
					lastPpcHi16 = nullptr;
					break;
				}
				case R_PPC_REL24:
				{
					std::uint64_t value;
					get4Byte(rel.getAddress(), value);
					std::uint64_t copy = value;
					// 24 bit relocation where bits 3-29 are used for relocations
					value = (value & 0x3FFFFFC) >> 2;
					value += (symAddress + rel.getAddend() - rel.getSectionOffset()) >> 2;
					value = (copy & 0xFC000003) | ((value << 2) & 0x3FFFFFC);
					set4Byte(rel.getAddress(), value);
					break;
				}
				default:
					return;
			}

			break;
		}
		default:
			return;
	}
}

} // namespace loader
} // namespace retdec
