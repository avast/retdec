/**
 * @file include/loader/loader/elf/elf_image.h
 * @brief Declaration of loadable ELF image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_LOADER_ELF_ELF_IMAGE_H
#define LOADER_LOADER_ELF_ELF_IMAGE_H

#include <string>
#include <unordered_map>
#include <vector>

#include "loader/loader/image.h"

namespace loader {

class ElfImage : public Image
{
	/**
	 * Holds information about mapping of section in segment. This information consits of
	 * pointer to fileformat section, offset of the section in the file and size of the section in the file.
	 * The last 2 mentioned does not have to be equal to the offset and size in the section table.
	 * Section might be on the boundary of the segment and therefore can start at bigger offset or end
	 * prematurely. For BSS sections, size represents virtual size of BSS section.
	 */
	struct SectionMapInfo
	{
		SectionMapInfo(const fileformat::Section* section_, std::uint64_t offset_, std::uint64_t size_) :
			section(section_), offset(offset_), size(size_) {}

		SectionMapInfo(const SectionMapInfo& mapInfo) :
			section(mapInfo.section), offset(mapInfo.offset), size(mapInfo.size) {}

		const fileformat::Section* section;
		std::uint64_t offset;
		std::uint64_t size;
	};

	using SectionList = std::vector<const fileformat::ElfSection*>;
	using SegmentToSectionsTable = std::unordered_map<const fileformat::ElfSegment*, SectionList>;

public:
	ElfImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);
	virtual ~ElfImage();

	virtual bool load() override;

protected:
	bool loadExecutableFile();
	bool loadRelocatableFile();
	bool canLoadSections(const std::vector<fileformat::Section*>& sections) const;
	void fixBssSegments();
	void applyRelocations();
	void resolveRelocation(const fileformat::Relocation& rel, const fileformat::Symbol& sym);

	SegmentToSectionsTable createSegmentToSectionsTable();
	const Segment* addSegment(const fileformat::SecSeg* secSeg, std::uint64_t address, std::uint64_t memSize);
};

} // namespace loader

#endif
