/**
 * @file include/loader/loader/macho/macho_image.h
 * @brief Declaration of loadable Mach-O image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_LOADER_MACHO_MACHO_IMAGE_H
#define LOADER_LOADER_MACHO_MACHO_IMAGE_H

#include <unordered_map>
#include <vector>

#include "loader/loader/image.h"

namespace loader {

class MachOImage : public Image
{
	using SectionList = std::vector<const fileformat::MachOSection*>;
	using SegmentToSectionsTable = std::unordered_map<std::string, SectionList>;
public:
	MachOImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);
	virtual ~MachOImage();

	virtual bool load() override;

protected:
	bool loadObjectFile();
	bool loadExecutableFile();

	SegmentToSectionsTable mapSegmentsToSections() const;
	const Segment* addSegment(const fileformat::SecSeg* secSeg);
};

} // namespace loader

#endif
