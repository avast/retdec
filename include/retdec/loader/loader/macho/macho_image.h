/**
 * @file include/retdec/loader/loader/macho/macho_image.h
 * @brief Declaration of loadable Mach-O image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_MACHO_MACHO_IMAGE_H
#define RETDEC_LOADER_RETDEC_LOADER_MACHO_MACHO_IMAGE_H

#include <unordered_map>
#include <vector>

#include "retdec/loader/loader/image.h"

namespace retdec {
namespace loader {

class MachOImage : public Image
{
	using SectionList = std::vector<const retdec::fileformat::MachOSection*>;
	using SegmentToSectionsTable = std::unordered_map<std::string, SectionList>;
public:
	MachOImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat);
	virtual ~MachOImage();

	virtual bool load() override;

protected:
	bool loadObjectFile();
	bool loadExecutableFile();

	SegmentToSectionsTable mapSegmentsToSections() const;
	const Segment* addSegment(const retdec::fileformat::SecSeg* secSeg);
};

} // namespace loader
} // namespace retdec

#endif
