/**
 * @file include/retdec/loader/loader/coff/coff_image.h
 * @brief Declaration of loadable COFF image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_COFF_COFF_IMAGE_H
#define RETDEC_LOADER_RETDEC_LOADER_COFF_COFF_IMAGE_H

#include <string>

#include "retdec/loader/loader/image.h"

namespace retdec {
namespace loader {

class CoffImage : public Image
{
public:
	CoffImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat);
	virtual ~CoffImage();

	virtual bool load() override;

protected:
	Segment* addSegment(const retdec::fileformat::Section* section, std::uint64_t address, std::uint64_t memSize);

	void applyRelocations();
	void resolveRelocation(const retdec::fileformat::Relocation& rel, const retdec::fileformat::Symbol& sym);
};

} // namespace loader
} // namespace retdec

#endif
