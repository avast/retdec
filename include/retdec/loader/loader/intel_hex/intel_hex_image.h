/**
 * @file include/retdec/loader/loader/intel_hex/intel_hex_image.h
 * @brief Declaration of loadable Intel HEX image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_INTEL_HEX_INTEL_HEX_IMAGE_H
#define RETDEC_LOADER_RETDEC_LOADER_INTEL_HEX_INTEL_HEX_IMAGE_H

#include <string>

#include "retdec/loader/loader/image.h"

namespace loader {

class IntelHexImage : public Image
{
public:
	IntelHexImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);
	virtual ~IntelHexImage();

	virtual bool load() override;

protected:
	Segment* addSegment(const fileformat::Section* section, std::uint64_t address, std::uint64_t memSize);
};

} // namespace loader

#endif
