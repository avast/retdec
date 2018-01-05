/**
 * @file include/retdec/loader/loader/raw_data/raw_data_image.h
 * @brief Declaration of loadable raw data image class for testing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_RAW_DATA_RAW_DATA_IMAGE_H
#define RETDEC_LOADER_RETDEC_LOADER_RAW_DATA_RAW_DATA_IMAGE_H

#include <cassert>
#include <string>

#include "retdec/loader/loader/image.h"

namespace retdec {
namespace loader {

/**
 * This class serves as loader for @c RawDataFormat from @c fileformat.
 * It just loads exactly one section from @c RawDataFormat as segment.
 * It is possible to reload it if section's configuration changes.
 */
class RawDataImage : public Image
{
public:
	RawDataImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat);
	virtual ~RawDataImage() override;

	virtual bool load() override;
	bool reload();
};

} // namespace loader
} // namespace retdec

#endif
