/**
 * @file include/loader/loader/raw_data/raw_data_image.h
 * @brief Declaration of loadable raw data image class for testing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_LOADER_RAW_DATA_RAW_DATA_IMAGE_H
#define LOADER_LOADER_RAW_DATA_RAW_DATA_IMAGE_H

#include <cassert>
#include <string>

#include "loader/loader/image.h"

namespace loader {

/**
 * This class serves as loader for @c RawDataFormat from @c fileformat.
 * It just loads exactly one section from @c RawDataFormat as segment.
 * It is possible to reload it if section's configuration changes.
 */
class RawDataImage : public Image
{
public:
	RawDataImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);
	virtual ~RawDataImage() override;

	virtual bool load() override;
	bool reload();
};

} // namespace loader

#endif
