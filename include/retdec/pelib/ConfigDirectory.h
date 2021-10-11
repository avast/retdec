/**
 * @file include/retdec/pelib/ConfigDirectory.h
 * @brief Class representing Load Config Directory of PE file
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PELIB_CONFIGDIRECTORY_H
#define RETDEC_PELIB_CONFIGDIRECTORY_H

#include "retdec/pelib/ImageLoader.h"

namespace PeLib {
/// Class that handles the Debug directory.
class ConfigDirectory
{
protected:
	PELIB_IMAGE_LOAD_CONFIG_DIRECTORY32 dir32 = { 0 };
	PELIB_IMAGE_LOAD_CONFIG_DIRECTORY64 dir64 = { 0 };
	bool is64bit = { 0 };

public:
	virtual ~ConfigDirectory() = default;

	int read(ImageLoader& imageLoader);

	std::uint32_t getTimeDateStamp() const;
};
} // namespace PeLib

#endif
