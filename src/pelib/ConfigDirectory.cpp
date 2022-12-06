/**
 * @file src/pelib/ConfigDirectory.cpp
 * @brief Class representing Load Config Directory of PE file
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "retdec/pelib/ConfigDirectory.h"

namespace PeLib {
/**
 * @param imageLoader A valid image loader reference which is necessary because some RVA calculations need to be done.
 **/

int ConfigDirectory::read(ImageLoader& imageLoader)
{
	this->is64bit = imageLoader.getImageBitability();

	std::uint32_t loadRva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);

	bool readSuccess = false;

	if (this->is64bit)
	{
		readSuccess = imageLoader.readImage(&this->dir64, loadRva, sizeof(dir64)) == sizeof(dir64);
	}
	else
	{
		readSuccess = imageLoader.readImage(&this->dir32, loadRva, sizeof(dir32)) == sizeof(dir32);
	}

	return readSuccess ? ERROR_NONE : ERROR_INVALID_FILE;
}

std::uint32_t ConfigDirectory::getTimeDateStamp() const
{
	return is64bit ? dir64.TimeDateStamp : dir32.TimeDateStamp;
}

} // namespace PeLib