/**
 * @file include/loader/loader/coff/coff_image.h
 * @brief Declaration of loadable COFF image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_LOADER_COFF_COFF_IMAGE_H
#define LOADER_LOADER_COFF_COFF_IMAGE_H

#include <string>

#include "loader/loader/image.h"

namespace loader {

class CoffImage : public Image
{
public:
	CoffImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);
	virtual ~CoffImage();

	virtual bool load() override;

protected:
	Segment* addSegment(const fileformat::Section* section, std::uint64_t address, std::uint64_t memSize);

	void applyRelocations();
	void resolveRelocation(const fileformat::Relocation& rel, const fileformat::Symbol& sym);
};

} // namespace loader

#endif
