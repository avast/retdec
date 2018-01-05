/**
 * @file include/loader/loader/pe/pe_image.h
 * @brief Declaration of loadable PE image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_LOADER_PE_PE_IMAGE_H
#define LOADER_LOADER_PE_PE_IMAGE_H

#include <string>

#include "loader/loader/image.h"

namespace loader {

class PeImage : public Image
{
public:
	PeImage(const std::shared_ptr<fileformat::FileFormat>& fileFormat);
	virtual ~PeImage();

	virtual bool load() override;

protected:
	Segment* addSegment(const fileformat::Section* section, std::uint64_t address, std::uint64_t memSize);
	Segment* addSingleSegment(std::uint64_t address, std::vector<std::uint8_t>& content);

	bool canAddSegment(std::uint64_t address, std::uint64_t memSize) const;

	void loadNonDecodableAddressRanges();

private:
	std::unique_ptr<std::vector<std::uint8_t>> _singleSegment; ///< Used when there is no section present in the file.
};

} // namespace loader

#endif
