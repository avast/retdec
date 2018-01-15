/**
 * @file include/retdec/loader/loader/pe/pe_image.h
 * @brief Declaration of loadable PE image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LOADER_RETDEC_LOADER_PE_PE_IMAGE_H
#define RETDEC_LOADER_RETDEC_LOADER_PE_PE_IMAGE_H

#include <string>

#include "retdec/loader/loader/image.h"

namespace retdec {
namespace loader {

class PeImage : public Image
{
public:
	PeImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat);
	virtual ~PeImage();

	virtual bool load() override;

protected:
	Segment* addSegment(const retdec::fileformat::Section* section, std::uint64_t address, std::uint64_t memSize);
	Segment* addSingleSegment(std::uint64_t address, std::vector<std::uint8_t>& content);

	bool canAddSegment(std::uint64_t address, std::uint64_t memSize) const;

	void loadNonDecodableAddressRanges();

private:
	std::unique_ptr<std::vector<std::uint8_t>> _singleSegment; ///< Used when there is no section present in the file.
};

} // namespace loader
} // namespace retdec

#endif
