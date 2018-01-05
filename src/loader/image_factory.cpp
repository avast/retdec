/**
 * @file src/loader/image_factory.cpp
 * @brief Factory for creating loaded images.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/image_factory.h"
#include "retdec/loader/loader/coff/coff_image.h"
#include "retdec/loader/loader/elf/elf_image.h"
#include "retdec/loader/loader/image.h"
#include "retdec/loader/loader/intel_hex/intel_hex_image.h"
#include "retdec/loader/loader/macho/macho_image.h"
#include "retdec/loader/loader/pe/pe_image.h"
#include "retdec/loader/loader/raw_data/raw_data_image.h"

namespace retdec {
namespace loader {

namespace { // anonymous namespace

std::unique_ptr<Image> createImageImpl(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat)
{
	if (!fileFormat || !fileFormat->isInValidState())
		return nullptr;

	std::unique_ptr<Image> image;
	switch (fileFormat->getFileFormat())
	{
		case retdec::fileformat::Format::PE:
			image = std::make_unique<PeImage>(fileFormat);
			break;
		case retdec::fileformat::Format::ELF:
			image = std::make_unique<ElfImage>(fileFormat);
			break;
		case retdec::fileformat::Format::COFF:
			image = std::make_unique<CoffImage>(fileFormat);
			break;
		case retdec::fileformat::Format::INTEL_HEX:
			image = std::make_unique<IntelHexImage>(fileFormat);
			break;
		case retdec::fileformat::Format::MACHO:
			image = std::make_unique<MachOImage>(fileFormat);
			break;
		case retdec::fileformat::Format::RAW_DATA:
			image = std::make_unique<RawDataImage>(fileFormat);
			break;
		default:
			return nullptr;
	}

	if (!image->load())
		return nullptr;

	return image;
} // anonymous namespace

}

/**
 * Create instance of Image class from path to file.
 * If the input file cannot be loaded, function will return @c nullptr.
 * Loaded image becomes owner of the provided @c FileFormat.
 *
 * @param filePath Path to input file.
 * @param config Config used to determine if the input is a raw binary file format.
 *
 * @return Pointer to instance of Image class or @c nullptr if any error
 */
std::unique_ptr<Image> createImage(const std::string& filePath, retdec::config::Config *config)
{
	std::unique_ptr<retdec::fileformat::FileFormat> fileFormat = retdec::fileformat::createFileFormat(filePath, config);
	std::shared_ptr<retdec::fileformat::FileFormat> fileFormatShared(std::move(fileFormat)); // Obtain ownership.
	return createImageImpl(fileFormatShared);
}

/**
 * Create instance of Image class from existing file format instance.
 * If the input file cannot be loaded, function will return @c nullptr,
 * Loaded image does not become owner of the provided @c FileFormat.
 *
 * @param fileFormat File format.
 *
 * @return Pointer to instance of Image class or @c nullptr if any error
 */
std::unique_ptr<Image> createImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat)
{
	return createImageImpl(fileFormat);
}

} // namespace loader
} // namespace retdec
