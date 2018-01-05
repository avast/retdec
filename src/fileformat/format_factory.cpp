/**
 * @file src/fileformat/format_factory.cpp
 * @brief Factory for creating file detectors.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/file_format/coff/coff_format.h"
#include "retdec/fileformat/file_format/elf/elf_format.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"
#include "retdec/fileformat/file_format/macho/macho_format.h"
#include "retdec/fileformat/file_format/pe/pe_format.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/fileformat/utils/format_detection.h"

namespace retdec {
namespace fileformat {

/**
 * Create instance of FileFormat class
 * @param filePath Path to input file
 * @param config Pointer to config used to detect raw data file format
 * @param loadFlags Load flags
 * @return Pointer to instance of FileFormat class or @c nullptr if any error
 *
 * If format of input file is not supported, function will return @c nullptr.
 */
std::unique_ptr<FileFormat> createFileFormat(const std::string &filePath, retdec::config::Config *config, LoadFlags loadFlags)
{
	switch(detectFileFormat(filePath, config))
	{
		case Format::PE:
			return std::make_unique<PeFormat>(filePath, loadFlags);
		case Format::ELF:
			return std::make_unique<ElfFormat>(filePath, loadFlags);
		case Format::COFF:
			return std::make_unique<CoffFormat>(filePath, loadFlags);
		case Format::MACHO:
			return std::make_unique<MachOFormat>(filePath, loadFlags);
		case Format::INTEL_HEX:
			return std::make_unique<IntelHexFormat>(filePath, loadFlags);
		case Format::RAW_DATA:
			return std::make_unique<RawDataFormat>(filePath, loadFlags);
		default:
			return nullptr;
	}
}

} // namespace fileformat
} // namespace retdec
