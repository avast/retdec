/**
 * @file src/fileformat/utils/other.cpp
 * @brief Simple utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <map>

#include "retdec/utils/container.h"
#include "retdec/fileformat/utils/other.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

namespace
{

const std::map<Format, std::string> formatMap =
{
	{Format::PE, "PE"},
	{Format::ELF, "ELF"},
	{Format::COFF, "COFF"},
	{Format::MACHO, "Mach-O"},
	{Format::INTEL_HEX, "Intel HEX"},
	{Format::RAW_DATA, "Raw Data"}
};

const std::map<Architecture, std::vector<std::string>> architectureMap =
{
	{Architecture::X86, {"Intel x86"}},
	{Architecture::X86_64, {"Intel x86-64"}},
	{Architecture::ARM, {"ARM", "ARM + Thumb"}},
	{Architecture::POWERPC, {"PowerPC"}},
	{Architecture::MIPS, {"MIPS", "PIC32"}}
};

} // anonymous namespace

/**
 * Get real size of selected area in region
 * @param offset Start offset of selected area in region
 * @param requestedSize Requested size of selected area (0 means maximal size from @a offset to end of region)
 * @param regionSize Total size of region
 * @return Real size of selected area in region
 */
std::size_t getRealSizeInRegion(std::size_t offset, std::size_t requestedSize, std::size_t regionSize)
{
	if(offset >= regionSize)
	{
		return 0;
	}

	return (!requestedSize || offset + requestedSize > regionSize) ? regionSize - offset : requestedSize;
}

/**
 * Get file format name
 * @param format File format
 * @return Name of file format
 */
std::string getFileFormatNameFromEnum(Format format)
{
	return mapGetValueOrDefault(formatMap, format, "");
}

/**
 * Get list of all supported file formats
 * @return List of all supported file formats
 */
std::vector<std::string> getSupportedFileFormats()
{
	std::vector<std::string> result;

	for(const auto &item: formatMap)
	{
		result.push_back(item.second);
	}

	return result;
}

/**
 * Get list of all supported target architectures
 */
std::vector<std::string> getSupportedArchitectures()
{
	std::vector<std::string> result;

	for(const auto &i : architectureMap)
	{
		for(const auto &j : i.second)
		{
			result.push_back(j);
		}
	}

	return result;
}

} // namespace fileformat
} // namespace retdec
