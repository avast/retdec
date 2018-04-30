/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/elf_core_map_plain_getter.cpp
 * @brief Methods of ElfCoreMapPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/elf_core_map_plain_getter.h"
#include "retdec/utils/conversion.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t headerDistArr[] = {5, 18, 10, 5, 40};

const std::string headerNameArr[] = {
	"i", "address", "size", "page", "path"
};

const std::string headerDescArr[] = {
	"index", "address", "size", "page offset", "path"
};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
ElfCoreMapPlainGetter::ElfCoreMapPlainGetter(
		FileInformation &fileInfo)
	: IterativeDistributionGetter(fileInfo)
{
	const auto& fMap = fileinfo.getElfCoreInfo().getFileMap();

	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fMap.size());
	numberOfExtraElements.push_back(0);

	title = "Core file map";
	distribution.insert(
				distribution.begin(),
				std::begin(headerDistArr),
				std::end(headerDistArr));
	commonHeaderElements.insert(
				commonHeaderElements.begin(),
				std::begin(headerNameArr),
				std::end(headerNameArr));
	commonHeaderDesc.insert(
				commonHeaderDesc.begin(),
				std::begin(headerDescArr),
				std::end(headerDescArr));
	loadRecords();
}

/**
 * Destructor
 */
ElfCoreMapPlainGetter::~ElfCoreMapPlainGetter()
{
}

std::size_t ElfCoreMapPlainGetter::getBasicInfo(
		std::size_t structIndex,
		std::vector<std::string> &desc,
		std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	const auto& fMap = fileinfo.getElfCoreInfo().getFileMap();
	desc.push_back("Number of entries: ");
	info.push_back(numToStr(fMap.size()));

	return info.size();
}

bool ElfCoreMapPlainGetter::loadRecord(
		std::size_t structIndex,
		std::size_t recIndex,
		std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures
			|| recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	auto& entry = fileinfo.getElfCoreInfo().getFileMap()[recIndex];

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(toHex(entry.address, true));
	record.push_back(std::to_string(entry.size));
	record.push_back(std::to_string(entry.page));
	record.push_back(replaceNonprintableChars(entry.path));

	return true;
}

bool ElfCoreMapPlainGetter::getFlagDescriptors(
		std::size_t structIndex,
		std::vector<std::string> &desc,
		std::vector<std::string> &abbv) const
{
	if(structIndex >= numberOfStructures)
	{
		return false;
	}

	desc.clear();
	abbv.clear();

	return true;
}

} // namespace fileinfo
