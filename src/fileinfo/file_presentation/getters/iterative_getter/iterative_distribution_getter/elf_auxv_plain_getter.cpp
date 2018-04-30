/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/elf_auxv_plain_getter.cpp
 * @brief Methods of ElfAuxVPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/elf_auxv_plain_getter.h"
#include "retdec/utils/conversion.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t headerDistArr[] = {5, 22, 18};
const std::string headerNameArr[] = {"i", "name", "value"};
const std::string headerDescArr[] = {"index", "name", "value"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
ElfAuxVPlainGetter::ElfAuxVPlainGetter(
		FileInformation &fileInfo)
	: IterativeDistributionGetter(fileInfo)
{
	const auto& auxV = fileinfo.getElfCoreInfo().getAuxVector();

	numberOfStructures = 1;
	numberOfStoredRecords.push_back(auxV.size());
	numberOfExtraElements.push_back(0);

	title = "Auxiliary vector";
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
ElfAuxVPlainGetter::~ElfAuxVPlainGetter()
{
}

std::size_t ElfAuxVPlainGetter::getBasicInfo(
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

	const auto& auxV = fileinfo.getElfCoreInfo().getAuxVector();
	desc.push_back("Number of entries: ");
	info.push_back(numToStr(auxV.size()));

	return info.size();
}

bool ElfAuxVPlainGetter::loadRecord(
		std::size_t structIndex,
		std::size_t recIndex,
		std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures
			|| recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	auto& entry = fileinfo.getElfCoreInfo().getAuxVector()[recIndex];

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(entry.first);
	record.push_back(toHex(entry.second, true));

	return true;
}

bool ElfAuxVPlainGetter::getFlagDescriptors(
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
