/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/pattern_matches_plain_getter.cpp
 * @brief Methods of PatternMatchesPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/pattern_matches_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t dirDistributionArray[] = {2, 11, 11, 11, 11, 9, 9};
const std::string dirHeaderArray[] = {"  ", "offset", "address", "size", "entrySize", "isInt", "isFloat"};
const std::string dirHeaderDesc[] = {"  ", "offset in file", "start address in memory", "size in bytes",
									"size in bytes of each entry in pattern", "true if pattern entries are integer numbers",
									"true if pattern entries are floating point numbers"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 * @param pMatches Detected matches
 */
PatternMatchesPlainGetter::PatternMatchesPlainGetter(FileInformation &fileInfo, const std::vector<PatternMatch> &pMatches) :
	IterativeDistributionGetter(fileInfo), matches(pMatches)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(matches.size());
	numberOfExtraElements.push_back(0);
	title = "";
	distribution.insert(distribution.begin(), std::begin(dirDistributionArray), std::end(dirDistributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(dirHeaderArray), std::end(dirHeaderArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(dirHeaderDesc), std::end(dirHeaderDesc));
	loadRecords();
}

/**
 * Destrcutor
 */
PatternMatchesPlainGetter::~PatternMatchesPlainGetter()
{

}

std::size_t PatternMatchesPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();
	return 0;
}

bool PatternMatchesPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(" ");
	unsigned long long val;
	record.push_back(matches[recIndex].getOffset(val) ? numToStr(val, hexWithPrefix) : "");
	record.push_back(matches[recIndex].getAddress(val) ? numToStr(val, hexWithPrefix) : "");
	record.push_back(matches[recIndex].getDataSize(val) ? numToStr(val, hexWithPrefix) : "");
	record.push_back(matches[recIndex].getEntrySize(val) ? numToStr(val, std::dec) : "");
	record.push_back(matches[recIndex].isInteger() ? "yes" : "no");
	record.push_back(matches[recIndex].isFloatingPoint() ? "yes" : "no");

	return true;
}

bool PatternMatchesPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
