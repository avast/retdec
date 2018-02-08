/**
 * @file src/cpdetect/utils/version_solver.cpp
 * @brief Function for detection of version stored in string.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <regex>
#include <vector>

#include "retdec/utils/conversion.h"
#include "retdec/cpdetect/utils/version_solver.h"

using namespace retdec::utils;

namespace retdec {
namespace cpdetect {

namespace
{

/**
 * Separate each subversion and store them into @a res
 * @param version Version
 * @param res Into this parameter the subversions are stored
 * @return Number of subversions
 *
 * Before loading subversions, everything from vector @a res is deleted.
 */
std::size_t separateVersions(const std::string &version, std::vector<std::string> &res)
{
	res.clear();
	std::size_t actPos, lastPos = 0;

	while ((actPos = version.find('.', lastPos)) != std::string::npos)
	{
		res.push_back(version.substr(lastPos, actPos - lastPos));
		lastPos = actPos + 1;
	}

	res.push_back(version.substr(lastPos));
	return res.size();
}

} // anonymous namespace

/**
 * Search for version stored in input string
 * @param input Input string
 * @param result Into this parameter the resulting version is stored
 * @return @c true if version was detected, @c false otherwise
 *
 * A version is considered to be a substring which consisting of numbers (and dots).
 * If input string contains more versions, result contains only the first one.
 *
 * If version is not found, @a result is left unchanged.
 */
bool getVersion(const std::string &input, std::string &result)
{
	std::smatch match;
	if (regex_search(input, match, std::regex("([0-9]+\\.)+[0-9]+")))
	{
		result = match.str();
		return true;
	}

	return false;
}

/**
 * Compare two versions
 * @param aVer First version
 * @param bVer Second version
 * @param result Into this parameter the result is stored.
 * @return @c true if @a aVer and @a bVer parameters represents valid version, @c false otherwise
 *
 * If function return @c false, @a result is left unchanged. Otherwise, @a result contains number
 * smaller than 0 if first version is smaller than second version, 0 if both versions are equal,
 * or number greater than 0 if first version is greater than second version.
 */
bool compareVersions(const std::string &aVer, const std::string &bVer, int &result)
{
	std::string tmp;
	if (!getVersion(aVer, tmp) || tmp != aVer || !getVersion(bVer, tmp) || tmp != bVer)
	{
		return false;
	}

	std::vector<std::string> ver1, ver2;
	const auto ver1Len = separateVersions(aVer, ver1);
	const auto ver2Len = separateVersions(bVer, ver2);
	std::size_t a = 0, b = 0;

	for (std::size_t i = 0, e = std::min(ver1Len, ver2Len); i < e; ++i)
	{
		if (!strToNum(ver1[i], a) || !strToNum(ver2[i], b))
		{
			return false;
		}
		else if (a > b)
		{
			result = 1;
			return true;
		}
		else if (a < b)
		{
			result = -1;
			return true;
		}
	}

	if (ver1Len > ver2Len)
	{
		result = 1;
	}
	else if (ver2Len > ver1Len)
	{
		result = -1;
	}
	else
	{
		result = 0;
	}

	return true;
}

} // namespace cpdetect
} // namespace retdec
