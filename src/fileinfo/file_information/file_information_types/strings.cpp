/**
 * @file src/fileinfo/file_information/file_information_types/strings.cpp
 * @brief Strings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/strings.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 */
Strings::Strings() : strings(nullptr)
{

}

std::size_t Strings::getNumberOfStrings() const
{
	return strings ? strings->size() : 0;
}

std::string Strings::getStringFileOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const
{
	if (!strings || index >= strings->size())
		return {};

	return getNumberAsString(strings->at(index).getFileOffset(), format);
}

std::string Strings::getStringTypeStr(std::size_t index) const
{
	if (!strings || index >= strings->size())
		return {};

	return strings->at(index).isAscii() ? "ASCII" : "Wide";
}

std::string Strings::getStringSectionName(std::size_t index) const
{
	if (!strings || index >= strings->size())
		return {};

	return strings->at(index).getSectionName();
}

std::string Strings::getStringContent(std::size_t index) const
{
	if (!strings || index >= strings->size())
		return {};

	return strings->at(index).getContent();
}

void Strings::setStrings(const std::vector<retdec::fileformat::String> *detectedStrings)
{
	strings = detectedStrings;
}

bool Strings::hasRecords() const
{
	return !strings->empty();
}

} // namespace fileinfo
