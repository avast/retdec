/**
 * @file src/fileformat/types/strings/string.cpp
 * @brief Class for string in the file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/strings/string.h"

namespace retdec {
namespace fileformat {

StringType String::getType() const
{
	return type;
}

std::uint64_t String::getFileOffset() const
{
	return fileOffset;
}

const std::string& String::getSectionName() const
{
	return sectionName;
}

const std::string& String::getContent() const
{
	return content;
}

bool String::isAscii() const
{
	return type == StringType::Ascii;
}

bool String::isWide() const
{
	return type == StringType::Wide;
}

void String::setType(StringType stringType)
{
	type = stringType;
}

void String::setFileOffset(std::uint64_t stringFileOffset)
{
	fileOffset = stringFileOffset;
}

void String::setSectionName(const std::string& stringSectionName)
{
	sectionName = stringSectionName;
}

void String::setSectionName(std::string&& stringSectionName)
{
	sectionName = std::move(stringSectionName);
}

void String::setContent(const std::string& stringContent)
{
	content = stringContent;
}

void String::setContent(std::string&& stringContent)
{
	content = std::move(stringContent);
}

bool String::operator<(const String& rhs) const
{
	return (fileOffset < rhs.fileOffset)
		|| (fileOffset == rhs.fileOffset && type < rhs.getType())
		|| (fileOffset == rhs.fileOffset && type == rhs.type && content < rhs.content);
}

bool String::operator==(const String& rhs) const
{
	return (fileOffset == rhs.fileOffset) && (type == rhs.type) && (content == rhs.content);
}

bool String::operator!=(const String& rhs) const
{
	return !(*this == rhs);
}

} // namespace fileformat
} // namespace retdec
