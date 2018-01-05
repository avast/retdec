/**
 * @file src/config/file_type.cpp
 * @brief Decompilation configuration manipulation: file type.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <string>
#include <vector>

#include "retdec/config/file_type.h"

namespace {

const std::vector<std::string> ftStrings =
{
	"unknown",
	"shared",
	"archive",
	"object",
	"executable"
};

} // anonymous namespace

namespace retdec {
namespace config {

bool FileType::isUnknown() const    { return _fileType == FT_UNKNOWN; }
bool FileType::isKnown() const      { return _fileType != FT_UNKNOWN; }
bool FileType::isShared() const     { return _fileType == FT_SHARED; }
bool FileType::isArchive() const    { return _fileType == FT_ARCHIVE; }
bool FileType::isObject() const     { return _fileType == FT_OBJECT; }
bool FileType::isExecutable() const { return _fileType == FT_EXECUTABLE; }

void FileType::setIsUnknown()    { _fileType = FT_UNKNOWN; }
void FileType::setIsShared()     { _fileType = FT_SHARED; }
void FileType::setIsArchive()    { _fileType = FT_ARCHIVE; }
void FileType::setIsObject()     { _fileType = FT_OBJECT; }
void FileType::setIsExecutable() { _fileType = FT_EXECUTABLE; }

/**
 * Returns JSON string value holding file type information.
 * @return JSON string value.
 */
Json::Value FileType::getJsonValue() const
{
	if (ftStrings.size() > static_cast<size_t>(_fileType))
	{
		return ftStrings[ static_cast<size_t>(_fileType) ];
	}
	else
	{
		return ftStrings[ static_cast<size_t>(FT_UNKNOWN) ];
	}
}

/**
 * Reads JSON string value holding file type information.
 * @param val JSON string value.
 */
void FileType::readJsonValue(const Json::Value& val)
{
	if ( val.isNull() )
	{
		return;
	}

	std::string enumStr = safeGetString(val);
	auto it = std::find(ftStrings.begin(), ftStrings.end(), enumStr);
	if (it == ftStrings.end())
	{
		_fileType = FT_UNKNOWN;
	}
	else
	{
		_fileType = static_cast<eFileType>( std::distance(ftStrings.begin(), it) );
	}
}

} // namespace config
} // namespace retdec
