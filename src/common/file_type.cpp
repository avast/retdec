/**
 * @file src/common/file_type.cpp
 * @brief Common file format representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <string>
#include <vector>

#include "retdec/common/file_type.h"

namespace retdec {
namespace common {

bool FileType::isUnknown() const    { return _fileType == FT_UNKNOWN; }
bool FileType::isKnown() const      { return _fileType != FT_UNKNOWN; }
bool FileType::isShared() const     { return _fileType == FT_SHARED; }
bool FileType::isArchive() const    { return _fileType == FT_ARCHIVE; }
bool FileType::isObject() const     { return _fileType == FT_OBJECT; }
bool FileType::isExecutable() const { return _fileType == FT_EXECUTABLE; }
FileType::eFileType FileType::getID() const { return _fileType; }

void FileType::setIsUnknown()    { _fileType = FT_UNKNOWN; }
void FileType::setIsShared()     { _fileType = FT_SHARED; }
void FileType::setIsArchive()    { _fileType = FT_ARCHIVE; }
void FileType::setIsObject()     { _fileType = FT_OBJECT; }
void FileType::setIsExecutable() { _fileType = FT_EXECUTABLE; }
void FileType::set(eFileType ft) { _fileType = ft; }

} // namespace common
} // namespace retdec
