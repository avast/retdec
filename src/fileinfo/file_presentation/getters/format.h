/**
 * @file src/fileinfo/file_presentation/getters/format.h
 * @brief Functions for formatting of strings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_FORMAT_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_FORMAT_H

#include <string>
#include <vector>

namespace fileinfo {

const std::size_t MAX_NAME_LENGTH = 100;

std::string abbvSerialization(const std::vector<std::string> &abbv);
void shrinkAndReplaceNonprintable(std::string &str, std::size_t maxLength);
void addUniqueValues(std::vector<std::string> &currentVal, const std::vector<std::string> &newVal);

} // namespace fileinfo

#endif
