/**
* @file src/ctypes/header_file.cpp
* @brief Implementation of HeaderFile.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/header_file.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new representation for header file.
*/
HeaderFile::HeaderFile(const std::string &path):
	path(path) {}

/**
* @brief Returns path to the header file.
*/
std::string HeaderFile::getPath() const
{
	return path;
}

/**
* @brief Returns header file name.
*/
std::string HeaderFile::getName() const
{
	auto foundIndex = path.find_last_of("/\\");
	return path.substr(foundIndex + 1);
}

} // namespace ctypes
} // namespace retdec
