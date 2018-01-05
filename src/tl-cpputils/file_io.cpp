/**
 * @file src/tl-cpputils/file_io.cpp
 * @brief Functions for file I/O.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "tl-cpputils/file_io.h"

namespace tl_cpputils {

/**
 * Does the provided file exist?
 * @param file Path to the file.
 */
bool fileExists(const std::string& file)
{
	std::ifstream f(file);
	return f.good();
}

} // namespace tl_cpputils
