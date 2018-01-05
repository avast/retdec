/**
* @file include/retdec/ctypes/header_file.h
* @brief A representation of C header file.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_HEADER_FILE_H
#define RETDEC_CTYPES_HEADER_FILE_H

#include <string>

namespace retdec {
namespace ctypes {

/**
* @brief A representation of C header file.
*/
class HeaderFile
{
	public:
		HeaderFile() = default;
		explicit HeaderFile(const std::string &path);

		std::string getPath() const;
		std::string getName() const;

	private:
		/// Path to header file.
		std::string path;
};

} // namespace ctypes
} // namespace retdec

#endif
