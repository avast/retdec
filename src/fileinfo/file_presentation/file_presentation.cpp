/**
 * @file src/fileinfo/file_presentation/file_presentation.cpp
 * @brief General presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/file_presentation.h"

namespace retdec {
namespace fileinfo {

/**
 * Constructor
 */
FilePresentation::FilePresentation(FileInformation &fileinfo_) : fileinfo(fileinfo_)
{
	returnCode = fileinfo.getStatus();
}

/**
 * @fn bool FilePresentation::present()
 * Present information about file
 * @return @c true if presentation went OK, @c false otherwise
 */

} // namespace fileinfo
} // namespace retdec
