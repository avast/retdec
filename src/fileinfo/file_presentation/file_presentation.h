/**
 * @file src/fileinfo/file_presentation/file_presentation.h
 * @brief General presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_FILE_PRESENTATION_H
#define FILEINFO_FILE_PRESENTATION_FILE_PRESENTATION_H

#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * General presentation class
 */
class FilePresentation
{
	protected:
		FileInformation &fileinfo;        ///< class with information about file
		retdec::cpdetect::ReturnCode returnCode; ///< return code of data member @a fileinfo
	public:
		FilePresentation(FileInformation &fileinfo_);
		virtual ~FilePresentation();

		virtual bool present() = 0;
};

} // namespace fileinfo

#endif
