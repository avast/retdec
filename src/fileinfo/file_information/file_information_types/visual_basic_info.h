/**
 * @file src/fileinfo/file_information/file_information_types/visual_basic_info.h
 * @brief Visual basic information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_VISUAL_BASIC_INFO_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_VISUAL_BASIC_INFO_H

#include "retdec/fileformat/types/visual_basic/visual_basic_info.h"
#include "retdec/fileformat/types/visual_basic/visual_basic_object.h"
#include "retdec/fileformat/types/visual_basic/visual_basic_extern.h"

namespace fileinfo {

/**
 * Class for rich header
 */
class VisualBasicInfo
{
	private:
		const retdec::fileformat::VisualBasicInfo *visualBasicInfo;
	public:
		VisualBasicInfo();
		~VisualBasicInfo();

		/// @name Getters
		/// @{
		std::string getLanguageDLL() const;
		std::string getBackupLanguageDLL() const;
		std::string getProjectExeName() const;
		std::string getProjectDescription() const;
		std::string getProjectHelpFile() const;
		std::string getProjectName() const;
		std::string getLanguageDLLPrimaryLCIDStr() const;
		std::string getLanguageDLLSecondaryLCIDStr() const;
		std::string getProjectPath() const;
		std::string getProjectPrimaryLCIDStr() const;
		std::string getProjectSecondaryLCIDStr() const;
		const retdec::fileformat::VisualBasicObject *getObject(std::size_t position) const;
		const retdec::fileformat::VisualBasicExtern *getExtern(std::size_t position) const;
		std::size_t getNumberOfObjects() const;
		std::size_t getNumberOfExterns() const;
		// std::string getTypeLibCLSIDStr() const;
		std::string getTypeLibLCIDStr() const;
		/// @}

		/// @name Setters
		/// @{
		void setInfo(const retdec::fileformat::VisualBasicInfo *vbInfo);
		/// @}

		/// @name Other methods
		/// @{
		/// @}
};

} // namespace fileinfo

#endif
