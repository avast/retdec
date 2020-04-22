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

namespace retdec {
namespace fileinfo {

/**
 * Class for rich header
 */
class VisualBasicInfo
{
	private:
		bool used = false;
		const retdec::fileformat::VisualBasicInfo *visualBasicInfo = nullptr;
	public:
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
		std::string getExternModuleName(std::size_t position) const;
		std::string getExternApiName(std::size_t position) const;
		std::string getObjectTableGUID() const;
		std::string getTypeLibCLSID() const;
		std::string getTypeLibMajorVersionStr() const;
		std::string getTypeLibMinorVersionStr() const;
		std::string getTypeLibLCIDStr() const;
		std::string getCOMObjectName() const;
		std::string getCOMObjectDescription() const;
		std::string getCOMObjectCLSID() const;
		std::string getCOMObjectInterfaceCLSID() const;
		std::string getCOMObjectEventsCLSID() const;
		std::string getCOMObjectType() const;
		std::string getExternTableHashCrc32() const;
		std::string getExternTableHashMd5() const;
		std::string getExternTableHashSha256() const;
		std::string getObjectTableHashCrc32() const;
		std::string getObjectTableHashMd5() const;
		std::string getObjectTableHashSha256() const;
		/// @}

		/// @name Setters
		/// @{
		void setInfo(const retdec::fileformat::VisualBasicInfo *vbInfo);
		void setUsed(bool set);
		/// @}

		/// @name Other methods
		/// @{
		bool isUsed() const;
		bool isPcode() const;
		/// @}
};

} // namespace fileinfo
} // namespace retdec

#endif
