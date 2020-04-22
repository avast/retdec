/**
 * @file include/retdec/fileformat/types/visual_basic/visual_basic_info.h
 * @brief Class for visual basic information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_INFO_H
#define RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_INFO_H

#include <string>
#include <vector>
#include <memory>

#include "retdec/fileformat/types/visual_basic/visual_basic_object.h"
#include "retdec/fileformat/types/visual_basic/visual_basic_extern.h"

namespace retdec {
namespace fileformat {

/**
 * Class for visual basic information
 */
class VisualBasicInfo
{
	private:
		// VB Header
		std::string languageDLL;
		std::string backupLanguageDLL;
		std::string projectExeName;
		std::string projectDescription;
		std::string projectHelpFile;
		std::string projectName;
		std::uint32_t languageDLLPrimaryLCID = 0;
		std::uint32_t languageDLLSecondaryLCID = 0;

		// VB Proj Info
		std::string projectPath;

		// VB Object table
		std::string objectTableGUID;
		std::uint32_t projectPrimaryLCID = 0;
		std::uint32_t projectSecondaryLCID = 0;
		std::vector<std::unique_ptr<VisualBasicObject>> objects;

		// VB extern table
		std::vector<std::unique_ptr<VisualBasicExtern>> externs;

		// COM register data
		std::string typeLibCLSID;
		std::uint32_t typeLibLCID = 0;
		std::uint16_t typeLibMajorVersion = 0;
		std::uint16_t typeLibMinorVersion = 0;

		// COM register info
		std::string COMObjectName;
		std::string COMObjectDescription;
		std::string COMObjectCLSID;
		std::string COMObjectInterfaceCLSID;
		std::string COMObjectEventsCLSID;
		std::string COMObjectType;

		// others
		std::string externTableHashCrc32;
		std::string externTableHashMd5;
		std::string externTableHashSha256;
		std::string objectTableHashCrc32;
		std::string objectTableHashMd5;
		std::string objectTableHashSha256;

		bool validLanguageDLLPrimaryLCID = false;
		bool validLanguageDLLSecondaryLCID = false;
		bool validProjectPrimaryLCID = false;
		bool validProjectSecondaryLCID = false;
		bool validTypeLibLCID = false;
		bool validTypeLibMajorVersion = false;
		bool validTypeLibMinorVersion = false;
		bool pcodeFlag = false;

		std::string guidToStr(const std::uint8_t data[16]);

	public:
		/// @name Getters
		/// @{
		const std::string &getLanguageDLL() const;
		const std::string &getBackupLanguageDLL() const;
		const std::string &getProjectExeName() const;
		const std::string &getProjectDescription() const;
		const std::string &getProjectHelpFile() const;
		const std::string &getProjectName() const;
		bool getLanguageDLLPrimaryLCID(std::uint32_t &res) const;
		bool getLanguageDLLSecondaryLCID(std::uint32_t &res) const;
		const std::string &getProjectPath() const;
		bool getProjectPrimaryLCID(std::uint32_t &res) const;
		bool getProjectSecondaryLCID(std::uint32_t &res) const;
		const std::vector<std::unique_ptr<VisualBasicObject>> &getObjects() const;
		const std::vector<std::unique_ptr<VisualBasicExtern>> &getExterns() const;
		const VisualBasicObject *getObject(std::size_t position) const;
		const VisualBasicExtern *getExtern(std::size_t position) const;
		std::size_t getNumberOfObjects() const;
		std::size_t getNumberOfExterns() const;
		const std::string &getObjectTableGUID() const;
		const std::string &getTypeLibCLSID() const;
		bool getTypeLibLCID(std::uint32_t &res) const;
		bool getTypeLibMajorVersion(std::uint16_t &res) const;
		bool getTypeLibMinorVersion(std::uint16_t &res) const;
		const std::string &getCOMObjectName() const;
		const std::string &getCOMObjectDescription() const;
		const std::string &getCOMObjectCLSID() const;
		const std::string &getCOMObjectInterfaceCLSID() const;
		const std::string &getCOMObjectEventsCLSID() const;
		const std::string &getCOMObjectType() const;
		const std::string &getExternTableHashCrc32() const;
		const std::string &getExternTableHashMd5() const;
		const std::string &getExternTableHashSha256() const;
		const std::string &getObjectTableHashCrc32() const;
		const std::string &getObjectTableHashMd5() const;
		const std::string &getObjectTableHashSha256() const;
		/// @}

		/// @name Setters
		/// @{
		void setLanguageDLL(const std::string &lDll);
		void setBackupLanguageDLL(const std::string &blDll);
		void setProjectExeName(const std::string &exeName);
		void setProjectDescription(const std::string &desc);
		void setProjectHelpFile(const std::string &helpFile);
		void setProjectName(const std::string &name);
		void setLanguageDLLPrimaryLCID(std::uint32_t lDllPrimLCID);
		void setLanguageDLLSecondaryLCID(std::uint32_t lDllSecLCID);
		void setProjectPath(const std::string &path);
		void setProjectPrimaryLCID(std::uint32_t primLCID);
		void setProjectSecondaryLCID(std::uint32_t secLCID);
		void setTypeLibCLSID(const std::uint8_t data[16]);
		void setTypeLibLCID(std::uint32_t tlbLCID);
		void setPcode(bool set);
		void setObjectTableGUID(const std::uint8_t data[16]);
		void setTypeLibMajorVersion(std::uint16_t majVer);
		void setTypeLibMinorVersion(std::uint16_t minVer);
		void setCOMObjectName(const std::string &name);
		void setCOMObjectDescription(const std::string &description);
		void setCOMObjectCLSID(const std::uint8_t data[16]);
		void setCOMObjectInterfaceCLSID(const std::uint8_t data[16]);
		void setCOMObjectEventsCLSID(const std::uint8_t data[16]);
		void setCOMObjectType(std::uint8_t type);
		/// @}

		/// @name Other methods
		/// @{
		void addObject(std::unique_ptr<VisualBasicObject>&& obj);
		void addExtern(std::unique_ptr<VisualBasicExtern>&& ext);
		bool hasProjectName() const;
		bool hasProjectDescription() const;
		bool hasProjectHelpFile() const;
		bool isPcode() const;
		void computeExternTableHashes();
		void computeObjectTableHashes();
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
