/**
 * @file src/fileformat/types/visual_basic/visual_basic_info.cpp
 * @brief Class visual basic information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/utils/system.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/crypto.h"
#include "retdec/fileformat/types/visual_basic/visual_basic_info.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Get language DLL
 * @return language DLL
 */
const std::string &VisualBasicInfo::getLanguageDLL() const
{
	return languageDLL;
}

/**
 * Get backup language DLL
 * @return backup language DLL
 */
const std::string &VisualBasicInfo::getBackupLanguageDLL() const
{
	return backupLanguageDLL;
}

/**
 * Get project exe name
 * @return project exe name
 */
const std::string &VisualBasicInfo::getProjectExeName() const
{
	return projectExeName;
}

/**
 * Get project description
 * @return project description
 */
const std::string &VisualBasicInfo::getProjectDescription() const
{
	return projectDescription;
}

/**
 * Get project help file
 * @return project help file
 */
const std::string &VisualBasicInfo::getProjectHelpFile() const
{
	return projectHelpFile;
}

/**
 * Get project name
 * @return project name
 */
const std::string &VisualBasicInfo::getProjectName() const
{
	return projectName;
}

/**
 * Get language DLL primary LCID
 * @param res Variable to store the result to
 * @return @c true if language DLL primary LCID is valid, @c false otherwise
 */
bool VisualBasicInfo::getLanguageDLLPrimaryLCID(std::uint32_t &res) const
{
	if (!validLanguageDLLPrimaryLCID)
	{
		return false;
	}
	res = languageDLLPrimaryLCID;
	return true;
}
/**
 * Get language DLL secondary LCID
 * @param res Variable to store the result to
 * @return @c true if language DLL secondary LCID is valid, @c false otherwise
 */
bool VisualBasicInfo::getLanguageDLLSecondaryLCID(std::uint32_t &res) const
{
	if (!validLanguageDLLSecondaryLCID)
	{
		return false;
	}
	res = languageDLLSecondaryLCID;
	return true;
}

/**
 * Get project path
 * @return project path
 */
const std::string &VisualBasicInfo::getProjectPath() const
{
	return projectPath;
}

/**
 * Get project primary LCID
 * @param res Variable to store the result to
 * @return @c true if project primary LCID is valid, @c false otherwise
 */
bool VisualBasicInfo::getProjectPrimaryLCID(std::uint32_t &res) const
{
	if (!validProjectPrimaryLCID)
	{
		return false;
	}
	res = projectPrimaryLCID;
	return true;
}

/**
 * Get project secondary LCID
 * @param res Variable to store the result to
 * @return @c true if project secondary LCID is valid, @c false otherwise
 */
bool VisualBasicInfo::getProjectSecondaryLCID(std::uint32_t &res) const
{
	if (!validProjectSecondaryLCID)
	{
		return false;
	}
	res = projectSecondaryLCID;
	return true;
}

/**
 * Get objects
 * @return Visual basic objects
 */
const std::vector<std::unique_ptr<VisualBasicObject>> &VisualBasicInfo::getObjects() const
{
	return objects;
}

/**
 * Get externs
 * @return Visual basic externs
 */
const std::vector<std::unique_ptr<VisualBasicExtern>> &VisualBasicInfo::getExterns() const
{
	return externs;
}

/**
 * Get object
 * @param position Index of selected visual basic object (indexed from 0)
 * @return Visual basic object
 */
const VisualBasicObject *VisualBasicInfo::getObject(std::size_t position) const
{
	return (position < objects.size()) ? objects[position].get() : nullptr;
}

/**
 * Get extern
 * @param position Index of selected visual basic extern (indexed from 0)
 * @return Visual basic extern
 */
const VisualBasicExtern *VisualBasicInfo::getExtern(std::size_t position) const
{
	return (position < externs.size()) ? externs[position].get() : nullptr;
}

/**
 * Get number of objects
 * @return Number of objects
 */
size_t VisualBasicInfo::getNumberOfObjects() const
{
	return objects.size();
}

/**
 * Get number of externs
 * @return Number of externs
 */
size_t VisualBasicInfo::getNumberOfExterns() const
{
	return externs.size();
}

/**
 * Get object table GUID
 * @return Object table GUID as string
 */
const std::string &VisualBasicInfo::getObjectTableGUID() const
{
	return objectTableGUID;
}

/**
 * Get typeLib CLSID
 * @return typeLib CLSID as string
 */
const std::string &VisualBasicInfo::getTypeLibCLSID() const
{
	return typeLibCLSID;
}

/**
 * Get typeLib LCID
 * @param res Variable to store the result to
 * @return @c true if typeLib LCID is valid, @c false otherwise
 */
bool VisualBasicInfo::getTypeLibLCID(std::uint32_t &res) const
{
	if (!validTypeLibLCID)
	{
		return false;
	}
	res = typeLibLCID;
	return true;
}

/**
 * Get typeLib major version
 * @param res Variable to store result to
 * @return @c true if typeLib major version is valid, @c false otherwise
 */
bool VisualBasicInfo::getTypeLibMajorVersion(std::uint16_t &res) const
{
	if (!validTypeLibMajorVersion)
	{
		return false;
	}
	res = typeLibMajorVersion;
	return true;
}

/**
 * Get typeLib minor version
 * @param res Variable to store result to
 * @return @c true if typeLib minor version is valid, @c false otherwise
 */
bool VisualBasicInfo::getTypeLibMinorVersion(std::uint16_t &res) const
{
	if (!validTypeLibMinorVersion)
	{
		return false;
	}
	res = typeLibMinorVersion;
	return true;
}

/**
 * Get COM object name
 * @return COM object name
 */
const std::string &VisualBasicInfo::getCOMObjectName() const
{
	return COMObjectName;
}

/**
 * Get COM object description
 * @return COM object description
 */
const std::string &VisualBasicInfo::getCOMObjectDescription() const
{
	return COMObjectDescription;
}

/**
 * Get COM object CLSID
 * @return COM object CLSID
 */
const std::string &VisualBasicInfo::getCOMObjectCLSID() const
{
	return COMObjectCLSID;
}

/**
 * Get COM object interface CLSID
 * @return COM object interface CLSID
 */
const std::string &VisualBasicInfo::getCOMObjectInterfaceCLSID() const
{
	return COMObjectInterfaceCLSID;
}

/**
 * Get COM object events CLSID
 * @return COM object events CLSID
 */
const std::string &VisualBasicInfo::getCOMObjectEventsCLSID() const
{
	return COMObjectEventsCLSID;
}

/**
 * Get COM object type
 * @return COM object type
 */
const std::string &VisualBasicInfo::getCOMObjectType() const
{
	return COMObjectType;
}

/**
 * Get extern table hash as CRC32
 * @return Extern table hash
 */
const std::string &VisualBasicInfo::getExternTableHashCrc32() const
{
	return externTableHashCrc32;
}

/**
 * Get extern table hash as MD5
 * @return Extern table hash
 */
const std::string &VisualBasicInfo::getExternTableHashMd5() const
{
	return externTableHashMd5;
}

/**
 * Get extern table hash as SHA256
 * @return Extern table hash
 */
const std::string &VisualBasicInfo::getExternTableHashSha256() const
{
	return externTableHashSha256;
}

/**
 * Get object table hash as CRC32
 * @return Object table hash
 */
const std::string &VisualBasicInfo::getObjectTableHashCrc32() const
{
	return objectTableHashCrc32;
}

/**
 * Get object table hash as MD5
 * @return Object table hash
 */
const std::string &VisualBasicInfo::getObjectTableHashMd5() const
{
	return objectTableHashMd5;
}

/**
 * Get object table hash as SHA256
 * @return Object table hash
 */
const std::string &VisualBasicInfo::getObjectTableHashSha256() const
{
	return objectTableHashSha256;
}

/**
 * Set language DLL
 * @param lDLL Language DLL to set
 */
void VisualBasicInfo::setLanguageDLL(const std::string &lDLL)
{
	languageDLL = lDLL;
}

/**
 * Set backup language DLL
 * @param blDLL Backup language DLL to set
 */
void VisualBasicInfo::setBackupLanguageDLL(const std::string &blDLL)
{
	backupLanguageDLL = blDLL;
}

/**
 * Set project exe name
 * @param exeName Project exe name to set
 */
void VisualBasicInfo::setProjectExeName(const std::string &exeName)
{
	projectExeName = exeName;
}

/**
 * Set project description
 * @param desc Project description to set
 */
void VisualBasicInfo::setProjectDescription(const std::string &desc)
{
	projectDescription = desc;
}

/**
 * Set project help file
 * @param helpFile Project help file to set
 */
void VisualBasicInfo::setProjectHelpFile(const std::string &helpFile)
{
	projectHelpFile = helpFile;
}

/**
 * Set project name
 * @param name Project name to set
 */
void VisualBasicInfo::setProjectName(const std::string &name)
{
	projectName = name;
}

/**
 * Set language DLL primary LCID
 * @param lDLLPrimLCID Language DLL primary LCID to set
 */
void VisualBasicInfo::setLanguageDLLPrimaryLCID(std::uint32_t lDLLPrimLCID)
{
	languageDLLPrimaryLCID = lDLLPrimLCID;
	validLanguageDLLPrimaryLCID = true;
}

/**
 * Set language DLL secondary LCID
 * @param lDLLSecLCID Language DLL secondary LCID to set
 */
void VisualBasicInfo::setLanguageDLLSecondaryLCID(std::uint32_t lDLLSecLCID)
{
	languageDLLSecondaryLCID = lDLLSecLCID;
	validLanguageDLLSecondaryLCID = true;
}

/**
 * Set project path
 * @param path Project path to set
 */
void VisualBasicInfo::setProjectPath(const std::string &path)
{
	const std::string prefix = "*\\A";

	if (prefix.size() > path.size())
	{
		projectPath = path;
	}
	else
	{
		auto res = std::mismatch(prefix.begin(), prefix.end(), path.begin());
		if (res.first == prefix.end())
		{
			projectPath = path.substr(prefix.size(), path.size() - prefix.size());
		}
		else
		{
			projectPath = path;
		}
	}
}

/**
 * Set project primary LCID
 * @param primLCID Project primary LCID to set
 */
void VisualBasicInfo::setProjectPrimaryLCID(std::uint32_t primLCID)
{
	projectPrimaryLCID = primLCID;
	validProjectPrimaryLCID = true;
}

/**
 * Set project secondary LCID
 * @param secLCID Project secondary LCID to set
 */
void VisualBasicInfo::setProjectSecondaryLCID(std::uint32_t secLCID)
{
	projectSecondaryLCID = secLCID;
	validProjectSecondaryLCID = true;
}

/**
 * Set typeLib CLSID
 * @param data CLSID raw data
 */
void VisualBasicInfo::setTypeLibCLSID(const std::uint8_t data[16])
{
	typeLibCLSID = guidToStr(data);
}

/**
 * Set typeLib LCID
 * @param tlbLCID TypeLib LCID to set
 */
void VisualBasicInfo::setTypeLibLCID(std::uint32_t tlbLCID)
{
	typeLibLCID = tlbLCID;
	validTypeLibLCID = true;
}

/**
 * Set whether visual basic file is a P-code file.
 * @param set @c true if file is a P-code, @c false otherwise.
 */
void VisualBasicInfo::setPcode(bool set)
{
	pcodeFlag = set;
}

/**
 * Set object table GUID
 * @param data Raw GUID data
 */
void VisualBasicInfo::setObjectTableGUID(const std::uint8_t data[16])
{
	objectTableGUID = guidToStr(data);
}

/**
 * Set typeLib major version
 * @param majVer Version to set
 */
void VisualBasicInfo::setTypeLibMajorVersion(std::uint16_t majVer)
{
	typeLibMajorVersion = majVer;
	validTypeLibMajorVersion = true;
}

/**
 * Set typeLib minor version
 * @param minVer Version to set
 */
void VisualBasicInfo::setTypeLibMinorVersion(std::uint16_t minVer)
{
	typeLibMinorVersion = minVer;
	validTypeLibMinorVersion = true;
}

/**
 * Set COM object name
 * @param name COM object name to set
 */
void VisualBasicInfo::setCOMObjectName(const std::string &name)
{
	COMObjectName = name;
}

/**
 * Set COM object description
 * @param description COM object description to set
 */
void VisualBasicInfo::setCOMObjectDescription(const std::string &description)
{
	COMObjectDescription = description;
}

/**
 * Set COM object CLSID
 * @param data Raw CLSID data
 */
void VisualBasicInfo::setCOMObjectCLSID(const std::uint8_t data[16])
{
	COMObjectCLSID = guidToStr(data);
}

/**
 * Set COM object interfaceCLSID
 * @param data Raw CLSID data
 */
void VisualBasicInfo::setCOMObjectInterfaceCLSID(const std::uint8_t data[16])
{
	COMObjectInterfaceCLSID = guidToStr(data);
}

/**
 * Set COM object eventsCLSID
 * @param data Raw CLSID data
 */
void VisualBasicInfo::setCOMObjectEventsCLSID(const std::uint8_t data[16])
{
	COMObjectEventsCLSID = guidToStr(data);
}

/**
 * Set COM object type
 * @param type COM object type to set
 */
void VisualBasicInfo::setCOMObjectType(std::uint8_t type)
{
	switch (type)
	{
		case 0x2: COMObjectType = "Designer"; break;
		case 0x10: COMObjectType = "ClassModule"; break;
		case 0x20: COMObjectType = "ActiveXUserControl"; break;
		case 0x80: COMObjectType = "UserDocument"; break;
		default: COMObjectType = "unknown"; break;
	}
}

/**
 * Add visual basic object
 * @param obj Object to add
 */
void VisualBasicInfo::addObject(std::unique_ptr<VisualBasicObject>&& obj)
{
	objects.push_back(std::move(obj));
}

/**
 * Add visual basic extern
 * @param ext Extern to add
 */
void VisualBasicInfo::addExtern(std::unique_ptr<VisualBasicExtern>&& ext)
{
	externs.push_back(std::move(ext));
}

/**
 * Check if visual basic file has project name
 * @return @c true if visual basic file has project name, @c false otherwise
 */
bool VisualBasicInfo::hasProjectName() const
{
	return !projectName.empty();
}

/**
 * Check if visual basic file has project description
 * @return @c true if visual basic file has project description, @c false otherwise
 */
bool VisualBasicInfo::hasProjectDescription() const
{
	return !projectDescription.empty();
}

/**
 * Check if visual basic file has project help file
 * @return @c true if visual basic file has project help file, @c false otherwise
 */
bool VisualBasicInfo::hasProjectHelpFile() const
{
	return !projectHelpFile.empty();
}

/**
 * Check if visual basic file is a P-code file
 * @return @c true if visual basic file is P-code, @c false otherwise
 */
bool VisualBasicInfo::isPcode() const
{
	return pcodeFlag;
}

/**
 * Compute external table hashes - CRC32, MD5, SHA256.
 */
void VisualBasicInfo::computeExternTableHashes()
{
	std::vector<std::uint8_t> hashBytes;

	for (const auto& ext : externs)
	{
		auto moduleName = toLower(ext->getModuleName());
		auto apiName = toLower(ext->getApiName());

		if(apiName.empty() || moduleName.empty())
		{
			continue;
		}

		if(!hashBytes.empty())
		{
			hashBytes.push_back(static_cast<unsigned char>(','));
		}

		for(const auto c : std::string(apiName + "." + moduleName))
		{
			hashBytes.push_back(static_cast<unsigned char>(c));
		}
	}

	externTableHashCrc32 = getCrc32(hashBytes.data(), hashBytes.size());
	externTableHashMd5 = getMd5(hashBytes.data(), hashBytes.size());
	externTableHashSha256 = getSha256(hashBytes.data(), hashBytes.size());
}

/**
 * Compute object table hashes - CRC32, MD5, SHA256.
 */
void VisualBasicInfo::computeObjectTableHashes()
{
	std::vector<std::uint8_t> hashBytes;

	for (const auto& obj : objects)
	{
		auto objName = toLower(obj->getName());
		if(objName.empty())
		{
			continue;
		}

		std::string methods = "";
		for (const auto &method : obj->getMethods())
		{
			if (!methods.empty())
			{
				methods.push_back('.');
			}

			methods += method;
		}

		if(!hashBytes.empty())
		{
			hashBytes.push_back(static_cast<unsigned char>(','));
		}

		for(const auto c : std::string(objName + "." + methods))
		{
			hashBytes.push_back(static_cast<unsigned char>(c));
		}
	}

	objectTableHashCrc32 = getCrc32(hashBytes.data(), hashBytes.size());
	objectTableHashMd5 = getMd5(hashBytes.data(), hashBytes.size());
	objectTableHashSha256 = getSha256(hashBytes.data(), hashBytes.size());
}

/**
 * Convert raw GUID data to string
 * @param data Raw GUID data
 */
std::string VisualBasicInfo::guidToStr(const std::uint8_t data[16])
{
	std::string r1, r2, r3, r4, r5;
	bytesToHexString(data, 16, r1, 0, 4);
	bytesToHexString(data, 16, r2, 4, 2);
	bytesToHexString(data, 16, r3, 6, 2);
	bytesToHexString(data, 16, r4, 8, 2);
	bytesToHexString(data, 16, r5, 10, 6);

	return r1 + "-" + r2 + "-" + r3 + "-" + r4 + "-" + r5;
}

} // namespace fileformat
} // namespace retdec
