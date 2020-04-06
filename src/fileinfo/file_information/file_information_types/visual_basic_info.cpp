/**
 * @file src/fileinfo/file_information/file_information_types/visual_basic_info.cpp
 * @brief Rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_information/file_information_types/visual_basic_info.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

/**
 * Get language DLL
 * @return Visual basic language DLL
 */
std::string VisualBasicInfo::getLanguageDLL() const
{
	return visualBasicInfo ? visualBasicInfo->getLanguageDLL() : "";
}

/**
 * Get backup language DLL
 * @return Visual basic backup language DLL
 */
std::string VisualBasicInfo::getBackupLanguageDLL() const
{
	return visualBasicInfo ? visualBasicInfo->getBackupLanguageDLL() : "";
}

/**
 * Get project exe name
 * @return Visual basic project exe name
 */
std::string VisualBasicInfo::getProjectExeName() const
{
	return visualBasicInfo ? visualBasicInfo->getProjectExeName() : "";
}

/**
 * Get project description
 * @return Visual basic project description
 */
std::string VisualBasicInfo::getProjectDescription() const
{
	return visualBasicInfo ? visualBasicInfo->getProjectDescription() : "";
}

/**
 * Get project help file
 * @return Visual basic project help file
 */
std::string VisualBasicInfo::getProjectHelpFile() const
{
	return visualBasicInfo ? visualBasicInfo->getProjectHelpFile() : "";
}

/**
 * Get project name
 * @return Visual basic project name
 */
std::string VisualBasicInfo::getProjectName() const
{
	return visualBasicInfo ? visualBasicInfo->getProjectName() : "";
}

/**
 * Get language DLL primary LCID
 * @return Visual basic language DLL primary LCID as string
 */
std::string VisualBasicInfo::getLanguageDLLPrimaryLCIDStr() const
{
	std::uint32_t lcid;
	if (!visualBasicInfo || !visualBasicInfo->getLanguageDLLPrimaryLCID(lcid))
	{
		return "";
	}
	return lcidToStr(lcid);
}

/**
 * Get language DLL secondary LCID
 * @return Visual basic language DLL secondary LCID as string
 */
std::string VisualBasicInfo::getLanguageDLLSecondaryLCIDStr() const
{
	std::uint32_t lcid;
	if (!visualBasicInfo || !visualBasicInfo->getLanguageDLLSecondaryLCID(lcid))
	{
		return "";
	}
	return lcidToStr(lcid);
}

/**
 * Get project path
 * @return Visual basic project path
 */
std::string VisualBasicInfo::getProjectPath() const
{
	return visualBasicInfo ? visualBasicInfo->getProjectPath() : "";
}

/**
 * Get project primary LCID
 * @return Visual basic project primary LCID as string
 */
std::string VisualBasicInfo::getProjectPrimaryLCIDStr() const
{
	std::uint32_t lcid;
	if (!visualBasicInfo || !visualBasicInfo->getProjectPrimaryLCID(lcid))
	{
		return "";
	}
	return lcidToStr(lcid);
}

/**
 * Get project secondary LCID
 * @return Visual basic project secondary LCID as string
 */
std::string VisualBasicInfo::getProjectSecondaryLCIDStr() const
{
	std::uint32_t lcid;
	if (!visualBasicInfo || !visualBasicInfo->getProjectSecondaryLCID(lcid))
	{
		return "";
	}
	return lcidToStr(lcid);
}

/**
 * Get object
 * @param position Index of selected visual basic object (indexed from 0)
 * @return Visual basic object
 */
const retdec::fileformat::VisualBasicObject *VisualBasicInfo::getObject(std::size_t position) const
{
	return visualBasicInfo ? visualBasicInfo->getObject(position) : nullptr;
}

/**
 * Get extern
 * @param position Index of selected visual basic extern (indexed from 0)
 * @return Visual basic extern
 */
const retdec::fileformat::VisualBasicExtern *VisualBasicInfo::getExtern(std::size_t position) const
{
	return visualBasicInfo ? visualBasicInfo->getExtern(position) : nullptr;
}

/**
 * Get number of objects
 * @return Visual basic number of objects
 */
std::size_t VisualBasicInfo::getNumberOfObjects() const
{
	return visualBasicInfo ? visualBasicInfo->getNumberOfObjects() : 0;
}

/**
 * Get number of externs
 * @return Visual basic number of externs
 */
std::size_t VisualBasicInfo::getNumberOfExterns() const
{
	return visualBasicInfo ? visualBasicInfo->getNumberOfExterns() : 0;
}

/**
 * Get extern module name
 * @param position Index of selected visual basic extern (indexed from 0)
 * @return Extern module name
 */
std::string VisualBasicInfo::getExternModuleName(std::size_t position) const
{
	auto ext = getExtern(position);
	return ext ? ext->getModuleName() : "";
}

/**
 * Get extern api name
 * @param position Index of selected visual basic extern (indexed from 0)
 * @return Extern api name
 */
std::string VisualBasicInfo::getExternApiName(std::size_t position) const
{
	auto ext = getExtern(position);
	return ext ? ext->getApiName() : "";
}

/**
 * Get object table GUID
 * @return Object table GUID as string
 */
std::string VisualBasicInfo::getObjectTableGUID() const
{
	return visualBasicInfo ? visualBasicInfo->getObjectTableGUID() : "";
}

/**
 * Get typeLib CLSID
 * @return typeLib CLSID as string
 */
std::string VisualBasicInfo::getTypeLibCLSID() const
{
	return visualBasicInfo ? visualBasicInfo->getTypeLibCLSID() : "";
}

/**
 * Get typeLib major version
 * @return TypeLib major version
 */
std::string VisualBasicInfo::getTypeLibMajorVersionStr() const
{
	std::uint16_t majV;
	if (!visualBasicInfo || !visualBasicInfo->getTypeLibMajorVersion(majV))
	{
		return "";
	}
	return getNumberAsString(majV);
}

/**
 * Get typeLib minor version
 * @return TypeLib minor version
 */
std::string VisualBasicInfo::getTypeLibMinorVersionStr() const
{
	std::uint16_t minV;
	if (!visualBasicInfo || !visualBasicInfo->getTypeLibMinorVersion(minV))
	{
		return "";
	}
	return getNumberAsString(minV);
}

/**
 * Get typeLib LCID
 * @return Visual basic typeLib LCID as string
 */
std::string VisualBasicInfo::getTypeLibLCIDStr() const
{
	std::uint32_t lcid;
	if (!visualBasicInfo || !visualBasicInfo->getTypeLibLCID(lcid))
	{
		return "";
	}
	return lcidToStr(lcid);
}

/**
 * Get COM object name
 * @return Visual basic COM object name
 */
std::string VisualBasicInfo::getCOMObjectName() const
{
	return visualBasicInfo ? visualBasicInfo->getCOMObjectName() : "";
}

/**
 * Get COM object description
 * @return Visual basic COM object description
 */
std::string VisualBasicInfo::getCOMObjectDescription() const
{
	return visualBasicInfo ? visualBasicInfo->getCOMObjectDescription() : "";
}

/**
 * Get COM object CLSID
 * @return Visual basic COM object CLSID
 */
std::string VisualBasicInfo::getCOMObjectCLSID() const
{
	return visualBasicInfo ? visualBasicInfo->getCOMObjectCLSID() : "";
}

/**
 * Get COM object interface CLSID
 * @return Visual basic COM object interface CLSID
 */
std::string VisualBasicInfo::getCOMObjectInterfaceCLSID() const
{
	return visualBasicInfo ? visualBasicInfo->getCOMObjectInterfaceCLSID() : "";
}

/**
 * Get COM object events CLSID
 * @return Visual basic COM object events CLSID
 */
std::string VisualBasicInfo::getCOMObjectEventsCLSID() const
{
	return visualBasicInfo ? visualBasicInfo->getCOMObjectEventsCLSID() : "";
}

/**
 * Get COM object type
 * @return Visual basic COM object type
 */
std::string VisualBasicInfo::getCOMObjectType() const
{
	return visualBasicInfo ? visualBasicInfo->getCOMObjectType() : "";
}

/**
 * Get extern table hash as CRC32
 * @return Extern table hash
 */
std::string VisualBasicInfo::getExternTableHashCrc32() const
{
	return visualBasicInfo ? visualBasicInfo->getExternTableHashCrc32() : "";
}

/**
 * Get extern table hash as MD5
 * @return Extern table hash
 */
std::string VisualBasicInfo::getExternTableHashMd5() const
{
	return visualBasicInfo ? visualBasicInfo->getExternTableHashMd5() : "";
}

/**
 * Get extern table hash as SHA256
 * @return Extern table hash
 */
std::string VisualBasicInfo::getExternTableHashSha256() const
{
	return visualBasicInfo ? visualBasicInfo->getExternTableHashSha256() : "";
}

/**
 * Get object table hash as CRC32
 * @return Object table hash
 */
std::string VisualBasicInfo::getObjectTableHashCrc32() const
{
	return visualBasicInfo ? visualBasicInfo->getObjectTableHashCrc32() : "";
}

/**
 * Get object table hash as MD5
 * @return Object table hash
 */
std::string VisualBasicInfo::getObjectTableHashMd5() const
{
	return visualBasicInfo ? visualBasicInfo->getObjectTableHashMd5() : "";
}

/**
 * Get object table hash as SHA256
 * @return Object table hash
 */
std::string VisualBasicInfo::getObjectTableHashSha256() const
{
	return visualBasicInfo ? visualBasicInfo->getObjectTableHashSha256() : "";
}

/**
 * Set visual basic information
 * @param vbInfo Instance of class with original information about visual basic
 */
void VisualBasicInfo::setInfo(const retdec::fileformat::VisualBasicInfo *vbInfo)
{
	visualBasicInfo = vbInfo;
}

/**
 * Set whether visual basic info is used.
 * @param set @c true if used, @c false otherwise.
 */
void VisualBasicInfo::setUsed(bool set)
{
	used = set;
}

/**
 * Check whether visual basic informations are used.
 * @return @c true if used, otherwise @c false.
 */
bool VisualBasicInfo::isUsed() const
{
	return used;
}

/**
 * Check whether visual basic file is a P-code file.
 * @return @c true if is a P-code file, otherwise @c false.
 */
bool VisualBasicInfo::isPcode() const
{
	return visualBasicInfo ? visualBasicInfo->isPcode() : false;
}

} // namespace fileinfo
} // namespace retdec
