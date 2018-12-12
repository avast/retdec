/**
 * @file src/fileinfo/file_information/file_information_types/visual_basic_info.cpp
 * @brief Rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/visual_basic_info.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 */
VisualBasicInfo::VisualBasicInfo() : visualBasicInfo(nullptr)
{

}

/**
 * Destructor
 */
VisualBasicInfo::~VisualBasicInfo()
{

}

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
	return getNumberAsString(lcid);
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
	return getNumberAsString(lcid);
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
	return getNumberAsString(lcid);
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
	return getNumberAsString(lcid);
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

// /**
//  * Get typeLib CLSID
//  * @return Visual basic typeLib CLSID as string
//  */
// std::string VisualBasicInfo::getTypeLibCLSIDStr() const
// {
// 	std::uint32_t clsid;
// 	if (!visualBasicInfo || !visualBasicInfo->getTypeLibCLSID(clsid))
// 	{
// 		return "";
// 	}
// 	return getNumberAsString(clsid);
// }

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
	return getNumberAsString(lcid);
}

/**
 * Set visual basic information
 * @param vbInfo Instance of class with original information about visual basic
 */
void VisualBasicInfo::setInfo(const retdec::fileformat::VisualBasicInfo *vbInfo)
{
	visualBasicInfo = vbInfo;
}

} // namespace fileinfo
