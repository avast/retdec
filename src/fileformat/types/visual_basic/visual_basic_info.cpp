/**
 * @file src/fileformat/types/visual_basic/visual_basic_info.cpp
 * @brief Class visual basic information.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/visual_basic/visual_basic_info.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
VisualBasicInfo::VisualBasicInfo() : languageDLLPrimaryLCID(0), languageDLLSecondaryLCID(0),
	projectPrimaryLCID(0), projectSecondaryLCID(0), /*typeLibCLSID(0),*/ typeLibLCID(0),
	validLanguageDLLPrimaryLCID(false), validLanguageDLLSecondaryLCID(false),
	validProjectPrimaryLCID(false), validProjectSecondaryLCID(false), /*validTypeLibCLSID(false),*/
	validTypeLibLCID(false), pcodeFlag(false)
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
	// if prefix else TODO
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

// /**
//  * Get typeLib CLSID
//  * @param res Variable to store the result to
//  * @return @c true if project typeLib CLSID is valid, @c false otherwise
//  */
// bool VisualBasicInfo::getTypeLibCLSID(std::uint32_t &res) const
// {
// 	if (!validTypeLibCLSID)
// 	{
// 		return false;
// 	}
// 	res = typeLibCLSID;
// 	return true;
// }

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
	projectPath = path;
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

// /**
//  * Set typeLib CLSID
//  * @param tlbCLSID TypeLib CLSID to set
//  */
// void VisualBasicInfo::setTypeLibCLSID(std::uint32_t tlbCLSID)
// {
// 	typeLibCLSID = tlbCLSID;
// 	validTypeLibCLSID = true;
// }

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


} // namespace fileformat
} // namespace retdec
