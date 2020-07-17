/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/visual_basic_plain_getter.cpp
 * @brief Methods of VisualBasicPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "retdec/utils/string.h"
#include "fileinfo/file_presentation/getters/simple_getter/visual_basic_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
VisualBasicPlainGetter::VisualBasicPlainGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

std::size_t VisualBasicPlainGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	if (!fileinfo.isVisualBasicUsed())
	{
		return 0;
	}

	desc.push_back("Project name                                                 : ");
	desc.push_back("Project exe name                                             : ");
	desc.push_back("Project path                                                 : ");
	desc.push_back("Project description                                          : ");
	desc.push_back("Project help file                                            : ");
	desc.push_back("Language DLL                                                 : ");
	desc.push_back("Backup Language DLL                                          : ");
	desc.push_back("Language DLL primary LCID                                    : ");
	desc.push_back("Language DLL secondary LCID                                  : ");
	desc.push_back("Project primary LCID                                         : ");
	desc.push_back("Project secondary LCID                                       : ");
	desc.push_back("TypeLib CLSID                                                : ");
	desc.push_back("TypeLib major version                                        : ");
	desc.push_back("TypeLib minor version                                        : ");
	desc.push_back("TypeLib LCID                                                 : ");
	desc.push_back("COM object name                                              : ");
	desc.push_back("COM object description                                       : ");
	desc.push_back("COM object CLSID                                             : ");
	desc.push_back("COM object interface CLSID                                   : ");
	desc.push_back("COM object events CLSID                                      : ");
	desc.push_back("COM object type                                              : ");
	desc.push_back("Is P-Code                                                    : ");

	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectName()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectExeName()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectPath()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectDescription()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectHelpFile()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicLanguageDLL()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicBackupLanguageDLL()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicLanguageDLLPrimaryLCIDStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicLanguageDLLSecondaryLCIDStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectPrimaryLCIDStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicProjectSecondaryLCIDStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicTypeLibCLSID()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicTypeLibMajorVersionStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicTypeLibMinorVersionStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicTypeLibLCIDStr()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicCOMObjectName()));
	info.push_back(replaceNonprintableChars(fileinfo.getVisualBasicCOMObjectDescription()));
	info.push_back(fileinfo.getVisualBasicCOMObjectCLSID());
	info.push_back(fileinfo.getVisualBasicCOMObjectInterfaceCLSID());
	info.push_back(fileinfo.getVisualBasicCOMObjectEventsCLSID());
	info.push_back(fileinfo.getVisualBasicCOMObjectType());
	info.push_back((fileinfo.getVisualBasicIsPcode()) ? "Yes" : "No");

	return info.size();
}

} // namespace fileinfo
} // namespace retdec
