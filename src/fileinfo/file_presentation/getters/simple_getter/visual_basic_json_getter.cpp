/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/visual_basic_json_getter.cpp
 * @brief Methods of VisualBasicJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/visual_basic_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
VisualBasicJsonGetter::VisualBasicJsonGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

std::size_t VisualBasicJsonGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	if (!fileinfo.isVisualBasicUsed())
	{
		return 0;
	}

	desc.push_back("projectName");
	desc.push_back("projectExeName");
	desc.push_back("projectPath");
	desc.push_back("projectDescription");
	desc.push_back("projectHelpFile");
	desc.push_back("languageDLL");
	desc.push_back("backupLanguageDLL");
	desc.push_back("languageDLLPrimaryLCID");
	desc.push_back("languageDLLSecondaryLCID");
	desc.push_back("projectPrimaryLCID");
	desc.push_back("projectSecondaryLCID");
	desc.push_back("typeLibCLSID");
	desc.push_back("typeLibMajorVersion");
	desc.push_back("typeLibMinorVersion");
	desc.push_back("typeLibLCID");
	desc.push_back("comObjectName");
	desc.push_back("comObjectDescription");
	desc.push_back("comObjectCLSID");
	desc.push_back("comObjectInterfaceCLSID");
	desc.push_back("comObjectEventsCLSID");
	desc.push_back("comObjectType");
	desc.push_back("isPCode");

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
	info.push_back((fileinfo.getVisualBasicIsPcode()) ? "yes" : "no");

	return info.size();
}

} // namespace fileinfo
