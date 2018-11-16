/**
 * @file include/retdec/fileformat/types/visual_basic_header/visual_basic_header.h
 * @brief Class for rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_HEADER_VISUAL_BASIC_HEADER_H
#define RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_HEADER_VISUAL_BASIC_HEADER_H

#include <string>

namespace retdec {
namespace fileformat {

struct VBHeader
{
	std::uint8_t signature[4];               ///< "VB5!" signature
	std::uint16_t runtimeBuild;              ///< Runtime flag
	std::uint8_t languageDLL[14];            ///< Language DLL
	std::uint8_t backupLanguageDLL[14];      ///< Backup language DLL
	std::uint16_t runtimeDLLVersion;         ///< Version of the runtime DLL
	std::uint32_t languageID;                ///< Application language
	std::uint32_t backupLanguageID;          ///< Used with backup language DLL
	std::uint32_t aSubMain;                  ///< Procedure to start after the application is launched
	std::uint32_t aProjectInfo;              ///< Pointer to ProjectInfo
	std::uint32_t fMDLIntObjs;
	std::uint32_t fMDLIntObjs2;
	std::uint32_t threadFlags;               ///< Thread flags
	std::uint32_t threadCount;               ///< Number of threads (themeaning of this field is unclear as VB doesn't let you make multithreaded application)
	std::uint16_t formCount;                 ///< Number of forms in this application
	std::uint16_t externalComponentCount;    ///< Number of external OCX components
	std::uint32_t thunkCount;
	std::uint32_t aGUITable;                 ///< Pointer to GUITable
	std::uint32_t aExternalComponentTable;   ///< Pointer to ExternalComponentTable
	std::uint32_t aComRegisterData;          ///< Pointer to ComRegisterData
	std::uint32_t oProjectExename;           ///< Pointer to the string containing EXE filename
	std::uint32_t oProjectTitle;             ///< Pointer to the string containing project's title
	std::uint32_t oHelpFile;                 ///< Pointer to the string containing name of the Help file
	std::uint32_t oProjectName;              ///< Pointer to the string containing project's name

	VBHeader()
	{

	}

	std::size_t headerSize()
	{
		return
			sizeof(signature) + sizeof(runtimeBuild) + sizeof(languageDLL) +
			sizeof(backupLanguageDLL) + sizeof(runtimeDLLVersion) + sizeof(languageID) +
			sizeof(backupLanguageID) + sizeof(aSubMain) + sizeof(aProjectInfo) +
			sizeof(fMDLIntObjs) + sizeof(fMDLIntObjs2) + sizeof(threadFlags) +
			sizeof(threadCount) + sizeof(formCount) + sizeof(externalComponentCount) +
			sizeof(thunkCount) + sizeof(aGUITable) + sizeof(aExternalComponentTable) +
			sizeof(aComRegisterData) + sizeof(oProjectExename) + sizeof(oProjectTitle) +
			sizeof(oHelpFile) + sizeof(oProjectName);
	}

	void dump(std::ostream &out)
	{
		out << "signature:\t\t";
		for (std::size_t i = 0; i < sizeof(signature); i++)
		{
			out << signature[i];
		}
		out << "\n";

		out << "runtimeBuild:\t\t" << runtimeBuild << "\n";

		out << "languageDLL:\t\t";
		for (std::size_t i = 0; i < sizeof(languageDLL); i++)
		{
			if (!languageDLL[i])
			{
				break;
			}
			out << languageDLL[i];
		}
		out << "\n";

		out << "backupLanguageDLL:\t";
		for (std::size_t i = 0; i < sizeof(backupLanguageDLL); i++)
		{
			if (!backupLanguageDLL[i])
			{
				break;
			}
			out << backupLanguageDLL[i];
		}
		out << "\n";

		out << "runtimeDLLVersion:\t" << runtimeDLLVersion << "\n";
		out << "languageID:\t\t" << languageID << "\n";
		out << "backupLanguageID:\t" << backupLanguageID << "\n";
		out << "aSubMain:\t\t" << std::hex << aSubMain << "\n";
		out << "aProjectInfo:\t\t" << aProjectInfo << std::dec << "\n";
		out << "fMDLIntObjs:\t\t" << fMDLIntObjs << "\n";
		out << "fMDLIntObjs2:\t\t" << fMDLIntObjs2 << "\n";
		out << "threadFlags:\t\t" << threadFlags << "\n";
		out << "threadCount:\t\t" << threadCount << "\n";
		out << "formCount:\t\t" << formCount << "\n";
		out << "externalComponentCount:\t" << externalComponentCount << "\n";
		out << "thunkCount:\t\t" << thunkCount << "\n";
		out << "aGUITable:\t\t" << std::hex << aGUITable << "\n";
		out << "aExternalComponentTable:" << aExternalComponentTable << "\n";
		out << "aComRegisterData:\t" << aComRegisterData << "\n";
		out << "oProjectExename:\t" << oProjectExename << "\n";
		out << "oProjectTitle:\t\t" << oProjectTitle << "\n";
		out << "oHelpFile:\t\t" << oHelpFile << "\n";
		out << "oProjectName:\t\t" << oProjectName << std::dec << "\n";
	}
};

/**
 * Visual basic header
 */
class VisualBasicHeader
{
	private:
		std::size_t headerAddress;           ///< Header address

	public:
		VisualBasicHeader();
		~VisualBasicHeader();

		/// @name Getters
		/// @{

		/// @}

		/// @name Setters
		/// @{
		void setHeaderAddress(std::size_t address);
		/// @}

		/// @name Iterators
		/// @{

		/// @}

		/// @name Other methods
		/// @{

		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
