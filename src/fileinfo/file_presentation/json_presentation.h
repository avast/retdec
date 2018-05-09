/**
 * @file src/fileinfo/file_presentation/json_presentation.h
 * @brief Plain text presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_JSON_PRESENTATION_H
#define FILEINFO_FILE_PRESENTATION_JSON_PRESENTATION_H

#include "fileinfo/file_presentation/file_presentation.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/iterative_subtitle_getter.h"

namespace fileinfo {

/**
 * JSON presentation class
 */
class JsonPresentation : public FilePresentation
{
	private:
		bool verbose; ///< @c true - print all information about file

		/// @name Auxiliary presentation methods
		/// @{
		void presentErrors(Json::Value &root) const;
		void presentLoaderError(Json::Value &root) const;
		void presentCompiler(Json::Value &root) const;
		void presentLanguages(Json::Value &root) const;
		void presentRichHeader(Json::Value &root) const;
		void presentPackingInfo(Json::Value &root) const;
		void presentOverlay(Json::Value &root) const;
		void presentPatterns(Json::Value &root) const;
		void presentLoaderInfo(Json::Value &root) const;
		void presentCertificateAttributes(Json::Value &root) const;
		void presentDotnetInfo(Json::Value &root) const;
		void presentElfNotes(Json::Value &root) const;
		void presentFlags(Json::Value &root, const std::string &title, const std::string &flags, const std::vector<std::string> &desc) const;
		void presentIterativeSubtitleStructure(Json::Value &root, const IterativeSubtitleGetter &getter, std::size_t structIndex) const;
		void presentIterativeSubtitle(Json::Value &root, const IterativeSubtitleGetter &getter) const;
		/// @}
	public:
		JsonPresentation(FileInformation &fileinfo_, bool verbose_);
		virtual ~JsonPresentation() override;

		virtual bool present() override;
};

} // namespace fileinfo

#endif
