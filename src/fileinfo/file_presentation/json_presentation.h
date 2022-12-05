/**
 * @file src/fileinfo/file_presentation/json_presentation.h
 * @brief Plain text presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_JSON_PRESENTATION_H
#define FILEINFO_FILE_PRESENTATION_JSON_PRESENTATION_H

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/encodings.h>

#include "fileinfo/file_presentation/file_presentation.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/iterative_subtitle_getter.h"

namespace retdec {
namespace fileinfo {

/**
 * JSON presentation class
 */
class JsonPresentation : public FilePresentation
{
	public:
		using Writer = rapidjson::PrettyWriter<
				rapidjson::StringBuffer,
				rapidjson::ASCII<>>;

	private:
		bool verbose;      ///< @c true - print all information about file
		bool analysisTime; ///< @c true - print when the analysis was done

		/// @name Auxiliary presentation methods
		/// @{
		void presentFileinfoVersion(Writer& writer) const;
		void presentErrors(Writer& writer) const;
		void presentLoaderError(Writer& writer) const;
		void presentCompiler(Writer& writer) const;
		void presentLanguages(Writer& writer) const;
		void presentRichHeader(Writer& writer) const;
		void presentPackingInfo(Writer& writer) const;
		void presentOverlay(Writer& writer) const;
		void presentPatterns(Writer& writer) const;
		void presentMissingDepsInfo(Writer& writer) const;
		void presentLoaderInfo(Writer& writer) const;
		void presentCertificates(Writer& writer) const;
		void presentTlsInfo(Writer& writer) const;
		void presentDotnetInfo(Writer& writer) const;
		void presentVersionInfo(Writer& writer) const;
		void presentVisualBasicInfo(Writer& writer) const;
		void presentElfNotes(Writer& writer) const;
		void presentFlags(
				Writer& writer,
				const std::string &title,
				const std::string &flags,
				const std::vector<std::string> &desc) const;
		void presentIterativeSubtitleStructure(
				Writer& writer,
				const IterativeSubtitleGetter &getter,
				std::size_t structIndex) const;
		void presentIterativeSubtitle(
				Writer& writer,
				const IterativeSubtitleGetter &getter) const;
		/// @}
	public:
		JsonPresentation(FileInformation &fileinfo_, bool verbose_, bool analysisTime_);

		virtual bool present() override;
};

} // namespace fileinfo
} // namespace retdec

#endif
