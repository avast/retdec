/**
 * @file src/fileinfo/file_presentation/plain_presentation.h
 * @brief Plain text presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_PLAIN_PRESENTATION_H
#define FILEINFO_FILE_PRESENTATION_PLAIN_PRESENTATION_H

#include "fileinfo/file_presentation/file_presentation.h"

namespace fileinfo {

/**
 * Plain text presentation class
 */
class PlainPresentation : public FilePresentation
{
	private:
		bool verbose;     ///< @c true - print all information about file
		bool explanatory; ///< @c true - print explanatory notes

		/// @name Auxiliary presentation methods
		/// @{
		void presentCompiler() const;
		void presentLanguages() const;
		void presentRichHeader() const;
		void presentOverlay() const;
		void presentPackingInfo() const;
		void presentSimpleFlags(const std::string &title, const std::string &flags, const std::vector<std::string> &desc, const std::vector<std::string> &abbv) const;
		void presentPatterns(const std::string &title, const std::vector<Pattern> &patterns);
		void presentDotnetClasses() const;
		void presentNotes() const;
		void presentCore() const;
		/// @}
	public:
		PlainPresentation(FileInformation &fileinfo_, bool verbose_, bool explanatory_);
		virtual ~PlainPresentation() override;

		virtual bool present() override;
};

} // namespace fileinfo

#endif
