/**
 * @file src/fileinfo/file_presentation/config_presentation.h
 * @brief Config DB presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_CONFIG_PRESENTATION_H
#define FILEINFO_FILE_PRESENTATION_CONFIG_PRESENTATION_H

#include "retdec/config/config.h"
#include "fileinfo/file_presentation/file_presentation.h"

namespace fileinfo {

class ConfigPresentation : public FilePresentation
{
	private:
		std::string configFile;         ///< name of output file
		retdec::config::Config outDoc; ///< representation of output file
		bool stateIsValid;              ///< internal state of instance
		std::string errorMessage;       ///< error message

		/// @name Auxiliary presentation methods
		/// @{
		void presentCompiler();
		void presentLanguages();
		void presentPatterns();
		/// @}
	public:
		ConfigPresentation(FileInformation &fileinfo_, std::string file_);
		virtual ~ConfigPresentation() override;

		virtual bool present() override;
		std::string getErrorMessage() const;
};

} // namespace fileinfo

#endif
