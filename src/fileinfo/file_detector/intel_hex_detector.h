/**
 * @file src/fileinfo/file_detector/intel_hex_detector.h
 * @brief Definition of @c IntelHexDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_INTEL_HEX_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_INTEL_HEX_DETECTOR_H

#include "fileinfo/file_detector/file_detector.h"

namespace fileinfo {

/**
 * @c IntelHexDetector - find info about Intel HEX binary file
 */
class IntelHexDetector : public FileDetector
{
	private:
		std::shared_ptr<retdec::fileformat::IntelHexFormat> ihexParser; ///< file parser

		/// @name Auxiliary detection methods
		/// @{
		void getSections();
		/// @}
	protected:
		/// @name Detection methods
		/// @{
		virtual void detectFileClass() override;
		virtual void detectArchitecture() override;
		virtual void detectFileType() override;
		virtual void getAdditionalInfo() override;
		virtual retdec::cpdetect::CompilerDetector* createCompilerDetector() const override;
		/// @}

	public:
		IntelHexDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);
		virtual ~IntelHexDetector() override;
};

} // namespace fileinfo

#endif
