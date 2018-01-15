/**
 * @file src/fileinfo/file_detector/raw_data_detector.h
 * @brief Definition of @c RawDataDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_RAW_DATA_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_RAW_DATA_DETECTOR_H

#include "fileinfo/file_detector/file_detector.h"

namespace fileinfo {

/**
 * @c RawDataDetector - find info about raw binary
 */
class RawDataDetector : public FileDetector
{
	private:
		std::shared_ptr<retdec::fileformat::RawDataFormat> rawParser; ///< file parser

		/// @name Auxiliary detection methods
		/// @{
		void getSection();
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
		RawDataDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);
		virtual ~RawDataDetector() override;
};

} // namespace fileinfo

#endif
