/**
 * @file src/fileinfo/file_detector/coff_detector.h
 * @brief Definition of CoffDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_COFF_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_COFF_DETECTOR_H

#include "fileinfo/file_detector/file_detector.h"
#include "fileinfo/file_wrapper/coff_wrapper.h"

namespace fileinfo {

/**
 * CoffDetector - find info about COFF binary file
 */
class CoffDetector : public FileDetector
{
	private:
		std::shared_ptr<CoffWrapper> coffParser; ///< file parser

		/// @name Auxiliary detection methods
		/// @{
		void getFileFlags();
		void getHeaderInfo();
		void getCoffSymbols();
		void getCoffRelocations();
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
		CoffDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);
		virtual ~CoffDetector() override;
};

} // namespace fileinfo

#endif
