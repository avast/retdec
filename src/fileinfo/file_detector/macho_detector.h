/**
 * @file src/fileinfo/file_detector/macho_detector.h
 * @brief Definition of MachODetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_MACHO_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_MACHO_DETECTOR_H

#include "fileinfo/file_detector/file_detector.h"
#include "fileinfo/file_wrapper/macho_wrapper.h"

namespace fileinfo {

/**
 * MachODetector - find info about MachO binary file
 */
class MachODetector : public FileDetector
{
	private:
		std::shared_ptr<MachOWrapper> machoParser; ///< file parser
	protected:
		/// @name Auxiliary detection methods
		/// @{
		void getEntryPoint();
		void getSegments();
		void getSections();
		void getSymbols();
		void getEncryption();
		void getOsInfo();
		void getRelocations();
		/// @}

		/// @name Detection methods
		/// @{
		virtual void detectFileClass() override;
		virtual void detectArchitecture() override;
		virtual void detectFileType() override;
		virtual void getAdditionalInfo() override;
		virtual retdec::cpdetect::CompilerDetector* createCompilerDetector() const override;
		/// @}
	public:
		MachODetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);
		virtual ~MachODetector() override;
		bool isMachoUniversalArchive();
};

} // namespace fileinfo

#endif
