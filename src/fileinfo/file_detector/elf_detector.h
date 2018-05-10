/**
 * @file src/fileinfo/file_detector/elf_detector.h
 * @brief Definition of ElfDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_ELF_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_ELF_DETECTOR_H

#include "fileinfo/file_detector/file_detector.h"
#include "fileinfo/file_wrapper/elf_wrapper.h"

namespace fileinfo {

/**
 * ElfDetector - find info about ELF binary file
 */
class ElfDetector : public FileDetector
{
	private:
		std::shared_ptr<ElfWrapper> elfParser; ///< file parser

		/// @name Auxiliary detection methods
		/// @{
		void getFileVersion();
		void getFileHeaderInfo();
		void getOsAbiInfoNote();
		void getOsAbiInfo();
		void getFlags();
		void getSegments();
		void getSymbolTable();
		void getRelocationTable(const ELFIO::section *sec);
		void getDynamicSection(const ELFIO::section *sec);
		void getSections();
		void getNotes();
		void getCoreInfo();
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
		ElfDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);
		virtual ~ElfDetector() override;
};

} // namespace fileinfo

#endif
