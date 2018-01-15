/**
 * @file src/fileinfo/file_detector/file_detector.h
 * @brief Definition of FileDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_FILE_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_FILE_DETECTOR_H

#include "retdec/utils/non_copyable.h"
#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * FileDetector - find info about binary file
 */
class FileDetector : private retdec::utils::NonCopyable
{
	private:
		/// @name Detection methods
		/// @{
		void getEndianness();
		void getArchitectureBitSize();
		void getCompilerInformation();
		void getRichHeaderInfo();
		void getOverlayInfo();
		void getPdbInfo();
		void getResourceInfo();
		void getManifestInfo();
		void getImports();
		void getExports();
		void getHashes();
		void getStrings();
		void getCertificates();
		void getLoaderInfo();
		/// @}
	protected:
		FileInformation &fileInfo;                           ///< information about file
		retdec::cpdetect::DetectParams &cpParams;                   ///< parameters for detection of used compiler
		retdec::config::Config *fileConfig;                 ///< configuration of input file
		std::shared_ptr<retdec::fileformat::FileFormat> fileParser; ///< parser of input file
		bool loaded;                                         ///< internal state of instance
		retdec::fileformat::LoadFlags loadFlags;                    ///< load flags for configurable running

		/// @name Pure virtual detection methods
		/// @{
		virtual void detectFileClass() = 0;
		virtual void detectArchitecture() = 0;
		virtual void detectFileType() = 0;
		virtual void getAdditionalInfo() = 0;
		virtual retdec::cpdetect::CompilerDetector* createCompilerDetector() const = 0;
		/// @}
	public:
		FileDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags);
		virtual ~FileDetector();

		void setConfigFile(retdec::config::Config &config);
		void getAllInformation();
		const retdec::fileformat::FileFormat* getFileParser() const;
};

} // namespace fileinfo

#endif
