/**
 * @file src/fileinfo/file_detector/file_detector.h
 * @brief Definition of FileDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_DETECTOR_FILE_DETECTOR_H
#define FILEINFO_FILE_DETECTOR_FILE_DETECTOR_H

#include "tl-cpputils/non_copyable.h"
#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * FileDetector - find info about binary file
 */
class FileDetector : private tl_cpputils::NonCopyable
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
		cpdetect::DetectParams &cpParams;                   ///< parameters for detection of used compiler
		retdec_config::Config *fileConfig;                 ///< configuration of input file
		std::shared_ptr<fileformat::FileFormat> fileParser; ///< parser of input file
		bool loaded;                                         ///< internal state of instance
		fileformat::LoadFlags loadFlags;                    ///< load flags for configurable running

		/// @name Pure virtual detection methods
		/// @{
		virtual void detectFileClass() = 0;
		virtual void detectArchitecture() = 0;
		virtual void detectFileType() = 0;
		virtual void getAdditionalInfo() = 0;
		virtual cpdetect::CompilerDetector* createCompilerDetector() const = 0;
		/// @}
	public:
		FileDetector(std::string pathToInputFile, FileInformation &finfo, cpdetect::DetectParams &searchPar, fileformat::LoadFlags loadFlags);
		virtual ~FileDetector();

		void setConfigFile(retdec_config::Config &config);
		void getAllInformation();
		const fileformat::FileFormat* getFileParser() const;
};

} // namespace fileinfo

#endif
