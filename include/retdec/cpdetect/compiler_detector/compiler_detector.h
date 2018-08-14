/**
 * @file include/retdec/cpdetect/compiler_detector/compiler_detector.h
 * @brief Class for tool detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_COMPILER_DETECTOR_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_COMPILER_DETECTOR_H

#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/non_copyable.h"
#include "yaracpp/yara_detector/yara_detector.h"
#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/cpdetect/compiler_detector/search/search.h"

namespace retdec {
namespace cpdetect {

/**
 * CompilerDetector - find information about tools
 */
class CompilerDetector : private retdec::utils::NonCopyable
{
	private:
		retdec::fileformat::FileFormat &fileParser; ///< parser of input file
		DetectParams &cpParams;                     ///< parameters for detection
		std::vector<std::string> externalDatabase;  ///< name of external files with rules

		/// @name External databases parsing
		/// @{
		bool getExternalDatabases();
		/// @}

		/// @name Other methods
		/// @{
		void removeCompilersWithLessSimilarity(double ratio);
		void removeUnusedCompilers();
		/// @}

		/// @name Detection methods
		/// @{
		void getAllHeuristics();
		ReturnCode getAllSignatures();
		ReturnCode getAllCompilers();
		/// @}

	protected:
		ToolInformation &toolInfo;                           ///< results - detected tools
		retdec::fileformat::Architecture targetArchitecture; ///< target architecture of input file
		Search *search;                                      ///< class for signature search
		Heuristics *heuristics;                              ///< class for heuristics detections
		std::vector<std::string> internalPaths;              ///< internal rule database files
		retdec::utils::FilesystemPath pathToShared;          ///< path to shared folder
		std::set<std::string> externalSuffixes;              ///< external database file suffixes

	public:
		CompilerDetector(
				retdec::fileformat::FileFormat &parser, DetectParams &params,
				ToolInformation &toolInfo);
		virtual ~CompilerDetector() = 0;

		/// @name Detection methods
		/// @{
		ReturnCode getAllInformation();
		/// @}
};

} // namespace cpdetect
} // namespace retdec

#endif
