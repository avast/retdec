/**
 * @file include/cpdetec/compiler_detector/compiler_detector.h
 * @brief Class for tool detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_COMPILER_DETECTOR_H
#define CPDETECT_COMPILER_DETECTOR_COMPILER_DETECTOR_H

#include "tl-cpputils/non_copyable.h"
#include "yaracpp/yara_detector/yara_detector.h"
#include "cpdetect/compiler_detector/heuristics/heuristics.h"
#include "cpdetect/compiler_detector/search/search.h"

namespace cpdetect {

/**
 * CompilerDetector - find information about tools
 */
class CompilerDetector : private tl_cpputils::NonCopyable
{
	private:
		fileformat::FileFormat &fileParser;       ///< parser of input file
		DetectParams &cpParams;                    ///< parameters for detection
		std::vector<std::string> externalDatabase; ///< name of external files with rules

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
		ToolInformation &toolInfo;                        ///< results - detected tools
		fileformat::Architecture targetArchitecture;     ///< target architecture of input file
		Search *search;                                   ///< class for search in signature
		Heuristics *heuristics;                           ///< class for heuristics detection of used tool
		const std::vector<const char*> *internalDatabase; ///< internal database of rules
		std::set<std::string> externalSuffixes;           ///< suffixes for external database files
	public:
		CompilerDetector(fileformat::FileFormat &parser, DetectParams &params, ToolInformation &toolInfo);
		virtual ~CompilerDetector() = 0;

		/// @name Detection methods
		/// @{
		ReturnCode getAllInformation();
		/// @}
};

} // namespace cpdetect

#endif
