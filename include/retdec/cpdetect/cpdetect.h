/**
 * @file include/retdec/cpdetect/cpdetect.h
 * @brief Class for tool detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_CPDETECT_H
#define RETDEC_CPDETECT_CPDETECT_H

#include "retdec/utils/filesystem.h"
#include "retdec/utils/non_copyable.h"
#include "retdec/cpdetect/cptypes.h"
#include "retdec/cpdetect/errors.h"
#include "retdec/cpdetect/heuristics/heuristics.h"
#include "retdec/cpdetect/search.h"

namespace retdec {
namespace cpdetect {

/**
 * CompilerDetector - find information about tools
 */
class CompilerDetector : private retdec::utils::NonCopyable
{
	private:
		retdec::fileformat::FileFormat &fileParser;
		DetectParams &cpParams;
		std::vector<std::string> externalDatabase;

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
		void populateInternalPaths(
				const fs::path& dir,
				const std::set<std::string>& formats,
				const std::set<std::string>& archs);

	protected:
		/// results - detected tools
		ToolInformation &toolInfo;
		retdec::fileformat::Architecture targetArchitecture;
		/// class for signature search
		Search search;
		/// class for heuristics detections
		std::unique_ptr<Heuristics> heuristics;
		/// internal rule database files
		std::vector<std::string> internalPaths;
		/// path to shared folder
		fs::path pathToShared;
		/// external database file suffixes
		std::set<std::string> externalSuffixes;

	public:
		CompilerDetector(
				retdec::fileformat::FileFormat &parser,
				DetectParams &params,
				ToolInformation &toolInfo);

		/// @name Detection methods
		/// @{
		ReturnCode getAllInformation();
		/// @}
};

} // namespace cpdetect
} // namespace retdec

#endif
