/**
 * @file src/fileinfo/pattern_detector/pattern_detector.h
 * @brief Definition of PatternDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_PATTERN_DETECTOR_PATTERN_DETECTOR_H
#define FILEINFO_PATTERN_DETECTOR_PATTERN_DETECTOR_H

#include <set>
#include <string>
#include <vector>

#include "yaracpp/yara_detector/yara_detector.h"
#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * Detector of YARA patterns
 */
class PatternDetector
{
	private:
		using patternCategoriesIterator = std::vector<std::pair<std::string, std::set<std::string>>>::const_iterator;
		const retdec::fileformat::FileFormat *fileParser;                             ///< parser of input file
		FileInformation &fileinfo;                                             ///< information about input file
		std::vector<std::pair<std::string, std::set<std::string>>> categories; ///< paths to YARA rules

		/// @name Iterators
		/// @{
		patternCategoriesIterator begin() const;
		patternCategoriesIterator end() const;
		/// @}

		/// @name Auxiliary methods
		/// @{
		void createPatternFromRule(Pattern &pattern, const yaracpp::YaraRule &rule);
		void saveCryptoRule(const yaracpp::YaraRule &rule);
		void saveMalwareRule(const yaracpp::YaraRule &rule);
		void saveOtherRule(const yaracpp::YaraRule &rule);
		/// @}
	public:
		PatternDetector(const retdec::fileformat::FileFormat *fparser, FileInformation &finfo);
		~PatternDetector();

		/// @name Detection methods
		/// @{
		void addFilePaths(const std::string &category, const std::set<std::string> &paths);
		void analyze();
		/// @}
};

} // namespace fileinfo

#endif
