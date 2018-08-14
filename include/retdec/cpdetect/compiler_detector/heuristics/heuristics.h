/**
 * @file include/retdec/cpdetect/compiler_detector/heuristics/heuristics.h
 * @brief Class for heuristics detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_HEURISTICS_HEURISTICS_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_HEURISTICS_HEURISTICS_H

#include "retdec/cpdetect/compiler_detector/search/search.h"
#include "retdec/cpdetect/cptypes.h"
#include "retdec/fileformat/file_format/file_format.h"

namespace retdec {
namespace cpdetect {

/**
 * Class for heuristics detection
 */
class Heuristics
{
	private:
		/// @name Sections heuristics
		/// @{
		void getSectionHeuristics();
		/// @}

		/// @name Comment sections heuristics
		/// @{
		bool parseGccComment(const std::string &record);
		bool parseGhcComment(const std::string &record);
		bool parseOpen64Comment(const std::string &record);
		void getCommentSectionsHeuristics();
		/// @}

		/// @name DWARF heuristics
		/// @{
		bool parseGccProducer(const std::string &producer);
		bool parseClangProducer(const std::string &producer);
		bool parseTmsProducer(const std::string &producer);
		void getDwarfInfo();
		/// @}

		/// @name Delphi specific heuristics
		/// @{
		std::string getEmbarcaderoVersion();
		void getEmbarcaderoHeuristics();
		/// @}

		/// @name Symbol heuristics
		/// @{
		void getSymbolHeuristic();
		/// @}

		/// @name Heuristics methods
		/// @{
		void getCommonToolsHeuristics();
		void getCommonLanguageHeuristics();
		/// @}

	protected:
		retdec::fileformat::FileFormat &fileParser; ///< input file parser
		Search &search;                             ///< signature search engine
		bool canSearch;                             ///< @c true if we can use search engine
		ToolInformation &toolInfo;                  ///< results - detected tools

		std::vector<const retdec::fileformat::Section*> sections; ///< section information
		std::map<std::string, std::size_t> sectionNameMap;        ///< section name counts
		std::size_t noOfSections;                                 ///< section count

		/**
		 * If @c true original language is detected with high reliability.
		 * This disables further detection of used programming languages.
		 */
		bool priorityLanguageIsSet = false;

		/// @name Auxiliary methods
		/// @{
		std::string getUpxVersion();
		const DetectResult* isDetected(
				const std::string &name,
				const DetectionStrength minStrength = DetectionStrength::LOW);
		/// @}

		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics();
		virtual void getFormatSpecificLanguageHeuristics();
		/// @}

		/// @name Add heuristic detection methods
		/// @{
		void addCompiler(
				DetectionMethod source, DetectionStrength strength, const std::string &name,
				const std::string &version = "", const std::string &extra = "");
		void addLinker(
				DetectionMethod source, DetectionStrength strength, const std::string &name,
				const std::string &version = "", const std::string &extra = "");
		void addInstaller(
				DetectionMethod source, DetectionStrength strength, const std::string &name,
				const std::string &version = "", const std::string &extra = "");
		void addPacker(
				DetectionMethod source, DetectionStrength strength, const std::string &name,
				const std::string &version = "", const std::string &extra = "");
		/// @}

		/// @name Add signature detection methods
		/// @{
		void addCompiler(
				std::size_t matchNibbles, std::size_t totalNibbles, const std::string &name,
				const std::string &version = "", const std::string &extra = "");
		void addPacker(
				std::size_t matchNibbles, std::size_t totalNibbles, const std::string &name,
				const std::string &version = "", const std::string &extra = "");
		/// @}

		/// @name Add language methods
		/// @{
		void addLanguage(
				const std::string &name, const std::string &extraInfo = "",
				bool isBytecode = false);
		void addPriorityLanguage(
				const std::string &name, const std::string &extraInfo = "",
				bool isBytecode = false);
		/// @}

		/// @name Other methods
		/// @{
		std::size_t findSectionName(const std::string &sectionName) const;
		std::size_t findSectionNameStart(const std::string &sectionName) const;
		/// @}

	public:
		Heuristics(
				retdec::fileformat::FileFormat &parser, Search &searcher,
				ToolInformation &toolInfo);
		virtual ~Heuristics();

		/// @name Heuristics methods
		/// @{
		void getAllHeuristics();
		/// @}
};

} // namespace cpdetect
} // namespace retdec

#endif
