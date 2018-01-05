/**
 * @file include/cpdetec/compiler_detector/heuristics/heuristics.h
 * @brief Class for heuristics detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_HEURISTICS_HEURISTICS_H
#define CPDETECT_COMPILER_DETECTOR_HEURISTICS_HEURISTICS_H

#include "cpdetect/compiler_detector/search/search.h"
#include "cpdetect/cptypes.h"
#include "fileformat/file_format/file_format.h"

namespace cpdetect {

/**
 * Class for heuristics detection
 */
class Heuristics
{
	private:
		/// @name Sections heuristics
		/// @{
		void getMewSectionHeuristics();
		void getNsPackSectionHeuristics();
		void getSectionHeuristics();
		/// @}

		/// @name Comment sections heuristics
		/// @{
		bool parseGccComment(const std::string &record);
		bool parseOpen64Comment(const std::string &record);
		bool parseGhcComment(const std::string &record);
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
		fileformat::FileFormat &fileParser;               ///< parser of input file
		Search &search;                                    ///< class for search in signature (search engine)
		ToolInformation &toolInfo;                         ///< results - detected tools
		std::vector<const fileformat::Section*> sections; ///< information about file sections
		std::size_t noOfSections;                          ///< number of sections stored in @a sections
		bool priorityLanguageIsSet;                        ///< @c true - original language is detected and detection of other languages is disabled
		bool canSearch;                                    ///< @c true - we can use search engine

		std::map<std::string, std::size_t> sectionNameMap;

		/// @name Auxiliary methods
		/// @{
		std::string getUpxVersion();
		const DetectResult* isDetected(const std::string &name,
			const DetectionStrength minStrength = DetectionStrength::LOW);
		/// @}

		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics();
		virtual void getFormatSpecificLanguageHeuristics();
		/// @}

		/// @name Add heuristic detection methods
		/// @{
		void addCompiler(DetectionMethod source, DetectionStrength strength, const std::string &name,
			const std::string &version = "", const std::string &extra = "");
		void addLinker(DetectionMethod source, DetectionStrength strength, const std::string &name,
			const std::string &version = "", const std::string &extra = "");
		void addInstaller(DetectionMethod source, DetectionStrength strength, const std::string &name,
			const std::string &version = "", const std::string &extra = "");
		void addPacker(DetectionMethod source, DetectionStrength strength, const std::string &name,
			const std::string &version = "", const std::string &extra = "");
		/// @}

		/// @name Add signature detection methods
		/// @{
		void addCompiler(std::size_t matchNibbles, std::size_t totalNibbles, const std::string &name,
			const std::string &version = "", const std::string &extra = "");
		void addPacker(std::size_t matchNibbles, std::size_t totalNibbles, const std::string &name,
			const std::string &version = "", const std::string &extra = "");
		/// @}

		/// @name Add language methods
		/// @{
		void addLanguage(const std::string &name, const std::string &extraInfo = "", bool isBytecode = false);
		void addPriorityLanguage(const std::string &name, const std::string &extraInfo = "", bool isBytecode = false);
		/// @}

		/// @name Other methods
		/// @{
		std::size_t findSectionName(const std::string &sectionName) const;
		std::size_t findSectionNameStart(const std::string &sectionName) const;
		/// @}

	public:
		Heuristics(fileformat::FileFormat &parser, Search &searcher, ToolInformation &toolInfo);
		virtual ~Heuristics();

		/// @name Heuristics methods
		/// @{
		void getAllHeuristics();
		/// @}
};

} // namespace cpdetect

#endif
