/**
 * @file include/cpdetec/compiler_detector/heuristics/macho_heuristics.h
 * @brief Definition of MachOHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_HEURISTICS_MACHO_HEURISTICS_H
#define CPDETECT_COMPILER_DETECTOR_HEURISTICS_MACHO_HEURISTICS_H

#include "cpdetect/compiler_detector/heuristics/heuristics.h"
#include "fileformat/file_format/macho/macho_format.h"

namespace cpdetect {

/**
 * Mach-O-specific heuristics
 */
class MachOHeuristics : public Heuristics
{
	private:
		/// @name Detection methods
		/// @{
		void getUpxHeuristic();
		void getGoHeuristic();
		void getSectionTableHeuristic();
		void getImportTableHeuristic();
		/// @}

	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		/// @}

	public:
		MachOHeuristics(fileformat::MachOFormat &parser, Search &searcher, ToolInformation &toolInfo);
		virtual ~MachOHeuristics() override;
};

} // namespace cpdetect

#endif
