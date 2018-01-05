/**
 * @file include/cpdetec/compiler_detector/heuristics/elf_heuristics.h
 * @brief Definition of ElfHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_HEURISTICS_ELF_HEURISTICS_H
#define CPDETECT_COMPILER_DETECTOR_HEURISTICS_ELF_HEURISTICS_H

#include "cpdetect/compiler_detector/heuristics/heuristics.h"
#include "fileformat/file_format/elf/elf_format.h"

namespace cpdetect {

/**
 * ELF-specific heuristics
 */
class ElfHeuristics : public Heuristics
{
	private:
		fileformat::ElfFormat &elfParser; ///< parser of input ELF file

		/// @name Detection methods
		/// @{
		void getUpxHeuristics();
		void getBorlandKylixHeuristics();
		void getDynamicEntriesHeuristics();
		/// @}

	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		/// @}

	public:
		ElfHeuristics(fileformat::ElfFormat &parser, Search &searcher, ToolInformation &toolInfo);
		virtual ~ElfHeuristics() override;
};

} // namespace cpdetect

#endif
