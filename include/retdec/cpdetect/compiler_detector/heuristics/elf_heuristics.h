/**
 * @file include/retdec/cpdetect/compiler_detector/heuristics/elf_heuristics.h
 * @brief Definition of ElfHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_HEURISTICS_ELF_HEURISTICS_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_HEURISTICS_ELF_HEURISTICS_H

#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/fileformat/file_format/elf/elf_format.h"

namespace retdec {
namespace cpdetect {

/**
 * ELF-specific heuristics
 */
class ElfHeuristics : public Heuristics
{
	private:
		retdec::fileformat::ElfFormat &elfParser; ///< parser of input ELF file

		/// @name Detection methods
		/// @{
		void getUpxHeuristics();
		void getNoteHeuristics();
		void getBorlandKylixHeuristics();
		void getDynamicEntriesHeuristics();
		/// @}

	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		/// @}

	public:
		ElfHeuristics(
				retdec::fileformat::ElfFormat &parser, Search &searcher,
				ToolInformation &toolInfo);
		virtual ~ElfHeuristics() override;
};

} // namespace cpdetect
} // namespace retdec

#endif
