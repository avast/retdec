/**
 * @file include/retdec/cpdetect/compiler_detector/heuristics/pe_heuristics.h
 * @brief Definition of PeHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_HEURISTICS_PE_HEURISTICS_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_HEURISTICS_PE_HEURISTICS_H

#include "retdec/cpdetect/compiler_detector/heuristics/heuristics.h"
#include "retdec/fileformat/file_format/pe/pe_format.h"

namespace retdec {
namespace cpdetect {

/**
 * PE-specific heuristics
 */
class PeHeuristics : public Heuristics
{
	private:
		retdec::fileformat::PeFormat &peParser; ///< parser of input PE file

		std::size_t declaredLength; ///< declared length of file
		std::size_t loadedLength;   ///< actual loaded length of file

		/// @name Auxiliary methods
		/// @{
		std::string getEnigmaVersion();
		std::string getUpxAdditionalInfo(std::size_t metadataPos);
		/// @}

		/// @name Heuristics for detection of original language
		/// @{
		void getGoHeuristics();
		void getAutoItHeuristics();
		void getDotNetHeuristics();
		void getVisualBasicHeuristics();
		/// @}

		/// @name Heuristics for detection of used compiler or packer
		/// @{
		void getSlashedSignatures();
		void getMorphineHeuristics();
		void getPelockHeuristics();
		void getEzirizReactorHeuristics();
		void getUpxHeuristics();
		void getFsgHeuristics();
		void getPeCompactHeuristics();
		void getAndpakkHeuristics();
		void getEnigmaHeuristics();
		void getVBoxHeuristics();
		void getActiveDeliveryHeuristics();
		void getAdeptProtectorHeuristics();
		void getCodeLockHeuristics();
		void getNetHeuristic();
		void getExcelsiorHeuristics();
		void getVmProtectHeuristics();
		void getBorlandDelphiHeuristics();
		void getBeRoHeuristics();
		void getMsvcIntelHeuristics();
		void getArmadilloHeuristic();
		void getStarforceHeuristic();
		void getLinkerVersionHeuristic();
		void getRdataHeuristic();
		void getNullsoftHeuristic();
		void getManifestHeuristic();
		void getSevenZipHeuristics();
		void getMewSectionHeuristics();
		void getNsPackSectionHeuristics();
		void getPeSectionHeuristics();
		/// @}

	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		virtual void getFormatSpecificLanguageHeuristics() override;
		/// @}

	public:
		PeHeuristics(
				retdec::fileformat::PeFormat &parser, Search &searcher,
				ToolInformation &toolInfo);
		virtual ~PeHeuristics() override;
};

} // namespace cpdetect
} // namespace retdec

#endif
