/**
 * @file include/cpdetec/compiler_detector/heuristics/pe_heuristics.h
 * @brief Definition of PeHeuristics class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_COMPILER_DETECTOR_HEURISTICS_PE_HEURISTICS_H
#define CPDETECT_COMPILER_DETECTOR_HEURISTICS_PE_HEURISTICS_H

#include "cpdetect/compiler_detector/heuristics/heuristics.h"
#include "fileformat/file_format/pe/pe_format.h"

namespace cpdetect {

/**
 * PE-specific heuristics
 */
class PeHeuristics : public Heuristics
{
	private:
		fileformat::PeFormat &peParser; ///< parser of input PE file

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
		void getPhoenixHeuristics();
		void getAssemblyInvokeHeuristics();
		void getCliSecureHeuristics();
		void getReNetPackHeuristics();
		void getDotNetZHeuristics();
		void getDotNetSpiderHeuristics();
		void getDotNetShrinkHeuristics();
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
		/// @}
	protected:
		/// @name Virtual methods
		/// @{
		virtual void getFormatSpecificCompilerHeuristics() override;
		virtual void getFormatSpecificLanguageHeuristics() override;
		/// @}
	public:
		PeHeuristics(fileformat::PeFormat &parser, Search &searcher, ToolInformation &toolInfo);
		virtual ~PeHeuristics() override;
};

} // namespace cpdetect

#endif
