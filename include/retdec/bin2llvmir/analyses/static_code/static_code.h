/**
* @file include/retdec/bin2llvmir/analyses/static_code/static_code.h
* @brief Static code analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_STATIC_CODE_STATIC_CODE_H
#define RETDEC_BIN2LLVMIR_ANALYSES_STATIC_CODE_STATIC_CODE_H

#include <map>

#include <capstone/capstone.h>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/stacofin/stacofin.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

class StaticCodeAnalysis
{
	public:
		using DetectedFunctionsPtrMap = typename std::map<
				utils::Address,
				retdec::stacofin::DetectedFunction*>;
		using DetectedFunctionsMultimap = typename std::multimap<
				utils::Address,
				retdec::stacofin::DetectedFunction>;
		using DetectedFunctionsPtrMultimap = typename std::multimap<
				utils::Address,
				retdec::stacofin::DetectedFunction*>;

	public:
		StaticCodeAnalysis(
				Config* c,
				FileImage* i,
				NameContainer* ns,
				csh ce,
				cs_mode md,
				bool debug = false);
		~StaticCodeAnalysis();

		const DetectedFunctionsMultimap& getAllDetections() const;
		const DetectedFunctionsPtrMap& getConfirmedDetections() const;

	private:
		using ByteData = typename std::pair<const std::uint8_t*, std::size_t>;

	private:
		void solveReferences();

		utils::Address getAddressFromRef(utils::Address ref);
		utils::Address getAddressFromRef_x86(utils::Address ref);
		utils::Address getAddressFromRef_mips(utils::Address ref);
		utils::Address getAddressFromRef_arm(utils::Address ref);
		utils::Address getAddressFromRef_ppc(utils::Address ref);

		void checkRef(retdec::stacofin::Reference& ref);
		void checkRef_x86(retdec::stacofin::Reference& ref);

		void confirmWithoutRefs();
		void confirmAllRefsOk(std::size_t minFncSzWithoutRefs = 0x20);
		void confirmPartialRefsOk(float okShare = 0.5);
		void confirmFunction(retdec::stacofin::DetectedFunction* f);

	private:
		Config* _config = nullptr;
		FileImage* _image = nullptr;
		NameContainer* _names = nullptr;

		csh _ce;
		cs_mode _ceMode;
		cs_insn* _ceInsn = nullptr;

		stacofin::Finder _codeFinder;

		std::set<std::string> _sigPaths;
		std::map<utils::Address, std::string> _imports;
		std::set<std::string> _sectionNames;

		DetectedFunctionsMultimap _allDetections;
		DetectedFunctionsPtrMap _confirmedDetections;
		DetectedFunctionsPtrMultimap _rejectedDetections;

	private:
		struct DetectedFunctionComp
		{
			bool operator()(
					const retdec::stacofin::DetectedFunction* a,
					const retdec::stacofin::DetectedFunction* b) const
			{
				return *a < *b;
			}
		};
		std::set<retdec::stacofin::DetectedFunction*, DetectedFunctionComp> _worklistDetections;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
