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

class StaticCodeFunction
{
	public:
		class Reference
		{
			public:
				Reference(
						std::size_t o,
						utils::Address a,
						const std::string& n,
						utils::Address t = utils::Address::getUndef,
						StaticCodeFunction* tf = nullptr,
						bool k = false);

			public:
				std::size_t offset = 0;
				utils::Address address;
				std::string name;

				utils::Address target;
				StaticCodeFunction* targetFnc = nullptr;
				bool ok = false;
		};

	public:
		StaticCodeFunction(const stacofin::DetectedFunction& df);
		bool operator<(const StaticCodeFunction& o) const;

		bool allRefsOk() const;
		std::size_t countRefsOk() const;
		float refsOkShare() const;
		std::string getName() const;
		bool isTerminating() const;
		bool isThumb() const;

	public:
		utils::Address address;
		std::size_t size;
		std::vector<std::string> names;
		std::string signaturePath;

		std::vector<Reference> references;
};

class StaticCodeAnalysis
{
	public:
		using DetectedFunctionsPtrMap = typename std::map<
				utils::Address,
				StaticCodeFunction*>;
		using DetectedFunctionsMultimap = typename std::multimap<
				utils::Address,
				StaticCodeFunction>;
		using DetectedFunctionsPtrMultimap = typename std::multimap<
				utils::Address,
				StaticCodeFunction*>;

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

		void checkRef(StaticCodeFunction::Reference& ref);
		void checkRef_x86(StaticCodeFunction::Reference& ref);

		void confirmWithoutRefs();
		void confirmAllRefsOk(std::size_t minFncSzWithoutRefs = 0x20);
		void confirmPartialRefsOk(float okShare = 0.5);
		void confirmFunction(StaticCodeFunction* f);

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
		struct StaticCodeFunctionComp
		{
			bool operator()(const StaticCodeFunction* a, const StaticCodeFunction* b) const
			{
				return *a < *b;
			}
		};
		std::set<StaticCodeFunction*, StaticCodeFunctionComp> _worklistDetections;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
