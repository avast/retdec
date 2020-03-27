/**
 * @file include/retdec/stacofin/stacofin.h
 * @brief Static code finder library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_STACOFIN_STACOFIN_H
#define RETDEC_STACOFIN_STACOFIN_H

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <capstone/capstone.h>

#include "retdec/config/config.h"
#include "retdec/common/address.h"

namespace retdec {
namespace loader {
	class Image;
} // namespace loader

namespace stacofin {

struct DetectedFunction;

/**
 * Data-type for offset-name relocation pairs.
 */
using CoveredCode = retdec::common::AddressRangeContainer;

/**
 * Structure representing one reference in a detected function's body.
 */
struct Reference
{
	public:
		Reference(
				std::size_t o,
				const std::string& n,
				common::Address a = common::Address::Undefined,
				common::Address t = common::Address::Undefined,
				DetectedFunction* tf = nullptr,
				bool k = false);

	public:
		std::size_t offset = 0;
		std::string name;

		common::Address address;
		common::Address target;
		DetectedFunction* targetFnc = nullptr;
		bool ok = false;
};

using References = std::vector<Reference>;

/**
 * Structure representing one detected function.
 */
struct DetectedFunction
{
	public:
		bool operator<(const DetectedFunction& o) const;

		bool allRefsOk() const;
		std::size_t countRefsOk() const;
		float refsOkShare() const;
		std::string getName() const;
		bool isTerminating() const;
		bool isThumb() const;

		void setReferences(const std::string &refsString);

		void setAddress(retdec::common::Address a);
		retdec::common::Address getAddress() const;

	public:
		/// Original size of source.
		std::size_t size;
		// File offset.
		std::size_t offset;

		/// Possible original names.
		std::vector<std::string> names;
		/// Offset-name relocation pairs.
		References references;

		/// Source signature path.
		std::string signaturePath;

	private:
		/// Virtual address.
		retdec::common::Address address;
};

using DetectedFunctionsPtrMap = typename std::map<
		common::Address,
		DetectedFunction*>;
using DetectedFunctionsMultimap = typename std::multimap<
		common::Address,
		DetectedFunction>;
using DetectedFunctionsPtrMultimap = typename std::multimap<
		common::Address,
		DetectedFunction*>;

/**
 * Finder implementation using Yara.
 */
class Finder
{
	public:
		/// @name Actions.
		/// @{
		void search(
				const retdec::loader::Image& image,
				const std::string& yaraFile);
		void search(
				const retdec::loader::Image& image,
				const std::set<std::string>& yaraFiles);
		void search(
				const retdec::loader::Image& image,
				const retdec::config::Config& config);
		void searchAndConfirm(
				const retdec::loader::Image& image,
				const retdec::config::Config& config);
		/// @}

		/// @name Getters.
		/// @{
		CoveredCode getCoveredCode();
		const DetectedFunctionsMultimap& getAllDetections() const;
		const DetectedFunctionsPtrMap& getConfirmedDetections() const;
		/// @}

	private:
		/// Code coverage.
		CoveredCode coveredCode;

		DetectedFunctionsMultimap _allDetections;
		DetectedFunctionsPtrMap _confirmedDetections;
		DetectedFunctionsPtrMultimap _rejectedDetections;

		struct DetectedFunctionComp
		{
			bool operator()(
					const DetectedFunction* a,
					const DetectedFunction* b) const
			{
				return *a < *b;
			}
		};
		std::set<DetectedFunction*, DetectedFunctionComp> _worklistDetections;

	private:
		using ByteData = typename std::pair<const std::uint8_t*, std::size_t>;

	private:
		bool initDisassembler();
		void solveReferences();

		common::Address getAddressFromRef(common::Address ref);
		common::Address getAddressFromRef_x86(common::Address ref);
		common::Address getAddressFromRef_mips(common::Address ref);
		common::Address getAddressFromRef_arm(common::Address ref);
		common::Address getAddressFromRef_ppc(common::Address ref);

		void checkRef(Reference& ref);
		void checkRef_x86(Reference& ref);

		void confirmWithoutRefs();
		void confirmAllRefsOk(std::size_t minFncSzWithoutRefs = 0x20);
		void confirmPartialRefsOk(float okShare = 0.5);
		void confirmFunction(DetectedFunction* f);

	private:
		const retdec::config::Config* _config = nullptr;
		const retdec::loader::Image* _image = nullptr;

		csh _ce = 0;
		cs_mode _ceMode = CS_MODE_LITTLE_ENDIAN;
		cs_insn* _ceInsn = nullptr;

		std::map<common::Address, std::string> _imports;
		std::set<std::string> _sectionNames;
};

} // namespace stacofin
} // namespace retdec

#endif
