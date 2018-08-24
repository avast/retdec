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

#include "retdec/utils/address.h"

namespace retdec {
namespace loader {
	class Image;
} // namespace loader

namespace stacofin {

struct DetectedFunction;

/**
 * Data-type for offset-name relocation pairs.
 */
using CoveredCode = retdec::utils::AddressRangeContainer;

/**
 * Structure representing one reference in a detected function's body.
 */
struct Reference
{
	public:
		Reference(
				std::size_t o,
				const std::string& n,
				utils::Address a = utils::Address::getUndef,
				utils::Address t = utils::Address::getUndef,
				DetectedFunction* tf = nullptr,
				bool k = false);

	public:
		std::size_t offset = 0;
		std::string name;

		utils::Address address;
		utils::Address target;
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

		void setAddress(retdec::utils::Address a);
		retdec::utils::Address getAddress() const;

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
		retdec::utils::Address address;
};

using DetectedFunctionsPtrMap = typename std::map<
		utils::Address,
		DetectedFunction*>;
using DetectedFunctionsMultimap = typename std::multimap<
		utils::Address,
		DetectedFunction>;
using DetectedFunctionsPtrMultimap = typename std::multimap<
		utils::Address,
		DetectedFunction*>;

/**
 * Finder implementation using Yara.
 */
class Finder
{
	public:
		Finder();
		~Finder();

		/// @name Actions.
		/// @{
		void clear();
		void search(
			const retdec::loader::Image &image,
			const std::string &yaraFile);
		/// @}

		/// @name Getters.
		/// @{
		CoveredCode getCoveredCode();
		const std::vector<DetectedFunction>& getDectedFunctions();
		/// @}

	private:
		CoveredCode coveredCode;                         ///< Code coverage.
		std::vector<DetectedFunction> detectedFunctions; ///< Functions.

		void sort();
		bool isSorted = true; ///< @c true if detected functions are sorted.
};

} // namespace stacofin
} // namespace retdec

#endif
