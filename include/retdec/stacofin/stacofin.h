/**
 * @file include/retdec/stacofin/stacofin.h
 * @brief Static code finder library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_STACOFIN_STACOFIN_H
#define RETDEC_STACOFIN_STACOFIN_H

#include <string>
#include <utility>
#include <vector>

#include "retdec/utils/address.h"

namespace retdec {
namespace loader {
	class Image;
} // namespace loader

namespace stacofin {

/**
 * Data-type for offset-name relocation pairs.
 */
using References = std::vector<std::pair<std::size_t, std::string>>;
using CoveredCode = retdec::utils::AddressRangeContainer;

/**
 * Structure representing one detected function.
 */
struct DetectedFunction
{
	public:
		std::size_t size;                ///< Original size of source.
		std::size_t offset;              ///< File offset.
		retdec::utils::Address address; ///< Virtual address.

		std::vector<std::string> names; ///< Possible original names.
		References references;          ///< Offset-name relocation pairs.

		std::string signaturePath; ///< Source signature path.

		/// @name Setters.
		/// @{
		void setReferences(const std::string &refsString);
		/// @}
};

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
		std::vector<DetectedFunction> getDectedFunctions();
		const std::vector<DetectedFunction>& accessDectedFunctions();
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
