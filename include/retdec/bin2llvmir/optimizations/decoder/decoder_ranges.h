/**
* @file include/retdec/bin2llvmir/optimizations/decoder/decoder_ranges.h
* @brief Representation of ranges to decode.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_RANGES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_RANGES_H

#include <iostream>

#include "retdec/utils/address.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class RangesToDecode
{
	public:
		void addPrimary(utils::Address s, utils::Address e);
		void addPrimary(const utils::AddressRange& r);
		void addAlternative(utils::Address s, utils::Address e);
		void addAlternative(const utils::AddressRange& r);
		void promoteAlternativeToPrimary();

		void remove(utils::Address s, utils::Address e);
		void remove(const utils::AddressRange& r);
		void removeZeroSequences(FileImage* image);

		bool isStrict() const;
		bool primaryEmpty() const;
		bool alternativeEmpty() const;

		const utils::AddressRange& primaryFront() const;
		const utils::AddressRange& alternativeFront() const;

		const utils::AddressRange* getPrimary(utils::Address a) const;
		const utils::AddressRange* getAlternative(utils::Address a) const;
		const utils::AddressRange* get(utils::Address a) const;

		void setArchitectureInstructionAlignment(unsigned a);

	friend std::ostream& operator<<(std::ostream &os, const RangesToDecode& rs);

	private:
		void removeZeroSequences(
				FileImage* image,
				utils::AddressRangeContainer& rs);

	private:
		utils::AddressRangeContainer _primaryRanges;
		utils::AddressRangeContainer _alternativeRanges;
		unsigned archInsnAlign = 0;
		bool _strict = false;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
