/**
* @file include/retdec/bin2llvmir/optimizations/decoder/decoder_ranges.h
* @brief Representation of ranges to decode.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_RANGES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_DECODER_DECODER_RANGES_H

#include <iostream>

#include "retdec/common/address.h"
#include "retdec/bin2llvmir/providers/fileimage.h"

namespace retdec {
namespace bin2llvmir {

class RangesToDecode
{
	public:
		void addPrimary(common::Address s, common::Address e);
		void addPrimary(const common::AddressRange& r);
		void addAlternative(common::Address s, common::Address e);
		void addAlternative(const common::AddressRange& r);
		void promoteAlternativeToPrimary();

		void remove(common::Address s, common::Address e);
		void remove(const common::AddressRange& r);
		void removeZeroSequences(FileImage* image);

		bool isStrict() const;
		bool primaryEmpty() const;
		bool alternativeEmpty() const;

		const common::AddressRange& primaryFront() const;
		const common::AddressRange& alternativeFront() const;

		const common::AddressRange* getPrimary(common::Address a) const;
		const common::AddressRange* getAlternative(common::Address a) const;
		const common::AddressRange* get(common::Address a) const;

		void setArchitectureInstructionAlignment(unsigned a);

	friend std::ostream& operator<<(std::ostream &os, const RangesToDecode& rs);

	private:
		void removeZeroSequences(
				FileImage* image,
				common::AddressRangeContainer& rs);

	private:
		common::AddressRangeContainer _primaryRanges;
		common::AddressRangeContainer _alternativeRanges;
		unsigned archInsnAlign = 0;
		bool _strict = false;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
