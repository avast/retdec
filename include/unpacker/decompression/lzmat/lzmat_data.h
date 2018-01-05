/**
 * @file include/unpacker/decompression/lzmat/lzmat_data.h
 * @brief Declaration of class for compressed LZMAT data representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKER_DECOMPRESSION_LZMAT_LZMAT_DATA_H
#define UNPACKER_DECOMPRESSION_LZMAT_LZMAT_DATA_H

#include <cstdint>
#include <vector>

#include "unpacker/decompression/compressed_data.h"

namespace unpacker {

class LzmatData : public CompressedData
{
public:
	LzmatData() = delete;
	LzmatData(const DynamicBuffer& buffer);
	LzmatData(const LzmatData&) = delete;

	virtual ~LzmatData() override;

	virtual bool decompress(DynamicBuffer& outputBuffer) override;

private:
	LzmatData& operator =(const LzmatData&);

	uint8_t get4Bits(uint32_t& pos, bool& unaligned);
	uint8_t get8Bits(uint32_t  pos, bool unaligned);
	uint16_t get12Bits(uint32_t pos, bool unaligned);
	uint16_t get16Bits(uint32_t pos, bool unaligned);
};

} // namespace unpacker

#endif
