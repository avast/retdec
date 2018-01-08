/**
 * @file include/retdec/unpacker/decompression/lzma/lzma_data.h
 * @brief Declaration of class for compressed LZMA data representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DECOMPRESSION_LZMA_LZMA_DATA_H
#define RETDEC_UNPACKER_DECOMPRESSION_LZMA_LZMA_DATA_H

#include "retdec/unpacker/decompression/compressed_data.h"

namespace retdec {
namespace unpacker {

/**
 * @brief Range decoder for LZMA.
 *
 * Represents the range decoder used in LZMA decompression.
 */
struct RangeDecoder
{
	RangeDecoder() : code(0), range(0), decoder() {}

	void reset()
	{
		code = 0;
		range = 0;
		decoder.clear();
	}

	uint32_t code;
	uint32_t range;
	std::vector<uint16_t> decoder; ///< Decoding buffer
};

/**
 * @brief LZMA compressed data
 *
 * Represents the LZMA compressed data with the option to
 * decompress such data.
 */
class LzmaData : public CompressedData
{
public:
	LzmaData() = delete;
	LzmaData(const DynamicBuffer& buffer, uint8_t pb, uint8_t lp, uint8_t lc);
	LzmaData(const LzmaData& data) = delete;

	virtual ~LzmaData() override;

	virtual bool decompress(DynamicBuffer& outputBuffer) override;

private:
	LzmaData& operator =(const LzmaData&);

	bool checkProperties();
	bool decodeBit(uint32_t pos, uint32_t& bit);
	bool decodeLiteral(uint32_t pos, uint8_t& returnByte, bool useRep, uint32_t rep);
	void rotateRep(uint32_t rep[4], uint32_t amount);
	bool decodeLen(uint32_t pos, uint32_t posState, uint32_t& len);
	bool decodeBitTree(uint32_t pos, uint32_t rep, uint32_t add, uint32_t& ret);
	bool decodeDirectBits(uint32_t count, uint32_t initValue, uint32_t& ret);
	bool decodeRevBitTree(uint32_t pos, uint32_t rep, uint32_t& posSlot);

	uint32_t _readPos; ///< The position of reading from the input buffer.
	uint8_t _pb, _lp, _lc; ///< Parameters of LZMA compression.
	RangeDecoder _rangeDecoder; ///< Range decoder.
};

} // namespace unpacker
} // namespace retdec

#endif
