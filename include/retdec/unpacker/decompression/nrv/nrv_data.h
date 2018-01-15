/**
 * @file include/retdec/unpacker/decompression/nrv/nrv_data.h
 * @brief Declaration of abstract class for NRV compressed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DECOMPRESSION_NRV_NRV_DATA_H
#define RETDEC_UNPACKER_DECOMPRESSION_NRV_NRV_DATA_H

#include "retdec/unpacker/decompression/compressed_data.h"
#include "retdec/unpacker/decompression/nrv/bit_parsers.h"

namespace retdec {
namespace unpacker {

class NrvData : public CompressedData
{
public:
	NrvData() = delete;
	NrvData(const DynamicBuffer& buffer, BitParser* bitParser) : CompressedData(buffer), _readPos(0), _writePos(0), _bitParser(bitParser) {}
	NrvData(const NrvData&) = delete;

	virtual ~NrvData() override {}

	void reset()
	{
		_readPos = 0;
		_writePos = 0;
	}

protected:
	uint32_t _readPos, _writePos;
	BitParser* _bitParser;

private:
	NrvData& operator =(const NrvData&);
};

} // namespace unpacker
} // namespace retdec

#endif
