/**
 * @file include/retdec/unpacker/decompression/nrv/nrv2d_data.h
 * @brief Declaration of class for NRV2D compressed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DECOMPRESSION_NRV_NRV2D_DATA_H
#define RETDEC_UNPACKER_DECOMPRESSION_NRV_NRV2D_DATA_H

#include <cstdint>
#include <vector>

#include "retdec/unpacker/decompression/nrv/bit_parsers.h"
#include "retdec/unpacker/decompression/nrv/nrv_data.h"

namespace retdec {
namespace unpacker {

class Nrv2dData : public NrvData
{
public:
	Nrv2dData() = delete;
	Nrv2dData(const DynamicBuffer& buffer, BitParser* bitParser);
	Nrv2dData(const Nrv2dData&) = delete;

	virtual ~Nrv2dData() override;

	virtual bool decompress(DynamicBuffer& outputBuffer) override;

private:
	Nrv2dData& operator =(const Nrv2dData&);
};

} // namespace unpacker
} // namespace retdec

#endif
