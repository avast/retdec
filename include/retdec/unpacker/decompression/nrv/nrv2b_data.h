/**
 * @file include/retdec/unpacker/decompression/nrv/nrv2b_data.h
 * @brief Declaration of class for NRV2B compressed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DECOMPRESSION_NRV_NRV2B_DATA_H
#define RETDEC_UNPACKER_DECOMPRESSION_NRV_NRV2B_DATA_H

#include <cstdint>
#include <vector>

#include "retdec/unpacker/decompression/nrv/bit_parsers.h"
#include "retdec/unpacker/decompression/nrv/nrv_data.h"

namespace retdec {
namespace unpacker {

class Nrv2bData : public NrvData
{
public:
	Nrv2bData() = delete;
	Nrv2bData(const DynamicBuffer& buffer, BitParser* bitParser);
	Nrv2bData(const Nrv2bData&) = delete;

	virtual ~Nrv2bData() override;

	virtual bool decompress(DynamicBuffer& outputBuffer) override;

private:
	Nrv2bData& operator =(const Nrv2bData&);
};

} // namespace unpacker
} // namespace retdec

#endif
