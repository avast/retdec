/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_upxshit.h
 * @brief Declaration of UPX scrambler UPX$HIT decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */
#ifndef UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_UPXSHIT_H
#define UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_UPXSHIT_H

#include "unpackertool/plugins/upx/decompressors/decompressor_scrambler.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Visitor-like decompressor for UPX$HIT scrambler decompression.
 */
class DecompressorUpxshit : public DecompressorScrambler
{
public:
	DecompressorUpxshit();
	virtual ~DecompressorUpxshit();

	virtual void readUnpackingStub(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) override;

	virtual void readUnpackingStub(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) override;
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
