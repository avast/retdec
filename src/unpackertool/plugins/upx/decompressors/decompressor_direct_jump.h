/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_direct_jump.h
 * @brief Declaration of UPX scrambler with direct jump decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */
#ifndef UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_DIRECT_JUMP_H
#define UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_DIRECT_JUMP_H

#include "unpackertool/plugins/upx/decompressors/decompressor_scrambler.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Visitor-like decompressor for direct jump scrambler decompression.
 */
class DecompressorDirectJump : public DecompressorScrambler
{
public:
	DecompressorDirectJump();
	virtual ~DecompressorDirectJump();

	virtual void readUnpackingStub(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) override;

	virtual void readUnpackingStub(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) override;
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
