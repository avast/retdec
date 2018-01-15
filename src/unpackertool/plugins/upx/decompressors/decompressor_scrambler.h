/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_scrambler.h
 * @brief Declaration of UPX scramblers decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */
#ifndef UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_SCRAMBLER_H
#define UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_SCRAMBLER_H

#include "unpackertool/plugins/upx/decompressors/decompressor.h"

namespace retdec {
namespace unpackertool {
namespace upx {

class UpxStub;

/**
 * Visitor-like decompressor for UPX scramblers decompression.
 */
class DecompressorScrambler : public Decompressor
{
public:
	DecompressorScrambler();
	virtual ~DecompressorScrambler();

	virtual void setupPackingMethod(ElfUpxStub<32>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(ElfUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(ElfUpxStub<64>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(ElfUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(MachOUpxStub<32>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(MachOUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(MachOUpxStub<64>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(MachOUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(PeUpxStub<32>* stub, std::uint8_t packingMethod) override;
	virtual void readPackedData(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata) override;
	virtual void decompress(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata) override;

	virtual void setupPackingMethod(PeUpxStub<64>* stub, std::uint8_t packingMethod) override;
	virtual void readPackedData(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata) override;
	virtual void decompress(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata) override;

protected:
	std::shared_ptr<UpxStub> _scrambledStub; ///< The unpacking stub packed by this scrambler.
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
