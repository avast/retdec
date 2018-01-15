/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_nrv.h
 * @brief Declaration of NRV decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */
#ifndef UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_NRV_H
#define UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_NRV_H

#include "unpackertool/plugins/upx/decompressors/decompressor.h"
#include "retdec/unpacker/decompression/nrv/bit_parsers.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Visitor-like decompressor for LZMA decompression.
 */
class DecompressorNrv : public Decompressor
{
public:
	explicit DecompressorNrv(std::unique_ptr<retdec::unpacker::BitParser> bitParser = nullptr);
	virtual ~DecompressorNrv();

	virtual void setupPackingMethod(ElfUpxStub<32>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(ElfUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(ElfUpxStub<64>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(ElfUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(MachOUpxStub<32>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(MachOUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(MachOUpxStub<64>* stub, std::uint8_t packingMethod) override;
	virtual void decompress(MachOUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) override;

	virtual void setupPackingMethod(PeUpxStub<32>* stub, std::uint8_t packingMethod) override;
	virtual void readUnpackingStub(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) override;
	virtual void readPackedData(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata) override;
	virtual void decompress(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata) override;

	virtual void setupPackingMethod(PeUpxStub<64>* stub, std::uint8_t packingMethod) override;
	virtual void readUnpackingStub(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) override;
	virtual void readPackedData(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata) override;
	virtual void decompress(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata) override;

protected:
	void setupPackingMethod(std::uint8_t packingMethod);
	void decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData);

private:
	char _nrvVersion;
	std::unique_ptr<retdec::unpacker::BitParser> _bitParser;
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
