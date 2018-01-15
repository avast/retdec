/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor.h
 * @brief Declaration of base decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_H
#define UNPACKERTOOL_PLUGINS_UPX_DECOMPRESSORS_DECOMPRESSOR_H

#include <cstdint>
#include <memory>

#include "retdec/unpacker/decompression/compressed_data.h"

namespace retdec {

namespace unpacker {
	class DynamicBuffer;
} // namespace unpacker

namespace unpackertool {
namespace upx {

template <int bits> class ElfUpxStub;
template <int bits> class MachOUpxStub;
template <int bits> class PeUpxStub;

/**
 * Base class for all UPX decompressors. Provides visitor-like interface for all UPX stubs.
 */
class Decompressor
{
public:
	Decompressor();
	virtual ~Decompressor();

	virtual void setupPackingMethod(ElfUpxStub<32>* stub, std::uint8_t packingMethod) = 0;
	virtual void decompress(ElfUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) = 0;

	virtual void setupPackingMethod(ElfUpxStub<64>* stub, std::uint8_t packingMethod) = 0;
	virtual void decompress(ElfUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) = 0;

	virtual void setupPackingMethod(MachOUpxStub<32>* stub, std::uint8_t packingMethod) = 0;
	virtual void decompress(MachOUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) = 0;

	virtual void setupPackingMethod(MachOUpxStub<64>* stub, std::uint8_t packingMethod) = 0;
	virtual void decompress(MachOUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData) = 0;

	virtual void setupPackingMethod(PeUpxStub<32>* stub, std::uint8_t packingMethod) = 0;
	virtual void readUnpackingStub(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) = 0;
	virtual void readPackedData(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata) = 0;
	virtual void decompress(PeUpxStub<32>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata) = 0;

	virtual void setupPackingMethod(PeUpxStub<64>* stub, std::uint8_t packingMethod) = 0;
	virtual void readUnpackingStub(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& unpackingStub) = 0;
	virtual void readPackedData(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, bool trustMetadata) = 0;
	virtual void decompress(PeUpxStub<64>* stub, retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData, bool trustMetadata) = 0;

protected:
	void performDecompression(const std::weak_ptr<retdec::unpacker::CompressedData>& compressedDataWptr, retdec::unpacker::DynamicBuffer& unpackedData);
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
