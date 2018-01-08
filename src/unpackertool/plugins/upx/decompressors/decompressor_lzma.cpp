/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_lzma.cpp
 * @brief Implementation of LZMA decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>

#include "unpackertool/plugins/upx/decompressors/decompressor_lzma.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/macho/macho_upx_stub.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/unpacker/decompression/lzma/lzma_data.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Constructor.
 */
DecompressorLzma::DecompressorLzma()
{
}

/**
 * Destructor.
 */
DecompressorLzma::~DecompressorLzma()
{
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The ELF32 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorLzma::setupPackingMethod(ElfUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	if (packingMethod != UPX_PACKING_METHOD_LZMA)
		throw UnsupportedPackingMethodException(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The ELF32 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorLzma::decompress(ElfUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	if (packedData.getRealDataSize() < 2)
		throw DecompressionFailedException();

	std::uint8_t prop0 = packedData.read<std::uint8_t>(0);
	std::uint8_t prop1 = packedData.read<std::uint8_t>(1);
	std::uint8_t pb = prop0 & 0x07;
	std::uint8_t lc = prop1 & 0x0F;
	std::uint8_t lp = (prop1 & 0xF0) >> 4;
	packedData.erase(0, 2);

	auto lzmaData = std::make_shared<LzmaData>(packedData, pb, lp, lc);
	performDecompression(lzmaData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The ELF64 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorLzma::setupPackingMethod(ElfUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	if (packingMethod != UPX_PACKING_METHOD_LZMA)
		throw UnsupportedPackingMethodException(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The ELF64 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorLzma::decompress(ElfUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	if (packedData.getRealDataSize() < 2)
		throw DecompressionFailedException();

	std::uint8_t prop0 = packedData.read<std::uint8_t>(0);
	std::uint8_t prop1 = packedData.read<std::uint8_t>(1);
	std::uint8_t pb = prop0 & 0x07;
	std::uint8_t lc = prop1 & 0x0F;
	std::uint8_t lp = (prop1 & 0xF0) >> 4;
	packedData.erase(0, 2);

	auto lzmaData = std::make_shared<LzmaData>(packedData, pb, lp, lc);
	performDecompression(lzmaData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The Mach-O 32-bit UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorLzma::setupPackingMethod(MachOUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	if (packingMethod != UPX_PACKING_METHOD_LZMA)
		throw UnsupportedPackingMethodException(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The Mach-O 32-bit UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorLzma::decompress(MachOUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	if (packedData.getRealDataSize() < 2)
		throw DecompressionFailedException();

	std::uint8_t prop0 = packedData.read<std::uint8_t>(0);
	std::uint8_t prop1 = packedData.read<std::uint8_t>(1);
	std::uint8_t pb = prop0 & 0x07;
	std::uint8_t lc = prop1 & 0x0F;
	std::uint8_t lp = (prop1 & 0xF0) >> 4;
	packedData.erase(0, 2);

	auto lzmaData = std::make_shared<LzmaData>(packedData, pb, lp, lc);
	performDecompression(lzmaData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The Mach-O 64-bit UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorLzma::setupPackingMethod(MachOUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	if (packingMethod != UPX_PACKING_METHOD_LZMA)
		throw UnsupportedPackingMethodException(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The Mach-O 64-bit UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorLzma::decompress(MachOUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	if (packedData.getRealDataSize() < 2)
		throw DecompressionFailedException();

	std::uint8_t prop0 = packedData.read<std::uint8_t>(0);
	std::uint8_t prop1 = packedData.read<std::uint8_t>(1);
	std::uint8_t pb = prop0 & 0x07;
	std::uint8_t lc = prop1 & 0x0F;
	std::uint8_t lp = (prop1 & 0xF0) >> 4;
	packedData.erase(0, 2);

	auto lzmaData = std::make_shared<LzmaData>(packedData, pb, lp, lc);
	performDecompression(lzmaData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorLzma::setupPackingMethod(PeUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	if (packingMethod != UPX_PACKING_METHOD_LZMA)
		throw UnsupportedPackingMethodException(packingMethod);
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorLzma::readUnpackingStub(PeUpxStub<32>* stub, DynamicBuffer& unpackingStub)
{
	std::uint32_t epOffset = stub->getRealEpAddress() - stub->getFile()->getEpSegment()->getAddress();

	std::vector<std::uint8_t> unpackingStubBytes;
	stub->getFile()->getEpSegment()->getBytes(unpackingStubBytes, epOffset, stub->getFile()->getEpSegment()->getSize() - epOffset);

	unpackingStub = DynamicBuffer(unpackingStubBytes, stub->getFile()->getFileFormat()->getEndianness());
}

/**
 * Reads the packed data from the input file.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packedData Buffer where to read packed data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorLzma::readPackedData(PeUpxStub<32>* stub, DynamicBuffer& packedData, bool trustMetadata)
{
	std::uint32_t packedDataOffset = 0, packedDataSize = 0;
	if (trustMetadata && stub->getUpxMetadata()->isDefined())
	{
		std::int32_t possibleDataOffset = stub->getUpxMetadata()->getFileOffset() + stub->getUpxMetadata()->getFileSize() -
			stub->getFile()->getEpSegment()->getSecSeg()->getOffset();

		packedDataOffset = std::max(possibleDataOffset, 0);
		packedDataSize = stub->getUpxMetadata()->getPackedDataSize();
	}
	else
	{
		packedDataOffset = stub->getStubCapturedData()->read<std::uint32_t>(0) - stub->getFile()->getEpSegment()->getAddress();
		packedDataSize = stub->getStubCapturedData()->read<std::uint32_t>(8) + 2; // The constant written in signature is always lesser by 2
	}

	if (packedDataSize <= 2)
		throw DecompressionFailedException();

	std::vector<std::uint8_t> packedDataBytes;
	stub->getFile()->getEpSegment()->getBytes(packedDataBytes, packedDataOffset, packedDataSize);

	packedData = DynamicBuffer(packedDataBytes, stub->getFile()->getFileFormat()->getEndianness());
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorLzma::decompress(PeUpxStub<32>* stub, DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	std::uint32_t unpackedDataSize = 0;
	if (trustMetadata && stub->getUpxMetadata()->isDefined())
		unpackedDataSize = stub->getUpxMetadata()->getUnpackedDataSize();
	else
		unpackedDataSize = stub->getStubCapturedData()->read<std::uint32_t>(4);
	unpackedData.setCapacity(unpackedDataSize);

	if (unpackedDataSize == 0 || packedData.getRealDataSize() < 2)
		throw DecompressionFailedException();

	std::uint8_t prop0 = packedData.read<std::uint8_t>(0);
	std::uint8_t prop1 = packedData.read<std::uint8_t>(1);
	std::uint8_t pb = prop0 & 0x07;
	std::uint8_t lc = prop1 & 0x0F;
	std::uint8_t lp = (prop1 & 0xF0) >> 4;
	packedData.erase(0, 2);

	auto lzmaData = std::make_shared<LzmaData>(packedData, pb, lp, lc);
	performDecompression(lzmaData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorLzma::setupPackingMethod(PeUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	if (packingMethod != UPX_PACKING_METHOD_LZMA)
		throw UnsupportedPackingMethodException(packingMethod);
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorLzma::readUnpackingStub(PeUpxStub<64>* stub, DynamicBuffer& unpackingStub)
{
	std::uint32_t epOffset = stub->getRealEpAddress() - stub->getFile()->getEpSegment()->getAddress();

	std::vector<std::uint8_t> unpackingStubBytes;
	stub->getFile()->getEpSegment()->getBytes(unpackingStubBytes, epOffset, stub->getFile()->getEpSegment()->getSize() - epOffset);

	unpackingStub = DynamicBuffer(unpackingStubBytes, stub->getFile()->getFileFormat()->getEndianness());
}

/**
 * Reads the packed data from the input file.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packedData Buffer where to read packed data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorLzma::readPackedData(PeUpxStub<64>* stub, DynamicBuffer& packedData, bool trustMetadata)
{
	std::uint32_t packedDataOffset = 0, packedDataSize = 0;
	if (trustMetadata && stub->getUpxMetadata()->isDefined())
	{
		std::int32_t possibleDataOffset = stub->getUpxMetadata()->getFileOffset() + stub->getUpxMetadata()->getFileSize() -
			stub->getFile()->getEpSegment()->getSecSeg()->getOffset();

		packedDataOffset = std::max(possibleDataOffset, 0);
		packedDataSize = stub->getUpxMetadata()->getPackedDataSize();
	}
	else
	{
		// In case of x64, the offset is RIP-dependant so we need to simulate current RIP position and then subtract written offset
		packedDataOffset = stub->getRealEpAddress() + 11 + stub->getStubCapturedData()->read<std::int32_t>(0) - stub->getFile()->getEpSegment()->getAddress();
		packedDataSize = stub->getStubCapturedData()->read<std::uint32_t>(8) + 2; // The constant written in signature is always lesser by 2
	}

	if (packedDataSize <= 2)
		throw DecompressionFailedException();

	std::vector<std::uint8_t> packedDataBytes;
	stub->getFile()->getEpSegment()->getBytes(packedDataBytes, packedDataOffset, packedDataSize);

	packedData = DynamicBuffer(packedDataBytes, stub->getFile()->getFileFormat()->getEndianness());
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorLzma::decompress(PeUpxStub<64>* stub, DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	std::uint32_t unpackedDataSize = 0;
	if (trustMetadata && stub->getUpxMetadata()->isDefined())
		unpackedDataSize = stub->getUpxMetadata()->getUnpackedDataSize();
	else
		unpackedDataSize = stub->getStubCapturedData()->read<std::uint32_t>(4);
	unpackedData.setCapacity(unpackedDataSize);

	if (unpackedDataSize == 0 || packedData.getRealDataSize() < 2)
		throw DecompressionFailedException();

	std::uint8_t prop0 = packedData.read<std::uint8_t>(0);
	std::uint8_t prop1 = packedData.read<std::uint8_t>(1);
	std::uint8_t pb = prop0 & 0x07;
	std::uint8_t lc = prop1 & 0x0F;
	std::uint8_t lp = (prop1 & 0xF0) >> 4;
	packedData.erase(0, 2);

	auto lzmaData = std::make_shared<LzmaData>(packedData, pb, lp, lc);
	performDecompression(lzmaData, unpackedData);
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
