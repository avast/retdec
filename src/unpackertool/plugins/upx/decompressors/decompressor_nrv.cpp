/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_nrv.cpp
 * @brief Implementation of NRV decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>

#include "unpackertool/plugins/upx/decompressors/decompressor_nrv.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/macho/macho_upx_stub.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/unpacker/decompression/nrv/nrv2b_data.h"
#include "retdec/unpacker/decompression/nrv/nrv2d_data.h"
#include "retdec/unpacker/decompression/nrv/nrv2e_data.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Constructor.
 */
DecompressorNrv::DecompressorNrv(std::unique_ptr<BitParser> bitParser) : _bitParser(std::move(bitParser))
{
}

/**
 * Destructor.
 */
DecompressorNrv::~DecompressorNrv()
{
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The ELF32 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorNrv::setupPackingMethod(ElfUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	setupPackingMethod(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The ELF32 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorNrv::decompress(ElfUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	decompress(packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The ELF64 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorNrv::setupPackingMethod(ElfUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	setupPackingMethod(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The ELF64 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorNrv::decompress(ElfUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	decompress(packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The Mach-O 32-bit UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorNrv::setupPackingMethod(MachOUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	setupPackingMethod(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The Mach-O 32-bit UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorNrv::decompress(MachOUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	decompress(packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The Mach-O 64-bit UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorNrv::setupPackingMethod(MachOUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	setupPackingMethod(packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The Mach-O 64-bit UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorNrv::decompress(MachOUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	decompress(packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorNrv::setupPackingMethod(PeUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	setupPackingMethod(packingMethod);
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorNrv::readUnpackingStub(PeUpxStub<32>* stub, DynamicBuffer& unpackingStub)
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
void DecompressorNrv::readPackedData(PeUpxStub<32>* stub, DynamicBuffer& packedData, bool trustMetadata)
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
		// In case of NRV the packed data size isn't available in the stub
		// Just take the offset in UPX1 read from the PackedDataAddressPos-th byte from EP up to the offset of EP in UPX1, that is maximal guaranteed size
		std::uint32_t epOffset = stub->getRealEpAddress() - stub->getFile()->getEpSegment()->getAddress();

		packedDataOffset = stub->getStubCapturedData()->read<std::uint32_t>(0) - stub->getFile()->getEpSegment()->getAddress();
		packedDataSize = epOffset - packedDataOffset;
	}

	if (packedDataSize == 0)
		throw DecompressionFailedException();

	std::vector<std::uint8_t> packedDataBytes;
	stub->getFile()->getEpSegment()->getBytes(packedDataBytes, packedDataOffset, packedDataSize);

	packedData = DynamicBuffer(packedDataBytes, stub->getFile()->getFileFormat()->getEndianness());

	// Stub is modified and contains rewrite dword modification
	// We need to take a dword and rewrite it in the packed data
	if (stub->getStubCapturedData()->getRealDataSize() > 4)
	{
		std::uint32_t calcOffset = stub->getFile()->getEpSegment()->getAddress() - stub->getStubCapturedData()->read<std::uint32_t>(4);
		std::uint32_t rewriteOffset = calcOffset + stub->getStubCapturedData()->read<std::uint32_t>(8) - stub->getFile()->getEpSegment()->getAddress();
		std::uint32_t rewriteDword = stub->getStubCapturedData()->read<std::uint32_t>(12);

		packedData.write<std::uint32_t>(rewriteDword, rewriteOffset);
	}
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorNrv::decompress(PeUpxStub<32>* stub, DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	if (_bitParser == nullptr)
		_bitParser = std::make_unique<BitParserLe32>();

	std::uint32_t unpackedDataSize = 0;
	if (trustMetadata && stub->getUpxMetadata()->isDefined())
	{
		unpackedDataSize = stub->getUpxMetadata()->getUnpackedDataSize();
	}
	else
	{
		// In case of NRV the unpacked data size isn't available in the stub
		// Just take the size of UPX0 + the offset of EP in UPX1, that is maximal guaranteed size
		std::uint32_t epOffset = stub->getRealEpAddress() - stub->getFile()->getEpSegment()->getAddress();
		unsigned long long upx0Size = stub->getFile()->getSegment(0)->getSize();

		unpackedDataSize = upx0Size + epOffset;
	}
	unpackedData.setCapacity(unpackedDataSize);

	if (unpackedDataSize == 0)
		throw DecompressionFailedException();

	decompress(packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorNrv::setupPackingMethod(PeUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	setupPackingMethod(packingMethod);
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorNrv::readUnpackingStub(PeUpxStub<64>* stub, DynamicBuffer& unpackingStub)
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
void DecompressorNrv::readPackedData(PeUpxStub<64>* stub, DynamicBuffer& packedData, bool trustMetadata)
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
		// In case of NRV the packed data size isn't available in the stub
		// Just take the offset in UPX1 read from the PackedDataAddressPos-th byte from EP up to the offset of EP in UPX1, that is maximal guaranteed size
		std::uint32_t epOffset = stub->getRealEpAddress() - stub->getFile()->getEpSegment()->getAddress();

		// In case of x64, the offset is RIP-dependant so we need to simulate current RIP position and then subtract written offset
		packedDataOffset = stub->getRealEpAddress() + 11 + stub->getStubCapturedData()->read<std::int32_t>(0) - stub->getFile()->getEpSegment()->getAddress();
		packedDataSize = epOffset - packedDataOffset;
	}

	if (packedDataSize == 0)
		throw DecompressionFailedException();

	std::vector<std::uint8_t> packedDataBytes;
	stub->getFile()->getEpSegment()->getBytes(packedDataBytes, packedDataOffset, packedDataSize);

	packedData = DynamicBuffer(packedDataBytes, stub->getFile()->getFileFormat()->getEndianness());

	// Stub is modified and contains rewrite dword modification
	// We need to take a dword and rewrite it in the packed data
	if (stub->getStubCapturedData()->getRealDataSize() > 4)
	{
		std::uint32_t calcOffset = stub->getFile()->getEpSegment()->getAddress() - stub->getStubCapturedData()->read<std::uint32_t>(4);
		std::uint32_t rewriteOffset = calcOffset + stub->getStubCapturedData()->read<std::uint32_t>(8) - stub->getFile()->getEpSegment()->getAddress();
		std::uint32_t rewriteDword = stub->getStubCapturedData()->read<std::uint32_t>(12);

		packedData.write<std::uint32_t>(rewriteDword, rewriteOffset);
	}
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorNrv::decompress(PeUpxStub<64>* stub, DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	if (_bitParser == nullptr)
		_bitParser = std::make_unique<BitParserLe32>();

	std::uint32_t unpackedDataSize = 0;
	if (trustMetadata && stub->getUpxMetadata()->isDefined())
	{
		unpackedDataSize = stub->getUpxMetadata()->getUnpackedDataSize();
	}
	else
	{
		// In case of NRV the unpacked data size isn't available in the stub
		// Just take the size of UPX0 + the offset of EP in UPX1, that is maximal guaranteed size
		std::uint32_t epOffset = stub->getRealEpAddress() - stub->getFile()->getEpSegment()->getAddress();
		unsigned long long upx0Size = stub->getFile()->getSegment(0)->getSize();

		unpackedDataSize = upx0Size + epOffset;
	}
	unpackedData.setCapacity(unpackedDataSize);

	decompress(packedData, unpackedData);
}

void DecompressorNrv::setupPackingMethod(std::uint8_t packingMethod)
{
	switch (packingMethod)
	{
		case UPX_PACKING_METHOD_NRV2B_8:
			_nrvVersion = 'B';
			_bitParser = std::make_unique<BitParser8>();
			break;
		case UPX_PACKING_METHOD_NRV2D_8:
			_nrvVersion = 'D';
			_bitParser = std::make_unique<BitParser8>();
			break;
		case UPX_PACKING_METHOD_NRV2E_8:
			_nrvVersion = 'E';
			_bitParser = std::make_unique<BitParser8>();
			break;
		case UPX_PACKING_METHOD_NRV2B_LE32:
			_nrvVersion = 'B';
			_bitParser = std::make_unique<BitParserLe32>();
			break;
		case UPX_PACKING_METHOD_NRV2D_LE32:
			_nrvVersion = 'D';
			_bitParser = std::make_unique<BitParserLe32>();
			break;
		case UPX_PACKING_METHOD_NRV2E_LE32:
			_nrvVersion = 'E';
			_bitParser = std::make_unique<BitParserLe32>();
			break;
		default:
			throw UnsupportedPackingMethodException(packingMethod);
	}
}

void DecompressorNrv::decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData)
{
	if (_bitParser == nullptr)
		throw FatalException("Unpacking NRV packed data without bit parser. Report this incident please.");

	std::shared_ptr<NrvData> nrvData = nullptr;
	switch (_nrvVersion)
	{
		case 'B':
			nrvData.reset(new Nrv2bData(packedData, _bitParser.get()));
			break;
		case 'D':
			nrvData.reset(new Nrv2dData(packedData, _bitParser.get()));
			break;
		case 'E':
			nrvData.reset(new Nrv2eData(packedData, _bitParser.get()));
			break;
		default:
			throw UnsupportedStubException();
	}

	performDecompression(nrvData, unpackedData);
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
