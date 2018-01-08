/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_scrambler.cpp
 * @brief Implementation of UPX scrambler decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "unpackertool/plugins/upx/decompressors/decompressor_scrambler.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/macho/macho_upx_stub.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/upx_stub.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Constructor.
 */
DecompressorScrambler::DecompressorScrambler() : _scrambledStub(nullptr)
{
}

/**
 * Destructor.
 */
DecompressorScrambler::~DecompressorScrambler()
{
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The ELF32 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorScrambler::setupPackingMethod(ElfUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	_scrambledStub->getDecompressor()->setupPackingMethod(static_cast<ElfUpxStub<32>*>(_scrambledStub.get()), packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The ELF32 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorScrambler::decompress(ElfUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	_scrambledStub->getDecompressor()->decompress(static_cast<ElfUpxStub<32>*>(_scrambledStub.get()), packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The ELF64 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorScrambler::setupPackingMethod(ElfUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	_scrambledStub->getDecompressor()->setupPackingMethod(static_cast<ElfUpxStub<64>*>(_scrambledStub.get()), packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The ELF64 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorScrambler::decompress(ElfUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	_scrambledStub->getDecompressor()->decompress(static_cast<ElfUpxStub<64>*>(_scrambledStub.get()), packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The Mach-O 32-bit UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorScrambler::setupPackingMethod(MachOUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	_scrambledStub->getDecompressor()->setupPackingMethod(static_cast<MachOUpxStub<32>*>(_scrambledStub.get()), packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The Mach-O 32-bit UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorScrambler::decompress(MachOUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	_scrambledStub->getDecompressor()->decompress(static_cast<MachOUpxStub<32>*>(_scrambledStub.get()), packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The Mach-O 64-bit UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorScrambler::setupPackingMethod(MachOUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	_scrambledStub->getDecompressor()->setupPackingMethod(static_cast<MachOUpxStub<64>*>(_scrambledStub.get()), packingMethod);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The Mach-O 64-bit UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 */
void DecompressorScrambler::decompress(MachOUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData)
{
	_scrambledStub->getDecompressor()->decompress(static_cast<MachOUpxStub<64>*>(_scrambledStub.get()), packedData, unpackedData);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorScrambler::setupPackingMethod(PeUpxStub<32>* /*stub*/, std::uint8_t packingMethod)
{
	_scrambledStub->getDecompressor()->setupPackingMethod(static_cast<PeUpxStub<32>*>(_scrambledStub.get()), packingMethod);
}

/**
 * Reads the packed data from the input file.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packedData Buffer where to read packed data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorScrambler::readPackedData(PeUpxStub<32>* /*stub*/, DynamicBuffer& packedData, bool trustMetadata)
{
	_scrambledStub->getDecompressor()->readPackedData(static_cast<PeUpxStub<32>*>(_scrambledStub.get()), packedData, trustMetadata);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorScrambler::decompress(PeUpxStub<32>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	_scrambledStub->getDecompressor()->decompress(static_cast<PeUpxStub<32>*>(_scrambledStub.get()), packedData, unpackedData, trustMetadata);
}

/**
 * Checks whether the provided packing method is valid.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packingMethod The packing method to setup.
 */
void DecompressorScrambler::setupPackingMethod(PeUpxStub<64>* /*stub*/, std::uint8_t packingMethod)
{
	_scrambledStub->getDecompressor()->setupPackingMethod(static_cast<PeUpxStub<64>*>(_scrambledStub.get()), packingMethod);
}

/**
 * Reads the packed data from the input file.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packedData Buffer where to read packed data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorScrambler::readPackedData(PeUpxStub<64>* /*stub*/, DynamicBuffer& packedData, bool trustMetadata)
{
	_scrambledStub->getDecompressor()->readPackedData(static_cast<PeUpxStub<64>*>(_scrambledStub.get()), packedData, trustMetadata);
}

/**
 * Performs decompression of packed data and place it into another buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param packedData The compressed packed data.
 * @param unpackedData The buffer where to decompress data.
 * @param trustMetadata True if UPX metadata are trusted, otherwise false.
 */
void DecompressorScrambler::decompress(PeUpxStub<64>* /*stub*/, DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	_scrambledStub->getDecompressor()->decompress(static_cast<PeUpxStub<64>*>(_scrambledStub.get()), packedData, unpackedData, trustMetadata);
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
