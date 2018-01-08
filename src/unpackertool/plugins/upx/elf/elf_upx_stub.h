/**
 * @file src/unpackertool/plugins/upx/elf/elf_upx_stub.h
 * @brief Declaration of UPX unpacking stub in ELF files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_ELF_ELF_UPX_STUB_H
#define UNPACKERTOOL_PLUGINS_UPX_ELF_ELF_UPX_STUB_H

#include <vector>

#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/unpacker/decompression/nrv/bit_parsers.h"
#include "retdec/unpacker/dynamic_buffer.h"

// Foroward declarations
namespace ELFIO {
	struct Elf32_Ehdr;
	struct Elf32_Phdr;
	struct Elf64_Ehdr;
	struct Elf64_Phdr;
}

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Base ELF UPX traits structure.
 */
template <int /*bits*/> struct ElfUpxStubTraits {};

/**
 * Specialized traits for ELF32.
 */
template <> struct ElfUpxStubTraits<32>
{
	using AddressType = std::uint32_t; ///< Type with default word size.
	using ElfHeaderType = ELFIO::Elf32_Ehdr; ///< Type of ELF header.
	using ProgHeaderType = ELFIO::Elf32_Phdr; ///< Type of ELF program headers.

	static const AddressType FirstBlockOffset = 0x18; ///< Offset of the first packed block in the file from the end of ELF header.

	static const AddressType ElfHeaderEhsizeOffset = 40; ///< Offset of @c ehsize field in ELF header.
	static const AddressType ElfHeaderPhnumOffset = 44; ///< Offset of @c phnum field in ELF header.

	static const AddressType ProgHeaderOffsetOffset = 4; ///< Offset of @c offset field in ELF program headers.
	static const AddressType ProgHeaderFileszOffset = 16; ///< Offset of @c filesz field in ELF program headers.
	static const AddressType ProgHeaderSize = 32; ///< Size of ELF program header.
};

/**
 * Specialized traits for ELF64.
 */
template <> struct ElfUpxStubTraits<64>
{
	using AddressType = std::uint64_t; ///< Type with default word size.
	using ElfHeaderType = ELFIO::Elf64_Ehdr; ///< Type of ELF header.
	using ProgHeaderType = ELFIO::Elf64_Phdr; ///< Type of ELF program headers.

	static const AddressType FirstBlockOffset = 0x18; ///< Offset of the first packed block in the file from the end of ELF header.

	static const AddressType ElfHeaderEhsizeOffset = 52; ///< Offset of @c ehsize field in ELF header.
	static const AddressType ElfHeaderPhnumOffset = 56; ///< Offset of @c phnum field in ELF header.

	static const AddressType ProgHeaderOffsetOffset = 8; ///< Offset of @c offset field in ELF program headers.
	static const AddressType ProgHeaderFileszOffset = 32; ///< Offset of @c filesz field in ELF program headers.
	static const AddressType ProgHeaderSize = 56; ///< Size of ELF program header.
};

/**
 * Base class for ELF unpacking stubs. It doesn't implement decompress method from @ref UpxStub as it is left
 * to subclasses which should implement decompression based on the used compression.
 *
 * @tparam bits Number of bits of the architecture.
 */
template <int bits> class ElfUpxStub : public UpxStub
{
public:
	using AddressType = typename ElfUpxStubTraits<bits>::AddressType;
	using ElfHeaderType = typename ElfUpxStubTraits<bits>::ElfHeaderType;
	using ProgHeaderType = typename ElfUpxStubTraits<bits>::ProgHeaderType;

	ElfUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const retdec::unpacker::DynamicBuffer& stubCapturedData,
			std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata);

	virtual ~ElfUpxStub() override;

	virtual void unpack(const std::string& outputFile) override;
	virtual void cleanup() override;

	void setupPackingMethod(std::uint8_t packingMethod);
	void decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData);

private:
	std::uint32_t getFirstBlockOffset();
	bool validBlock(const retdec::unpacker::DynamicBuffer& block);
	void unpackBlock(retdec::unpacker::DynamicBuffer& unpackedData, AddressType fileOffset, AddressType& readFromBuffer, std::uint32_t sizeHint = 0);
	void unpackBlock(retdec::unpacker::DynamicBuffer& unpackedData, retdec::unpacker::DynamicBuffer& packedBlock, AddressType& readFromBuffer, std::uint32_t sizeHint = 0);
	AddressType nextLoadSegmentGap(const std::vector<ProgHeaderType>& phdrs, std::uint32_t currentLoadSegmentIndex);
	void unfilterBlock(const retdec::unpacker::DynamicBuffer& packedBlock, retdec::unpacker::DynamicBuffer& unpackedData);

	retdec::unpacker::BitParser* _bitParser; ///< Associated NRV bit parser.
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
