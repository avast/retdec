/**
 * @file src/unpackertool/plugins/upx/macho/macho_upx_stub.h
 * @brief Declaration of UPX unpacking stub in Mach-O files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_MACHO_MACHO_UPX_STUB_H
#define UNPACKERTOOL_PLUGINS_UPX_MACHO_MACHO_UPX_STUB_H

#include <cstdint>

#include "unpackertool/plugins/upx/upx_stub.h"
#include "retdec/unpacker/decompression/nrv/bit_parsers.h"
#include "retdec/unpacker/dynamic_buffer.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Base Mach-O UPX traits structure.
 */
template <int /*bits*/> struct MachOUpxStubTraits {};

/**
 * Specialized traits for Mach-O 32-bit.
 */
template <> struct MachOUpxStubTraits<32>
{
	using AddressType = std::uint32_t; ///< Type with default word size.
	using MachOHeaderType = llvm::MachO::mach_header;
	using MachOSegmentCommandType = llvm::MachO::segment_command;

	static const std::uint64_t MachOHeaderNcmdsOffset = 0x10;
	static const std::uint64_t MachOHeaderSize = 0x1C;
	static const std::uint32_t LoadCommandSegment = llvm::MachO::LC_SEGMENT;
	static const std::uint64_t LoadCommandSegmentFileoffOffset = 0x20;
	static const std::uint64_t LoadCommandSegmentFilesizeOffset = 0x24;
};

/**
 * Specialized traits for Mach-O 64-bit.
 */
template <> struct MachOUpxStubTraits<64>
{
	using AddressType = std::uint64_t; ///< Type with default word size.
	using MachOHeaderType = llvm::MachO::mach_header_64;
	using MachOSegmentCommandType = llvm::MachO::segment_command_64;

	static const std::uint64_t MachOHeaderNcmdsOffset = 0x10;
	static const std::uint64_t MachOHeaderSize = 0x20;
	static const std::uint32_t LoadCommandSegment = llvm::MachO::LC_SEGMENT_64;
	static const std::uint64_t LoadCommandSegmentFileoffOffset = 0x28;
	static const std::uint64_t LoadCommandSegmentFilesizeOffset = 0x30;
};

/**
 * Base class for Mach-O unpacking stubs. It doesn't implement decompress method from @ref UpxStub as it is left
 * to subclasses which should implement decompression based on the used compression.
 *
 * @tparam bits Number of bits of the architecture.
 */
template <int bits> class MachOUpxStub : public UpxStub
{
public:
	using AddressType = typename MachOUpxStubTraits<bits>::AddressType;
	using MachOHeaderType = typename MachOUpxStubTraits<bits>::MachOHeaderType;
	using MachOSegmentCommandType = typename MachOUpxStubTraits<bits>::MachOSegmentCommandType;

	MachOUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const retdec::unpacker::DynamicBuffer& stubCapturedData,
			std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata);

	virtual ~MachOUpxStub() override;

	virtual void unpack(const std::string& outputFile) override;
	virtual void cleanup() override;

	void setupPackingMethod(std::uint8_t packingMethod);
	void decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData);

	void unpack(std::ifstream& inputFile, std::ofstream& outputFile, std::uint64_t baseInputOffset, std::uint64_t baseOutputOffset);

protected:
	std::uint32_t getFirstBlockOffset(std::ifstream& inputFile) const;
	retdec::unpacker::DynamicBuffer readNextBlock(std::ifstream& inputFile);
	retdec::unpacker::DynamicBuffer unpackBlock(retdec::unpacker::DynamicBuffer& packedBlock);
	void unfilterBlock(const retdec::unpacker::DynamicBuffer& packedBlock, retdec::unpacker::DynamicBuffer& unpackedData);

private:
	std::uint64_t _readPos;
	std::unique_ptr<retdec::unpacker::BitParser> _bitParser;
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
