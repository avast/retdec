/**
 * @file src/unpackertool/plugins/upx/macho/macho_upx_stub.cpp
 * @brief Implementation of UPX unpacking stub in Mach-O files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

#include "retdec/utils/alignment.h"
#include "retdec/utils/file_io.h"
#include "retdec/fileformat/fileformat.h"
#include "unpackertool/plugins/upx/decompressors/decompressors.h"
#include "unpackertool/plugins/upx/macho/macho_upx_stub.h"
#include "unpackertool/plugins/upx/unfilter.h"
#include "unpackertool/plugins/upx/upx.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "retdec/unpacker/dynamic_buffer.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

namespace {
	const std::uint32_t PackedBlockHeaderSize = 0xC;     ///< Size of packed block header.

	const std::uint32_t FirstBlockOffset = 0x18;         ///< Offset of the first packed block against the start of UPX metadata.

	const std::uint32_t FatHeaderEntriesOffset = 0x8;    ///< Offset of the FAT header entries.
	const std::uint32_t FatHeaderEntrySize = 0x14;       ///< Size of the single entry about architecture in FAT header.
	const std::uint32_t FatHeaderArchOffsetOffset = 0x8; ///< Offset of architecture offset in the FAT header entry.
	const std::uint32_t FatHeaderArchSizeOffset = 0xC;   ///< Offset of architecture size in the FAT header entry.

	std::string archToName(retdec::fileformat::Architecture arch)
	{
		switch (arch)
		{
			case retdec::fileformat::Architecture::X86:
				return "x86";
			case retdec::fileformat::Architecture::X86_64:
				return "x86-64";
			case retdec::fileformat::Architecture::ARM:
				return "ARM";
			case retdec::fileformat::Architecture::POWERPC:
				return "PowerPC";
			case retdec::fileformat::Architecture::MIPS:
				return "MIPS";
			default:
				return "unknown";
		}
	}
}

/**
 * Constructor.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param inputFile Packed input file.
 * @param stubData @ref UpxStubData associated with this unpacking stub.
 * @param stubCapturedData Data captured from signature matching.
 * @param decompressor Associated decompressor with this unpacking stub.
 * @param metadata The UPX metadata associated with this unpacking stub.
 */
template <int bits> MachOUpxStub<bits>::MachOUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData,
		const DynamicBuffer& stubCapturedData, std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata)
	: UpxStub(inputFile, stubData, stubCapturedData, std::move(decompressor), metadata), _bitParser(nullptr)
{
}

/**
 * Destructor.
 *
 * @tparam bits Number of bits of the architecture.
 */
template <int bits> MachOUpxStub<bits>::~MachOUpxStub()
{
}

/**
 * Performs the whole process of unpacking. This is the method that is being run from @ref UpxPlugin to start
 * unpacking stub.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param outputFile Path to unpacked output file.
 */
template <int bits> void MachOUpxStub<bits>::unpack(const std::string& outputFile)
{
	std::ofstream output(outputFile, std::ios::out | std::ios::trunc | std::ios::binary);
	std::ifstream input(_file->getFileFormat()->getPathToFile(), std::ios::in | std::ios::binary);

	auto fileFormat = _file->getFileFormatWptr().lock();
	auto machoFormat = static_cast<retdec::fileformat::MachOFormat*>(fileFormat.get());
	if (!machoFormat->isFatBinary())
	{
		unpack(input, output, 0, 0);
	}
	else
	{
		upx_plugin->log("Unpacking universal Mach-O.");

		std::vector<std::pair<std::uint32_t, std::uint32_t>> offsetAndSize;
		std::uint32_t offset = 0;
		std::uint32_t archIndex = 0;
		while (machoFormat->chooseArchitectureAtIndex(archIndex))
		{
			// Calculate output offset of the current architecture.
			// First architecture is written to the offset of its packed counterpart.
			// All other architectures are written to the aligned offset based on the size of their predecessors.
			if (archIndex == 0)
				offset = machoFormat->getChosenArchitectureOffset();
			else
				offset = retdec::utils::alignUp(output.tellp(), 0x1000);

			upx_plugin->log("Unpacking architecture ", archToName(machoFormat->getTargetArchitecture()), " from universal Mach-O.");

			// This is not nice, but we have no other option. MachOUpxStub is templated class and therefore @c bits is set to 32 or 64 based on the bit width of the architecture.
			// Universal Mach-O binaries may contain both 32 and 64 bits binaries. If we want to get correct values out of MachOUpxStubTraits we need to create new versions of these
			//   stubs and run unpacking in them.
			auto image = retdec::loader::createImage(fileFormat);
			if (!image)
				throw UnsupportedFileException();

			auto substub = createStub(image.get());
			if (machoFormat->is32Bit())
				static_cast<MachOUpxStub<32>*>(substub.get())->unpack(input, output, machoFormat->getChosenArchitectureOffset(), offset);
			else
				static_cast<MachOUpxStub<64>*>(substub.get())->unpack(input, output, machoFormat->getChosenArchitectureOffset(), offset);

			offsetAndSize.emplace_back(offset, static_cast<std::uint32_t>(output.tellp()) - offset);
			archIndex++;
		}

		// Finally write fat header at the beginning of the file.
		input.seekg(0, std::ios::beg);
		output.seekp(0, std::ios::beg);

		std::vector<std::uint8_t> fatHeaderBytes;
		retdec::utils::readFile(input, fatHeaderBytes, input.tellg(), FatHeaderEntriesOffset + archIndex * FatHeaderEntrySize);
		DynamicBuffer fatHeader(fatHeaderBytes, retdec::utils::Endianness::BIG);

		for (std::uint32_t i = 0; i < archIndex; ++i)
		{
			fatHeader.write<std::uint32_t>(offsetAndSize[i].first, FatHeaderEntriesOffset + FatHeaderArchOffsetOffset + i * FatHeaderEntrySize);
			fatHeader.write<std::uint32_t>(offsetAndSize[i].second, FatHeaderEntriesOffset + FatHeaderArchSizeOffset + i * FatHeaderEntrySize);
		}

		retdec::utils::writeFile(output, fatHeader.getBuffer());
	}

	input.close();
	output.close();
}

/**
 * Performs releasing of owned resources.
 *
 * @tparam bits Number of bits of the architecture.
 */
template <int bits> void MachOUpxStub<bits>::cleanup()
{
}

template <int bits> void MachOUpxStub<bits>::setupPackingMethod(std::uint8_t packingMethod)
{
	_decompressor = decodePackingMethod(packingMethod);

	_decompressor->setupPackingMethod(this, packingMethod);
}

template <int bits> void MachOUpxStub<bits>::decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData)
{
	_decompressor->decompress(this, packedData, unpackedData);
}

template <int bits> void MachOUpxStub<bits>::unpack(std::ifstream& inputFile, std::ofstream& outputFile, std::uint64_t baseInputOffset, std::uint64_t baseOutputOffset)
{
	// Move to the specific offset of the first packed block.
	inputFile.seekg(baseInputOffset + getFirstBlockOffset(inputFile), std::ios::beg);

	upx_plugin->log("Unpacking original Mach-O header.");

	// First read packed original Mach-O header and unpack it.
	DynamicBuffer packedOriginalHeader = readNextBlock(inputFile);
	DynamicBuffer originalHeaderData = unpackBlock(packedOriginalHeader);
	retdec::utils::writeFile(outputFile, originalHeaderData.getBuffer(), baseOutputOffset);

	// Extract number of commands from the original header.
	MachOHeaderType machoHeader;
	machoHeader.ncmds = originalHeaderData.read<std::uint32_t>(MachOUpxStubTraits<bits>::MachOHeaderNcmdsOffset);

	// Find all load segment commands.
	std::uint32_t readPos = MachOUpxStubTraits<bits>::MachOHeaderSize;
	std::vector<MachOSegmentCommandType> commands;
	for (std::uint32_t i = 0; i < machoHeader.ncmds; ++i)
	{
		std::uint32_t cmd = originalHeaderData.read<std::uint32_t>(readPos);
		std::uint32_t cmdsize = originalHeaderData.read<std::uint32_t>(readPos + 4);

		// If not LC_SEGMENT or LC_SEGMENT_64 command.
		if (cmd != MachOUpxStubTraits<bits>::LoadCommandSegment)
			continue;

		// Extract file offset and file size of the load segment commands.
		MachOSegmentCommandType segCommand;
		segCommand.cmd = cmd;
		segCommand.cmdsize = cmdsize;
		segCommand.fileoff = originalHeaderData.read<std::uint32_t>(readPos + MachOUpxStubTraits<bits>::LoadCommandSegmentFileoffOffset);
		segCommand.filesize = originalHeaderData.read<std::uint32_t>(readPos + MachOUpxStubTraits<bits>::LoadCommandSegmentFilesizeOffset);

		commands.push_back(segCommand);
		readPos += segCommand.cmdsize;
	}

	// First segment is always shifted in the file by the size of the original Mach-O header.
	// This is because original Mach-O header is cut off from the first segment during packing.
	std::uint32_t firstSegmentOffset = originalHeaderData.getRealDataSize();
	for (const auto& command : commands)
	{
		// These kind of segments do not have any packed data.
		if (command.filesize == 0)
			continue;

		upx_plugin->log("Unpacking block of load segment command with file offset 0x", std::hex, command.fileoff,
				" and file size 0x", command.filesize, std::dec, ".");

		DynamicBuffer packedBlock = readNextBlock(inputFile);
		DynamicBuffer unpackedData = unpackBlock(packedBlock);

		// Segments are always written at the position of fileoff with first segment shifted by the specific offset.
		retdec::utils::writeFile(outputFile, unpackedData.getBuffer(), baseOutputOffset + command.fileoff + firstSegmentOffset);

		// Shift offset of the first segment will be reset after the first iteration so all other segments will have its original file offset.
		firstSegmentOffset = 0;
	}
}

template <int bits> std::uint32_t MachOUpxStub<bits>::getFirstBlockOffset(std::ifstream& inputFile) const
{
	auto machoFormat = static_cast<retdec::fileformat::MachOFormat*>(_file->getFileFormat());

	// This is possible first block offset. It is located right behind all load commands, but it is not guaranteed.
	std::uint32_t firstBlockOffset = MachOUpxStubTraits<bits>::MachOHeaderSize + machoFormat->getSizeOfCommands();

	// Seek to the possible first block offset and read next 256 bytes.
	std::vector<std::uint8_t> firstBlockBytes;
	retdec::utils::readFile(inputFile, firstBlockBytes, machoFormat->getChosenArchitectureOffset() + firstBlockOffset, 256);

	// Find first non-zero byte.
	auto itr = std::find_if(firstBlockBytes.begin(), firstBlockBytes.end(), [](std::uint8_t b) { return b != 0; });
	if (itr == firstBlockBytes.end())
		throw FirstBlockNotFoundException();

	return firstBlockOffset + (itr - firstBlockBytes.begin()) + FirstBlockOffset;
}

template <int bits> DynamicBuffer MachOUpxStub<bits>::readNextBlock(std::ifstream& inputFile)
{
	const std::size_t blockFilePos = inputFile.tellg();

	// Read the block header.
	std::vector<std::uint8_t> blockHeaderBytes;
	retdec::utils::readFile(inputFile, blockHeaderBytes, blockFilePos, PackedBlockHeaderSize);
	DynamicBuffer blockHeader(blockHeaderBytes, _file->getEndianness());

	// Extract size of packed and unpacked data.
	std::uint32_t unpackedDataSize = blockHeader.read<std::uint32_t>(0);
	std::uint32_t packedDataSize = blockHeader.read<std::uint32_t>(4);

	// Unpacked data can't be smaller or even 0
	if (packedDataSize == 0 || unpackedDataSize == 0 || unpackedDataSize < packedDataSize)
		throw InvalidBlockException();

	// Read the whole block as we know the size already.
	std::vector<std::uint8_t> packedBlockBytes;
	retdec::utils::readFile(inputFile, packedBlockBytes, blockFilePos, PackedBlockHeaderSize + packedDataSize);

	return DynamicBuffer(packedBlockBytes, _file->getEndianness());
}

template <int bits> DynamicBuffer MachOUpxStub<bits>::unpackBlock(DynamicBuffer& packedBlock)
{
	std::uint32_t unpackedDataSize = packedBlock.read<std::uint32_t>(0);
	std::uint32_t packedDataSize = packedBlock.read<std::uint32_t>(4);

	// Read the packed data (without header) from the single block as packedBlock may contain more blocks joined together
	DynamicBuffer packedData(packedBlock, PackedBlockHeaderSize, packedDataSize);

	// Set the required capacity to unpackedData buffer
	DynamicBuffer unpackedData(unpackedDataSize, _file->getEndianness());

	// Decompress the data only if the size of packed data is less than size of unpacked data
	// If they are equal the data are not packed
	if (packedDataSize < unpackedDataSize)
	{
		// Check packing method
		setupPackingMethod(packedBlock.read<std::uint8_t>(8));

		// Decompress data
		decompress(packedData, unpackedData);

		// Unfilter jumps
		unfilterBlock(packedBlock, unpackedData);
	}
	else
		return packedData;

	return unpackedData;
}

/**
 * Unfilters the unpacked block based on the packed block header.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param packedBlock The packed block which contains at least its header.
 * @param unpackedData Data containing unpacked block.
 */
template <int bits> void MachOUpxStub<bits>::unfilterBlock(const DynamicBuffer& packedBlock, DynamicBuffer& unpackedData)
{
	std::uint8_t filterId = packedBlock.read<std::uint8_t>(9);
	std::uint8_t filterParam = packedBlock.read<std::uint8_t>(10);
	bool ret = Unfilter::run(unpackedData, filterId, filterParam);

	if (!ret)
		throw UnsupportedFilterException(filterId);

	upx_plugin->log("Unfiltering filter 0x", std::hex, static_cast<std::uint32_t>(filterId), std::dec, " with parameter ", static_cast<std::uint32_t>(filterParam), ".");
}

// Explicit instantiation.
template class MachOUpxStub<32>;
template class MachOUpxStub<64>;

} // namespace upx
} // namespace unpackertool
} // namespace retdec
