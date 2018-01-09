/**
 * @file src/unpackertool/plugins/upx/elf/elf_upx_stub.cpp
 * @brief Implementation of UPX unpacking stub in ELF files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <limits>

#include <elfio/elfio.hpp>

#include "retdec/utils/alignment.h"
#include "retdec/utils/file_io.h"
#include "retdec/loader/loader.h"
#include "unpackertool/plugins/upx/decompressors/decompressors.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/unfilter.h"
#include "unpackertool/plugins/upx/upx.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub_signatures.h"
#include "retdec/unpacker/dynamic_buffer.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

namespace {
	const std::uint32_t PackedBlockHeaderSize = 0xC; ///< Size of packed block header.
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
template <int bits> ElfUpxStub<bits>::ElfUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData,
		const DynamicBuffer& stubCapturedData, std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata)
	: UpxStub(inputFile, stubData, stubCapturedData, std::move(decompressor), metadata)
{
}

/**
 * Destructor.
 *
 * @tparam bits Number of bits of the architecture.
 */
template <int bits> ElfUpxStub<bits>::~ElfUpxStub()
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
template <int bits> void ElfUpxStub<bits>::unpack(const std::string& outputFile)
{
	// Find where is the first packed block
	auto firstBlockOffset = getFirstBlockOffset();

	// Read packed original ELF header and unpack it
	AddressType readPos;
	DynamicBuffer originalHeaderData(_file->getFileFormat()->getEndianness());
	unpackBlock(originalHeaderData, firstBlockOffset, readPos);

	std::fstream output(outputFile, std::ios::out | std::ios::trunc | std::ios::binary);
	retdec::utils::writeFile(output, originalHeaderData.getBuffer());

	// Load these data manually because of endianness independence
	ElfHeaderType originalHeader;
	originalHeader.e_ehsize = originalHeaderData.read<std::uint16_t>(ElfUpxStubTraits<bits>::ElfHeaderEhsizeOffset);
	originalHeader.e_phnum = originalHeaderData.read<std::uint16_t>(ElfUpxStubTraits<bits>::ElfHeaderPhnumOffset);

	AddressType phdrReadOffset = originalHeader.e_ehsize;
	std::vector<ProgHeaderType> originalProgHeaders(originalHeader.e_phnum);
	for (auto& phdr : originalProgHeaders)
	{
		phdr.p_type = originalHeaderData.read<std::uint32_t>(phdrReadOffset);
		phdr.p_offset = originalHeaderData.read<AddressType>(phdrReadOffset + ElfUpxStubTraits<bits>::ProgHeaderOffsetOffset);
		phdr.p_filesz = originalHeaderData.read<AddressType>(phdrReadOffset + ElfUpxStubTraits<bits>::ProgHeaderFileszOffset);
		phdrReadOffset += ElfUpxStubTraits<bits>::ProgHeaderSize;
	}

	// The first LOAD segment has cut off ELF header but has p_offset 0x0, so we need to write the first segment at this initial offset
	// We don't use getRealDataSize() because UPX sometimes uses the sparse files/datas so repeating sequences of 0s at the end of original data
	//  are sometimes not packed
	std::uint32_t initialOffset = originalHeaderData.getCapacity();

	for (std::uint32_t i = 0; i < originalHeader.e_phnum; ++i)
	{
		// It seems that only PT_LOAD segments are packed, other segments are joined to them, but header is kept
		if (originalProgHeaders[i].p_type != PT_LOAD)
			continue;

		AddressType segReadPos;
		DynamicBuffer unpackedData(_file->getFileFormat()->getEndianness());

		upx_plugin->log("Unpacking block at file offset 0x", std::hex, firstBlockOffset + readPos, std::dec, ".");
		unpackBlock(unpackedData, firstBlockOffset + readPos, segReadPos, originalProgHeaders[i].p_filesz);

		retdec::utils::writeFile(output, unpackedData.getBuffer(), initialOffset + originalProgHeaders[i].p_offset);

		initialOffset = 0;
		readPos += segReadPos;
	}

	// We need to do this hack, because UPX doesn't map its whole content to the segments
	// Especially content that is not needed during the runtime, but is important for original file reconstruction
	//  such as section headers, string tables, etc.
	// Thus there is no way we can get this data through fileformat nor elfio
	std::string inputFilePath = _file->getFileFormat()->getPathToFile();

	unsigned long long ep;
	_file->getFileFormat()->getEpAddress(ep);
	ep -= _file->getEpSegment()->getAddress();

	// There are two possible options where these data can be, they can be between the two LOAD segments that are in packed file
	//  or they can be located after the last LOAD segment at the end of the file
	// UPX recognizes this by using UPX metadata which we don't want to rely on, so we do these heuristic analyses
	// If there is enough data between the last packed block and EP to store packed block header, we check whether it is a valid block
	// If it isn't, we assume that these additional data are located at the end
	std::ifstream additionalDataFile(inputFilePath, std::ios::in | std::ios::binary);
	AddressType additionalDataPos = 0, additionalDataSize = 0;
	bool additionalDataBehindStub = false;

	// Check the space between last packed block and EP
	if (ep - readPos + firstBlockOffset > PackedBlockHeaderSize)
	{
		AddressType possibleBlockSize = ep - readPos + firstBlockOffset;

		std::vector<std::uint8_t> possibleBlockBytes;
		retdec::utils::readFile(additionalDataFile, possibleBlockBytes, readPos + firstBlockOffset, possibleBlockSize);

		DynamicBuffer possibleBlock(possibleBlockBytes, _file->getFileFormat()->getEndianness());

		// If there is no valid block in this space, we assume these data are behind the last LOAD segment
		if (!validBlock(possibleBlock))
		{
			additionalDataBehindStub = true;
		}
		else
		{
			// Try to run unpacking algorithm on it, it must be successful
			// This is done because there may be cases when validBlock returns true for invalid block, that seems valid
			// Probability is very small, but there may be
			DynamicBuffer dummyUnpackedData;
			AddressType readFromBlock;

			try
			{
				unpackBlock(dummyUnpackedData, possibleBlock, readFromBlock);
			}
			catch (const UnpackerException&)
			{
				additionalDataBehindStub = true;
			}
		}
	}

	if (additionalDataBehindStub)
	{
		upx_plugin->log("Additional packed data detected at the end of the file.");

		// These data are always at the offset which is aligned by 4
		additionalDataPos = retdec::utils::alignUp(_file->getEpSegment()->getSize(), 4);

		// These data goes up to the end of the file
		additionalDataSize = static_cast<AddressType>(_file->getFileFormat()->getLoadedFileLength() - additionalDataPos);
	}
	else
	{
		upx_plugin->log("Additional packed data detected between LOAD segments.");

		// We just continue reading where we ended up
		additionalDataPos = readPos + firstBlockOffset;

		// These data goes max. up to the EP
		additionalDataSize = ep - additionalDataPos;
	}

	upx_plugin->log("Additional data are at file offset 0x", std::hex, additionalDataPos,
			" and have size of 0x", additionalDataSize, std::dec, ".");

	std::vector<std::uint8_t> additionalDataBytes;
	retdec::utils::readFile(additionalDataFile, additionalDataBytes, additionalDataPos, additionalDataSize);
	additionalDataFile.close();

	DynamicBuffer additionalData(additionalDataBytes, _file->getFileFormat()->getEndianness());

	for (std::uint32_t i = 0; i < originalHeader.e_phnum; ++i)
	{
		// Check if there is gap between segments
		AddressType gap = nextLoadSegmentGap(originalProgHeaders, i);
		if (gap == 0)
			continue;

		// If there is, unpack data into the gap
		DynamicBuffer unpackedData(_file->getFileFormat()->getEndianness());

		upx_plugin->log("Unpacking block from additional data behind segment ", i, ".");
		unpackBlock(unpackedData, additionalData, readPos);
		retdec::utils::writeFile(output, unpackedData.getBuffer(), originalProgHeaders[i].p_offset + originalProgHeaders[i].p_filesz);

		// Erase already unpacked data from additional data buffer
		additionalData.erase(0, readPos);
	}

	// There still might be one last block that should be written at the end of the file, at the last segment
	while (validBlock(additionalData))
	{
		DynamicBuffer unpackedData(_file->getFileFormat()->getEndianness());

		upx_plugin->log("Unpacking last block from additional data at the end of the file.");
		unpackBlock(unpackedData, additionalData, readPos);

		output.seekp(0, std::ios::end);
		retdec::utils::writeFile(output, unpackedData.getBuffer(), output.tellp());

		// Erase already unpacked data from additional data buffer
		additionalData.erase(0, readPos);
	}

	output.close();
}

/**
 * Accepts the visitor-like decompressor and runs checking of packing method.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param packingMethod The packing method to check.
 */
template <int bits> void ElfUpxStub<bits>::setupPackingMethod(std::uint8_t packingMethod)
{
	_decompressor = decodePackingMethod(packingMethod);

	_decompressor->setupPackingMethod(this, packingMethod);
}

/**
 * Accepts the visitor-like decompressor and runs decompression.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param packedData The packed data.
 * @param unpackedData Buffer where to unpack the data.
 */
template <int bits> void ElfUpxStub<bits>::decompress(retdec::unpacker::DynamicBuffer& packedData, retdec::unpacker::DynamicBuffer& unpackedData)
{
	_decompressor->decompress(this, packedData, unpackedData);
}

/**
 * Performs releasing of owned resources.
 *
 * @tparam bits Number of bits of the architecture.
 */
template <int bits> void ElfUpxStub<bits>::cleanup()
{
}

/**
 * Finds the offset of the first block.
 *
 * @return Offset of the first block.
 */
template <int bits> std::uint32_t ElfUpxStub<bits>::getFirstBlockOffset()
{
	auto elfFormat = static_cast<const retdec::fileformat::ElfFormat*>(_file->getFileFormat());

	// UPX data should begin at the end of ELF header
	auto baseOffset = elfFormat->getSegmentTableOffset() + elfFormat->getSegmentTableSize();

	// Iterate over all segments and check whether any segment begins where we suspect the start of UPX data
	for (auto itr = elfFormat->getSegments().begin(), end = elfFormat->getSegments().end(); itr != end; ++itr)
	{
		if (baseOffset == (*itr)->getOffset())
		{
			baseOffset += (*itr)->getSizeInFile();
			// Reset back to the beginning, we need to find whether there are more segments between the first packed block and the end of ELF header
			itr = elfFormat->getSegments().begin();
		}
	}

	return baseOffset + ElfUpxStubTraits<bits>::FirstBlockOffset;
}

/**
 * Checks whether the packed block is valid.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param block The buffer that contains block to be checked.
 *
 * @return True if the block is valid, otherwise false.
 */
template <int bits> bool ElfUpxStub<bits>::validBlock(const DynamicBuffer& block)
{
	// At least 0xC + 1 bytes
	if (block.getRealDataSize() <= PackedBlockHeaderSize)
		return false;

	std::uint32_t unpackedDataSize = block.read<std::uint32_t>(0);
	std::uint32_t packedDataSize = block.read<std::uint32_t>(4);

	// Unpacked data size cannot be less than packed data size
	if (unpackedDataSize < packedDataSize)
		return false;

	// But cannot also be 0
	if (unpackedDataSize == 0 || packedDataSize == 0)
		return false;

	// Size of packed data cannot be larger than size of the whole file
	if (packedDataSize >= _file->getFileFormat()->getFileLength())
		return false;

	// There must be at least 0xC + packedDataSize bytes
	if (packedDataSize > block.getRealDataSize() - PackedBlockHeaderSize)
		return false;

	return true;
}

/**
 * Unpacks the packed block that is in the packed input file.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param unpackedData Buffer where to unpack the block.
 * @param fileOffset Offset in the file, where the packed block is located.
 * @param readFromBlock Number of bytes that equal to the size of the block together with its header.
 * @param sizeHint Potentional size of the unpacked data. The size of unpacked data is determinted by comparing this value with the
 *      data written in packed block header. Higher value is chosen.
 */
template <int bits> void ElfUpxStub<bits>::unpackBlock(DynamicBuffer& unpackedData, AddressType fileOffset, AddressType& readFromBlock, std::uint32_t sizeHint /*= 0*/)
{
	// First extract the packed and unpacked sizes of block from the file
	// They should be in the first 8 bytes of the block
	std::vector<std::uint8_t> blockSizesBytes;
	_file->getEpSegment()->getBytes(blockSizesBytes, fileOffset, 8);

	DynamicBuffer blockSizes(blockSizesBytes, _file->getFileFormat()->getEndianness());

	std::uint32_t unpackedDataSize = blockSizes.read<std::uint32_t>(0);
	std::uint32_t packedDataSize = blockSizes.read<std::uint32_t>(4);

	// Unpacked data can't be smaller or even 0
	if (packedDataSize == 0 || unpackedDataSize == 0 || unpackedDataSize < packedDataSize)
		throw FatalException("Invalid block found.");

	// Read the whole block together with its header
	std::vector<std::uint8_t> packedBlockBytes;
	_file->getEpSegment()->getBytes(packedBlockBytes, fileOffset, PackedBlockHeaderSize + packedDataSize);
	DynamicBuffer packedBlock = DynamicBuffer(packedBlockBytes, _file->getFileFormat()->getEndianness());

	// Unpack the block using the in-memory method overload
	unpackBlock(unpackedData, packedBlock, readFromBlock, sizeHint);
}

/**
 * Unpacks the packed block that is stored in the @ref retdec::unpacker::DynamicBuffer.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param unpackedData Buffer where to unpack the block.
 * @param packedBlock Buffer that contains packed block.
 * @param readFromBlock Number of bytes that equal to the size of the block together with its header.
 * @param sizeHint Potentional size of the unpacked data. The size of unpacked data is determinted by comparing this value with the
 *      data written in packed block header. Higher value is chosen.
 */
template <int bits> void ElfUpxStub<bits>::unpackBlock(DynamicBuffer& unpackedData, DynamicBuffer& packedBlock, AddressType& readFromBlock, std::uint32_t sizeHint /*= 0*/)
{
	std::uint32_t unpackedDataSize = packedBlock.read<std::uint32_t>(0);
	std::uint32_t packedDataSize = packedBlock.read<std::uint32_t>(4);

	// Unpacked data can't be smaller or even 0
	if (!validBlock(packedBlock))
		throw FatalException("Invalid block found.");

	// Read the packed data (without header) from the single block as packedBlock may contain more blocks joined together
	DynamicBuffer packedData = DynamicBuffer(packedBlock, PackedBlockHeaderSize, packedDataSize);

	// sizeHint comes from original ELF program headers, it is a size of segment
	// There are few samples where segment is bigger than size reported in block header
	// We use this hint if program header reportrs bigger size
	unpackedData.setCapacity(std::max(unpackedDataSize, sizeHint));

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
		unpackedData = packedData;

	// Finally, set how many bytes we read from buffer
	readFromBlock = packedDataSize + PackedBlockHeaderSize;
}

/**
 * Finds the gap between two following LOAD segments in the original ELF header. Headers are searched circullary
 * starting from the specified segment.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param phdrs Program headers in the original ELF header.
 * @param currentLoadSegmentIndex Index of starting segment.
 *
 * @return The size of the gap. 0 if no gap is available. Maximal integer value for invalid gap.
 */
template <int bits> typename ElfUpxStub<bits>::AddressType ElfUpxStub<bits>::nextLoadSegmentGap(const std::vector<ProgHeaderType>& phdrs, std::uint32_t currentLoadSegmentIndex)
{
	// Do not search for anything for non-LOAD segments
	if (phdrs[currentLoadSegmentIndex].p_type != PT_LOAD)
		return 0;

	AddressType nearestLoadSegmentDist = std::numeric_limits<AddressType>::max();

	// Calculate size of gap between two consecutive LOAD segments - [currentLoadSegmentIndex] and the following one
	for (std::uint32_t i = currentLoadSegmentIndex + 1; i != currentLoadSegmentIndex; ++i)
	{
		// Segements don't have to be stored in any order, so we need to do circular search over all program headers
		if (i == phdrs.size())
			i = 0;

		// Break if we made a cycle
		if (i == currentLoadSegmentIndex)
			break;

		// Skip non-LOAD segments
		if (phdrs[i].p_type != PT_LOAD)
			continue;

		// If the segment lies behind the current segment
		if (phdrs[currentLoadSegmentIndex].p_offset < phdrs[i].p_offset)
		{
			// Find the minimal distance between 2 segments
			if (nearestLoadSegmentDist >= phdrs[i].p_offset - (phdrs[currentLoadSegmentIndex].p_offset + phdrs[currentLoadSegmentIndex].p_filesz))
			{
				nearestLoadSegmentDist = phdrs[i].p_offset - (phdrs[currentLoadSegmentIndex].p_offset + phdrs[currentLoadSegmentIndex].p_filesz);

				// If the minimal distance is 0, we don't even have to search for next one
				if (nearestLoadSegmentDist == 0)
					return 0;
			}
		}
	}

	return (nearestLoadSegmentDist == std::numeric_limits<AddressType>::max() ? 0 : nearestLoadSegmentDist);
}

/**
 * Unfilters the unpacked block based on the packed block header.
 *
 * @tparam bits Number of bits of the architecture.
 *
 * @param packedBlock The packed block which contains at least its header.
 * @param unpackedData Data containing unpacked block.
 */
template <int bits> void ElfUpxStub<bits>::unfilterBlock(const DynamicBuffer& packedBlock, DynamicBuffer& unpackedData)
{
	std::uint8_t filterId = packedBlock.read<std::uint8_t>(9);
	std::uint8_t filterParam = packedBlock.read<std::uint8_t>(10);
	bool ret = Unfilter::run(unpackedData, filterId, filterParam);

	if (!ret)
		throw UnsupportedFilterException(filterId);

	upx_plugin->log("Unfiltering filter 0x", std::hex, static_cast<std::uint32_t>(filterId), std::dec, " with parameter ", static_cast<std::uint32_t>(filterParam), ".");
}

// Explicit instantiation.
template class ElfUpxStub<32>;
template class ElfUpxStub<64>;

} // namespace upx
} // nemespace unpackertool
} // namespace retdec
