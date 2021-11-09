/**
 * @file src/unpackertool/plugins/mpress/mpress.cpp
 * @brief Unpacker plugin for MPRESS packer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cstdint>
#include <memory>

#include "retdec/loader/loader.h"
#include "retdec/unpacker/plugin.h"
#include "retdec/unpacker/decompression/lzma/lzma_data.h"
#include "retdec/unpacker/decompression/lzmat/lzmat_data.h"
#include "retdec/unpacker/unpacker_exception.h"

#include "unpackertool/plugins/mpress/mpress.h"
#include "unpackertool/plugins/mpress/mpress_exceptions.h"

#include "retdec/fileformat/fileformat.h"
#include "retdec/pelib/PeFile.h"

using namespace retdec::utils;
using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace mpress {

namespace {

const MpressUnpackerStubData mpressUnpackerStubData[MPRESS_UNPACKER_STUB_UNKNOWN] =
{
	{ 0x2B6, 0x2BC, 0x2B8, 0x2C8, 0x2C0, COMPRESSION_LZMAT }, // MPRESS_UNPACKER_STUB_101_105
	{ 0x29E, 0x2A4, 0x2A0, 0x2B0, 0x2A8, COMPRESSION_LZMAT }, // MPRESS_UNPACKER_STUB_107_127
	{ 0x299, 0x29F, 0x29B, 0x2AB, 0x2A3, COMPRESSION_LZMAT }, // MPRESS_UNPACKER_STUB_201
	{ 0xB57, 0xB5D, 0xB59, 0xB61, 0xB69, COMPRESSION_LZMA  }, // MPRESS_UNPACKER_STUB_205_LZMA
	{ 0x29C, 0x2A2, 0x29E, 0x2A6, 0x2AE, COMPRESSION_LZMAT }, // MPRESS_UNPACKER_STUB_205_LZMAT
	{ 0xB5A, 0xB60, 0xB5C, 0xB64, 0xB6C, COMPRESSION_LZMA  }, // MPRESS_UNPACKER_STUB_212_219_LZMA
	{ 0x29F, 0x2A5, 0x2A1, 0x2A9, 0x2B1, COMPRESSION_LZMAT }  // MPRESS_UNPACKER_STUB_212_219_LZMAT
};

const MpressFixStubData mpressFixStubData[MPRESS_FIX_STUB_UNKNOWN] =
{
	{ 0x8B,  0xC1,  0xBD }, // MPRESS_FIX_STUB_10x
	{ 0x45, 0x138, 0x134 }, // MPRESS_FIX_STUB_127_20x
	{ 0x35, 0x128, 0x124 }  // MPRESS_FIX_STUB_21x
};

}

/**
 * Constructor.
 */
MpressPlugin::MpressPlugin() : _file(), _peFile(nullptr), _unpackerStub(MPRESS_UNPACKER_STUB_UNKNOWN),
	_fixStub(MPRESS_FIX_STUB_UNKNOWN), _packedContentSect(nullptr), _addedSectionCount(0),
	_iatVa(0), _iatSize(0), _oepVa(0), _importHintsOffset(0)
{
	info.name          = "MPRESS";
	info.pluginVersion = "0.99";
	info.packerVersion = R"/([12]\..{2})/"; // 1.xx or 2.xx
	info.author        = "Marek Milkovic";
}

/**
 * Destructor.
 */
MpressPlugin::~MpressPlugin()
{
	cleanup();
}

/**
 * Performs preparation of unpacking.
 */
void MpressPlugin::prepare()
{
	_file = retdec::loader::createImage(getStartupArguments()->inputFile);
	if (!_file)
		throw UnsupportedFileException();

	_peFile = new PeLib::PeFileT(getStartupArguments()->inputFile);
	if(_peFile->loadPeHeaders() != PeLib::ERROR_NONE)
		throw UnsupportedFileException();

	// We currently don't support PE32+ as the decompiler doesn't support them anyways
	if (_peFile->imageLoader().getImageBitability() != 32)
		throw UnsupportedFileException();

	if (!_file->getEpSegment())
		throw NoEntryPointException();

	// Detect the version of the used MPRESS packer and the compression used
	if (detectUnpackerStubVersion() == MPRESS_UNPACKER_STUB_UNKNOWN)
		throw UnsupportedStubException();
}

/**
 * Starts unpacking in the current plugin.
 */
void MpressPlugin::unpack()
{
	// Find the section which contains the packed content
	std::uint64_t ep;
	std::vector<std::uint8_t> packedContentSectAddrBytes;

	_file->getFileFormat()->getEpAddress(ep);
	_file->getEpSegment()->getBytes(packedContentSectAddrBytes, ep - _file->getEpSegment()->getAddress() + mpressUnpackerStubData[_unpackerStub].packedContentOffset, 4);

	DynamicBuffer packedContentSectAddrBuffer(packedContentSectAddrBytes, _file->getFileFormat()->getEndianness());
	std::uint32_t packedContentSectAddr = ep + mpressUnpackerStubData[_unpackerStub].packedContentOffset + packedContentSectAddrBuffer.read<std::int32_t>(0);

	_packedContentSect = _file->getSegmentFromAddress(packedContentSectAddr);
	if (_packedContentSect == nullptr)
		throw PackedDataSectionNotFoundException();

	std::vector<std::uint8_t> packedContent;
	_packedContentSect->getBytes(packedContent);

	DynamicBuffer packedContentBuffer(packedContent, _file->getFileFormat()->getEndianness());

	// First 6 bytes contains metadata about the packed content
	// 2 bytes == size of the section with packed content shifted right by 0xC
	// 4 bytes == actual size of the packed content
	std::uint32_t unpackedSize = packedContentBuffer.read<std::uint16_t>(0) << 0xC;
	std::uint32_t packedSize = packedContentBuffer.read<std::uint32_t>(2);

	// Remove the header of the packed data from the buffer
	packedContentBuffer.erase(0, 6);

	if (packedSize > packedContentBuffer.getRealDataSize())
		throw CorruptedUnpackingStubException();

	// Remove tail of the packed data
	packedContentBuffer.erase(packedSize, packedContentBuffer.getRealDataSize() - packedSize);

	// Decode the content of .MPRESS1 section which is compressed with LZMAT algorithm
	DynamicBuffer unpackedContent(unpackedSize, _file->getFileFormat()->getEndianness());
	if (!decompressData(packedContentBuffer, unpackedContent))
		throw DecompressionFailedException();

	// Fix JMP and CALL instructions with correction of their offsets
	fixJumpsAndCalls(unpackedContent);

	// Detect the version of fix stub here
	if (detectFixStubVersion(unpackedContent) == MPRESS_FIX_STUB_UNKNOWN)
		throw UnsupportedStubException();

	// Fix imports & EP
	fixImportsAndEp(unpackedContent);

	// Fix relocations
	fixRelocations();

	// Split the unpacked section as much as possible into individual sections based on the known offsets
	offsetAnalysis(unpackedContent);

	// Perform section trailing bytes analysis
	trailingBytesAnalysis(unpackedContent);

	// Save the new file
	saveFile(getStartupArguments()->outputFile, unpackedContent);
}

/**
 * Performs freeing of all owned resources.
 */
void MpressPlugin::cleanup()
{
	delete _peFile;
	_peFile = nullptr;
}

bool MpressPlugin::decompressData(DynamicBuffer& compressedContent, DynamicBuffer& decompressedContent)
{
	if (mpressUnpackerStubData[_unpackerStub].compression == COMPRESSION_LZMAT)
	{
		LzmatData lzmatData(compressedContent);
		if (!lzmatData.decompress(decompressedContent))
		{
			error("Unable to decompress LZMAT compressed content");
			return false;
		}
	}
	else if (mpressUnpackerStubData[_unpackerStub].compression == COMPRESSION_LZMA)
	{
		// Decode the LZMA properties and remove them from the compressedContent
		std::uint8_t pb, lp, lc;
		decodeLzmaProperties(compressedContent, pb, lp, lc);

		LzmaData lzmaData(compressedContent, pb, lp, lc);
		if (!lzmaData.decompress(decompressedContent))
		{
			error("Unable to decompress LZMA compressed content");
			return false;
		}
	}
	else
	{
		error("Unable to decompressed content");
		return false;
	}

	return true;
}

void MpressPlugin::decodeLzmaProperties(DynamicBuffer& compressedContent, std::uint8_t& pb, std::uint8_t& lp, std::uint8_t& lc)
{
	lp = compressedContent.read<std::uint8_t>(0) & 0x0F;
	pb = (compressedContent.read<std::uint8_t>(0) & 0xF0) >> 4;
	lc = compressedContent.read<std::uint8_t>(1);

	compressedContent.erase(0, 2);
}

std::uint32_t MpressPlugin::getFixStub()
{
	std::uint64_t ep, epOffset;
	std::vector<std::uint8_t> fixStubOffsetBytes;

	// Fix imports stub is calculated from the EP section where there is offset into it written at specific offset
	_file->getFileFormat()->getEpAddress(ep);
	epOffset = ep - _file->getEpSegment()->getAddress();
	_file->getEpSegment()->getBytes(fixStubOffsetBytes, epOffset + mpressUnpackerStubData[_unpackerStub].fixStubOffset, 4);

	DynamicBuffer fixStubOffsetBuffer(fixStubOffsetBytes, _file->getFileFormat()->getEndianness());

	// If we subtract the address of .MPRESS1 section, we have the offset in section
	std::uint32_t fixImportsStubAddr = ep + mpressUnpackerStubData[_unpackerStub].fixStubOffset + 4 + fixStubOffsetBuffer.read<std::int32_t>(0);
	fixImportsStubAddr -= _packedContentSect->getAddress();
	return fixImportsStubAddr;
}

void MpressPlugin::fixJumpsAndCalls(DynamicBuffer& buffer)
{
	std::uint32_t pos = 0;
	std::uint32_t maxAddr = std::max(0, static_cast<std::int32_t>(buffer.getRealDataSize()) - 0x1000);
	while (pos < maxAddr)
	{
		std::uint32_t moveOffset = pos;
		std::uint8_t opcode = buffer.read<std::uint8_t>(pos++);
		if ((opcode & 0xFE) != 0xE8) // JMP == E9, CALL == E8
			continue;

		std::int32_t offset = buffer.read<std::int32_t>(pos);
		moveOffset++;
		pos += 4;

		if (offset >= 0)
		{
			if (offset >= static_cast<std::int64_t>(maxAddr))
				continue;
		}
		else
		{
			offset += moveOffset;
			if (offset < 0)
				continue;

			offset += maxAddr;
		}

		buffer.write<std::int32_t>(offset - moveOffset, pos - 4);
	}
}

void MpressPlugin::fixImportsAndEp(DynamicBuffer& buffer)
{
	PeLib::ImageLoader & imageLoader = _peFile->imageLoader();
	std::uint32_t pointerSize = imageLoader.getPointerSize();

	// At the offset from EP is written EIP relative offset of fix import stub
	// Fix import stub is then located at the <EP Address> + offset + <loaded offset>
	// This stub was packed together with code and data in .MPRESS1 section and also contains hints for import table rebuild
	std::uint32_t fixStubAddr = getFixStub();

	// Offet to the hints is located at the <Fix Import Stub Address> + offset
	// Import hints are located at the <Fix Import Stub Address> + offset + <Import Hints Offset>
	std::uint32_t importHints = fixStubAddr + mpressFixStubData[_fixStub].importHintsOffset + buffer.read<std::uint32_t>(fixStubAddr + mpressFixStubData[_fixStub].importHintsOffset);

	// Go through MPRESS import hints and fill the import directory
	std::int32_t destOffset = imageLoader.getSectionHeader(_packedContentSect->getSecSeg()->getIndex())->VirtualAddress + importHints;
	std::int32_t lowestDestOffset = std::numeric_limits<std::int32_t>::max();
	std::int32_t highestDestOffset = 0;
	std::int32_t destOffsetDiff;
	std::uint32_t readPos = importHints;
	while ((destOffsetDiff = buffer.read<std::int32_t>(readPos)) != -1)
	{
		destOffset += destOffsetDiff;
		buffer.writeRepeatingByte(0, readPos, 4);
		readPos += 4;

		std::string moduleName = buffer.readString(readPos);
		buffer.writeRepeatingByte(0, readPos, static_cast<uint32_t>(moduleName.length()));
		readPos += static_cast<uint32_t>(moduleName.length() + 1);

		destOffsetDiff = 0;
		while (buffer.read<std::uint8_t>(readPos) != 0)
		{
			// Import by ordinal
			if (buffer.read<std::uint8_t>(readPos) <= 0x20)
			{
				std::uint16_t ordinal = buffer.read<std::uint16_t>(readPos + 1);
				_peFile->impDir().addFunction(moduleName, ordinal);
				buffer.writeRepeatingByte(0, readPos, 3);
				readPos += 3;
			}
			// Import by name
			else
			{
				std::string symbolName = buffer.readString(readPos);
				_peFile->impDir().addFunction(moduleName, symbolName);
				buffer.writeRepeatingByte(0, readPos, static_cast<uint32_t>(symbolName.length() + 1));
				readPos += static_cast<uint32_t>(symbolName.length() + 1);
			}

			destOffsetDiff += 4;
		}
		readPos++; // skip null terminator

		// Set FirstThunk to point into IAT
		int fileIndex = _peFile->impDir().getFileIndex(moduleName, true);
		if (fileIndex == -1)
			throw InvalidImportHintsException();

		_peFile->impDir().setFirstThunk(fileIndex, true, destOffset);
		lowestDestOffset = std::min(destOffset, lowestDestOffset);
		highestDestOffset = std::max(destOffset, highestDestOffset);
		destOffset += destOffsetDiff;
	}

	buffer.writeRepeatingByte(0, readPos, 4); // clear out last -1 from the hint list

	// Fix the import directory and import address directory addresses
	// Since ILT is lost we need to make them from scratch in the whole new section
	// Ensure the .imports section will be large enough, resize if there are more data
	std::uint32_t fileAlignment = imageLoader.getFileAlignment();
	std::uint32_t importFileSize = _peFile->impDir().calculateSize(pointerSize);
	std::uint32_t importSectSize = importFileSize & ~(fileAlignment - 1);
	std::uint32_t newSectionIndex;

	if (importFileSize & (fileAlignment - 1))
		importSectSize += fileAlignment;
	PeLib::PELIB_IMAGE_SECTION_HEADER * pNewSection = imageLoader.addSection(".imports", importSectSize);

	pNewSection->Characteristics = PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
	imageLoader.setDataDirectory(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT, pNewSection->VirtualAddress, importSectSize);

	// IAT needs to be put at the desired offset
	std::uint32_t iatOffset = lowestDestOffset;
	imageLoader.setDataDirectory(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_IAT, iatOffset, highestDestOffset + 4 - lowestDestOffset);
	imageLoader.makeValid();

	// Offset to OEP is stored at the offset from the <Fix Import Stub Address>
	// This offset is addressed from the <Fix Import Stub Address> + offset
	std::uint32_t oepOffset = imageLoader.getSectionHeader(_packedContentSect->getSecSeg()->getIndex())->VirtualAddress + fixStubAddr +
			mpressFixStubData[_fixStub].importHintsOffset + buffer.read<std::uint32_t>(fixStubAddr + mpressFixStubData[_fixStub].oepOffset);
	imageLoader.setAddressOfEntryPoint(oepOffset);

	// Finally, get rid of the fix imports stub as it is going to mess up frontend analysis in the unpacked section
	// At the end we add 16 because of 4 bytes directly belonging to the importHintsOffset and additional 12 bytes used
	// to store library calls GetProcAddress and LoadLibrary
	buffer.writeRepeatingByte(0, fixStubAddr, mpressFixStubData[_fixStub].importHintsOffset + 16);

	// Set to the global plugin attributes, so it can be used later
	_iatVa = iatOffset;
	_iatSize = highestDestOffset + 4 - lowestDestOffset;
	_oepVa = oepOffset;
	_importHintsOffset = importHints;
}

void MpressPlugin::offsetAnalysis(const DynamicBuffer& buffer)
{
	PeLib::PELIB_IMAGE_SECTION_HEADER * packedContectSection;
	PeLib::PELIB_IMAGE_SECTION_HEADER * entryPointSection;
	PeLib::ImageLoader & imageLoader = _peFile->imageLoader();
	std::size_t packedContentSectionIndex = _packedContentSect->getSecSeg()->getIndex();
	std::uint32_t sectionAlignment = imageLoader.getSectionAlignment();
	std::uint32_t fixStubOffset = getFixStub();
	std::uint32_t dataFlags = PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
	std::uint32_t codeFlags = dataFlags | PeLib::PELIB_IMAGE_SCN_CNT_CODE | PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE;

	// Get pointer to entry point section and also section with packed content
	packedContectSection = imageLoader.getSectionHeader(packedContentSectionIndex);
	entryPointSection = imageLoader.getSectionHeader(_file->getEpSegment()->getSecSeg()->getIndex());

	// Remove the .MPRESS2 section as the getEpSection()->getIndex() will be shifted by newly created
	// sections and we can do it safely here
	//_peFile->peHeader().removeSection(_file->getEpSection()->getIndex());
	// @todo There is some problem with removing a section and valid PE file in some cases
	entryPointSection->Characteristics = dataFlags;

	// Resize packed content section so we can put unpacked content into it
	size_t diff = buffer.getRealDataSize() - packedContectSection->SizeOfRawData;
	packedContectSection->SizeOfRawData =  buffer.getRealDataSize();

	for (size_t i = _packedContentSect->getSecSeg()->getIndex() + 1; i < imageLoader.getNumberOfSections(); ++i)
	{
		PeLib::PELIB_IMAGE_SECTION_HEADER * tempSection = imageLoader.getSectionHeader(i);

		tempSection->PointerToRawData = tempSection->PointerToRawData + diff;
	}

	// Here we will split the big unpacked section into the more data sections and try to locate the code section as much as possible
	// We will use import hints, IAT, fix stub address and OEP to locate the original sections
	// We know that hints and fix stub are located at the end of original sections
	// We also know that IAT is its own section
	std::uint32_t oepOffset = _oepVa - packedContectSection->VirtualAddress;
	std::uint32_t iatOffset = (_iatVa & ~(sectionAlignment - 1)) - packedContectSection->VirtualAddress;

	// We will need this as all other heuristics are based on the shrinking of .text section
	std::uint32_t moveOffset = 0;

	// Hints are located before the OEP, we suspect that there is data section before the code
	if (_importHintsOffset < oepOffset)
	{
		// Split the section into .data0|.text
		if (imageLoader.splitSection(packedContentSectionIndex, ".data0", ".text",
				(_importHintsOffset & ~(sectionAlignment - 1)) + sectionAlignment) == 0)
		{
			imageLoader.getSectionHeader(packedContentSectionIndex)->Characteristics = dataFlags;
			imageLoader.getSectionHeader(packedContentSectionIndex+1)->Characteristics = codeFlags;
			_addedSectionCount++;

			// We will need this as all other heuristics are based on the shrinking of .text section
			// We need to subtract this from every split offset calculation
			moveOffset = imageLoader.getSectionHeader(packedContentSectionIndex)->SizeOfRawData;
		}

		// We don't mind if IAT is at the beginning of the data, since it is treated properly as data
		// However there can be IAT between data and code
		if (_importHintsOffset < iatOffset && iatOffset < oepOffset)
		{
			// Split the layout into .data0|.data2|.text
			if (imageLoader.splitSection(packedContentSectionIndex + 1, ".data2", ".text",
					((iatOffset + _iatSize) & ~(sectionAlignment - 1)) + sectionAlignment - moveOffset) == 0)
			{
				imageLoader.getSectionHeader(packedContentSectionIndex + 1)->Characteristics = dataFlags;
				imageLoader.getSectionHeader(packedContentSectionIndex + 2)->Characteristics = codeFlags;
				_addedSectionCount++;

				moveOffset += imageLoader.getSectionHeader(packedContentSectionIndex + 1)->SizeOfRawData;
			}
		}

		// Another heuristic is based on the fact that fix stub can be located behind the code
		// There we can get original code section almost perfectly
		if (fixStubOffset > oepOffset)
		{
			// Split into .data0|.text|.data1 or .data0|.data2|.text|.data1
			if (imageLoader.splitSection(packedContentSectionIndex + _addedSectionCount, ".text", ".data1",
					(fixStubOffset & ~(sectionAlignment - 1)) + sectionAlignment - moveOffset) == 0)
			{
				imageLoader.getSectionHeader(packedContentSectionIndex + _addedSectionCount)->Characteristics = codeFlags;
				imageLoader.getSectionHeader(packedContentSectionIndex + _addedSectionCount + 1)->Characteristics = dataFlags;
				_addedSectionCount++;
			}
		}
	}
	// The OEP is before the hints, so code section is probably the first one in this big section
	else
	{
		// Split into .text|.data0
		if (imageLoader.splitSection(packedContentSectionIndex, ".text", ".data0",
				(_importHintsOffset & ~(sectionAlignment - 1)) + sectionAlignment) == 0)
		{
			imageLoader.getSectionHeader(packedContentSectionIndex)->Characteristics = codeFlags;
			imageLoader.getSectionHeader(packedContentSectionIndex + 1)->Characteristics = dataFlags;
			_addedSectionCount++;
		}

		// There can be even IAT between the .text and .data0 if the hints were placed far behind
		if (oepOffset < iatOffset && iatOffset < _importHintsOffset)
		{
			// Split into .text|.data2|.data0
			if (imageLoader.splitSection(packedContentSectionIndex, ".text", ".data2",
					(iatOffset + _iatSize) & ~(sectionAlignment - 1)) == 0)
			{
				imageLoader.getSectionHeader(packedContentSectionIndex)->Characteristics = codeFlags;
				imageLoader.getSectionHeader(packedContentSectionIndex + 1)->Characteristics = dataFlags;
				_addedSectionCount++;
			}
		}

		// This will probably never happen because if there would be space for fix stub, the hints would be there more probably, but just in case
		if (fixStubOffset < oepOffset)
		{
			// Split into .data1|.text|.data0 or .data1|.text|.data2|.data0
			if (imageLoader.splitSection(packedContentSectionIndex, ".data1", ".text",
					(fixStubOffset & ~(sectionAlignment - 1)) + sectionAlignment) == 0)
			{
				imageLoader.getSectionHeader(packedContentSectionIndex)->Characteristics = dataFlags;
				imageLoader.getSectionHeader(packedContentSectionIndex + 1)->Characteristics = codeFlags;
				_addedSectionCount++;
			}
		}
	}

	imageLoader.makeValid();
}

void MpressPlugin::trailingBytesAnalysis(const DynamicBuffer& buffer)
{
	// Analysis of the trailing bytes of the section
	// 64 bytes at the every section alignment multiple are checked, if they are all 0, the new section is probably here so it is created
	// Only code section left after this function is the one containing the OEP, the code will execute even if some of the code is in data sections
	// and decompiler will take care of this in front-end instruction decoder
	PeLib::ImageLoader & imageLoader = _peFile->imageLoader();
	PeLib::PELIB_IMAGE_SECTION_HEADER * packedContentSection = imageLoader.getSectionHeader(_packedContentSect->getSecSeg()->getIndex());
	std::size_t section = imageLoader.getSectionIndexByRva(imageLoader.getAddressOfEntryPoint());
	PeLib::PELIB_IMAGE_SECTION_HEADER * entryPointSection = imageLoader.getSectionHeader(section);
	std::uint32_t sectionAlignment = imageLoader.getSectionAlignment();
	std::uint32_t startOffset = entryPointSection->PointerToRawData - packedContentSection->PointerToRawData;
	std::uint32_t endOffset = startOffset + entryPointSection->SizeOfRawData;
	std::uint32_t oepOffset = imageLoader.getAddressOfEntryPoint() - packedContentSection->VirtualAddress;

	// Used to build the section names
	std::uint32_t nameCounter = 3;

	// Start at the next section alignment closest to the start of current .text section
	// Move with the step of section alignment
	// End if end of the unpacked section is reached
	for (std::uint32_t offset = startOffset + sectionAlignment; offset < endOffset; offset += sectionAlignment)
	{
		// Inspect trailing 64 bytes, if they are all 0, needSplit is marked as true, resulting in section split
		bool needSplit = true;
		for (std::uint8_t idx = 1; idx <= 64; ++idx)
		{
			if (buffer.read<std::uint8_t>(offset - idx) != 0)
			{
				needSplit = false;
				break;
			}
		}

		if (!needSplit)
			continue;

		std::stringstream ssFirst, ssSecond;
		std::uint32_t flags[2];
		// OEP lies in the first part of splitted sections
		if (startOffset <= oepOffset && oepOffset < offset)
		{
			ssFirst << ".text";
			ssSecond << ".data" << nameCounter++;
			flags[1] = PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
			flags[0] = flags[1] | PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE | PeLib::PELIB_IMAGE_SCN_CNT_CODE;
		}
		// OEP lies in the second part of splitted sections
		else if (offset <= oepOffset && oepOffset < endOffset)
		{
			ssFirst << ".data" << nameCounter++;
			ssSecond << ".text";
			flags[0] = PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
			flags[1] = flags[0] | PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE | PeLib::PELIB_IMAGE_SCN_CNT_CODE;
		}
		// OEP doesn't lie in neither of these two parts, this can happen if .text section was already created and we are analyzing the rest after that
		else
		{
			ssFirst << ".data" << nameCounter++;
			ssSecond << ".data" << nameCounter++;
			flags[0] = PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
			flags[1] = flags[0];
		}

		imageLoader.splitSection(section, ssFirst.str(), ssSecond.str(), offset - startOffset);
		imageLoader.getSectionHeader(section)->Characteristics = flags[0];
		imageLoader.getSectionHeader(section + 1)->Characteristics = flags[1];
		imageLoader.makeValid();
		_addedSectionCount++;
		section++;
		startOffset = offset;
	}
}

void MpressPlugin::fixRelocations()
{
	// We will only manipulate this section as all information are stored here
	const retdec::loader::Segment* epSegment = _file->getEpSegment();
	PeLib::ImageLoader & imageLoader = _peFile->imageLoader();

	// Calculate the offset of EP in EP section
	std::uint64_t epAddress;
	_file->getFileFormat()->getEpAddress(epAddress);
	epAddress -= epSegment->getAddress();

	// Read the data at the desired offsets
	std::vector<unsigned char> relocRvaBytes, relocSizeBytes;
	epSegment->getBytes(relocRvaBytes, epAddress + mpressUnpackerStubData[_unpackerStub].relocOffset, 4);
	epSegment->getBytes(relocSizeBytes, epAddress + mpressUnpackerStubData[_unpackerStub].relocSizeOffset, 4);

	DynamicBuffer relocRvaBuffer(relocRvaBytes, _file->getFileFormat()->getEndianness());
	DynamicBuffer relocSizeBuffer(relocSizeBytes, _file->getFileFormat()->getEndianness());

	// When the size of relocation is 0, there are no relocations
	std::uint32_t relocSize = relocSizeBuffer.read<std::uint32_t>(0);
	if (relocSize == 0)
		return;

	// Set the base relocation directory in the new file
	// All relocations are here undamaged so we are good with this
	std::uint32_t relocRva = relocRvaBuffer.read<std::uint32_t>(0);
	imageLoader.setDataDirectory(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC, relocRva, relocSize);
}

MpressUnpackerStub MpressPlugin::detectUnpackerStubVersion()
{
	std::uint64_t ep;
	std::vector<std::uint8_t> signatureBytes;

	// Get the data in EP section so we can compare it with signature
	_file->getFileFormat()->getEpAddress(ep);
	ep -= _file->getEpSegment()->getAddress();
	_file->getEpSegment()->getBytes(signatureBytes, ep + 8, 4);

	DynamicBuffer signatureBuffer(signatureBytes, _file->getFileFormat()->getEndianness());
	std::uint32_t signature = signatureBuffer.read<std::uint32_t>(0);

	// Signature should not be bigger than 0xC00 for all versions of MPRESS
	// This heuristic can catch corrupted unpacking stubs
	if (signature >= 0xC00)
		throw CorruptedUnpackingStubException();

	for (std::uint32_t version = 0; version < static_cast<std::uint32_t>(MPRESS_UNPACKER_STUB_UNKNOWN); ++version)
	{
		if (signature == mpressUnpackerStubData[version].signature)
		{
			_unpackerStub = static_cast<MpressUnpackerStub>(version);
			return static_cast<MpressUnpackerStub>(version);
		}
	}

	return MPRESS_UNPACKER_STUB_UNKNOWN;
}

MpressFixStub MpressPlugin::detectFixStubVersion(DynamicBuffer& unpackedContent)
{
	std::uint32_t fixStub = getFixStub();
	for (std::uint32_t version = 0; version < static_cast<std::uint32_t>(MPRESS_FIX_STUB_UNKNOWN); ++version)
	{
		if (unpackedContent.read<std::uint8_t>(fixStub + 7) == mpressFixStubData[version].signature)
		{
			_fixStub = static_cast<MpressFixStub>(version);
			return static_cast<MpressFixStub>(version);
		}
	}

	return MPRESS_FIX_STUB_UNKNOWN;
}

void MpressPlugin::saveFile(const std::string& fileName, DynamicBuffer& content)
{
	PeLib::ImageLoader & imageLoader = _peFile->imageLoader();

	// Removes the file if it already exists
	std::remove(fileName.c_str());

	// Headers
	imageLoader.Save(fileName.c_str(), PeLib::IoFlagNewFile);

	std::fstream outputFile(fileName, std::ios::binary | std::ios::out | std::ios::in);
	// Copy the section bytes from original file for the sections preceding the packed section
	for (std::uint32_t index = 0; index < _packedContentSect->getSecSeg()->getIndex(); ++index)
		copySectionFromOriginalFile(index, outputFile, index);

	// Copy the section bytes in between packed section and EP section
	for (std::uint32_t index = _packedContentSect->getSecSeg()->getIndex() + _addedSectionCount; index < _file->getEpSegment()->getSecSeg()->getIndex(); ++index)
		copySectionFromOriginalFile(index, outputFile, index + _addedSectionCount);

	// Copy the section bytes from original file for sections after EP section excluded
	for (std::uint32_t index = _file->getEpSegment()->getSecSeg()->getIndex() + 1; index < _file->getNumberOfSegments(); ++index)
		copySectionFromOriginalFile(index, outputFile, index + _addedSectionCount);

	// Write content of new import section
	std::uint32_t Rva = imageLoader.getDataDirRva(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT);
	_peFile->impDir().write(fileName, imageLoader.getFileOffsetFromRva(Rva), Rva, imageLoader.getPointerSize());

	// After this all we need to update the IAT with the contents of ILT
	// since Import Directory in PeLib is built after the write to the file
	for (size_t fileIndex = 0; fileIndex < _peFile->impDir().getNumberOfFiles(false); ++fileIndex)
	{
		auto tmp = static_cast<unsigned int>(fileIndex);
		auto w = static_cast<unsigned short>(_packedContentSect->getSecSeg()->getIndex());
		size_t destOffset = _peFile->impDir().getFirstThunk(tmp, false) - imageLoader.getSectionHeader(w)->VirtualAddress;
		for (size_t funcIndex = 0; funcIndex < _peFile->impDir().getNumberOfFunctions(tmp, false); ++funcIndex, destOffset += 4)
		{
			content.write<std::uint32_t>(
					_peFile->impDir().getOriginalFirstThunk(tmp, static_cast<unsigned int>(funcIndex), false),
					static_cast<uint32_t>(destOffset));
		}
	}

	// Write the unpacked content to the packed content section
	// Use regular file as we will write more sections at once
	outputFile.seekp(imageLoader.getSectionHeader(_packedContentSect->getSecSeg()->getIndex())->PointerToRawData, std::ios_base::beg);
	outputFile.write(reinterpret_cast<const char*>(content.getRawBuffer()), content.getRealDataSize());
	outputFile.close();
}

void MpressPlugin::copySectionFromOriginalFile(std::uint32_t origSectIndex, std::ostream& outputFile, std::uint32_t newSectIndex)
{
	const retdec::loader::Segment* seg = _file->getSegment(origSectIndex);
	std::vector<std::uint8_t> bytes;
	seg->getBytes(bytes);

	PeLib::ImageLoader & imageLoader = _peFile->imageLoader();
	const auto* newSect = imageLoader.getSectionHeader(newSectIndex);
	outputFile.seekp(newSect->PointerToRawData, std::ios_base::beg);
	outputFile.write(reinterpret_cast<const char*>(bytes.data()), std::min(static_cast<std::uint32_t>(bytes.size()), newSect->SizeOfRawData));

}

} // namespace mpress
} // namespace unpackertool
} // namespace retdec
