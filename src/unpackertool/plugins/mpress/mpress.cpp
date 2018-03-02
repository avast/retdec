/**
 * @file src/unpackertool/plugins/mpress/mpress.cpp
 * @brief Unpacker plugin for MPRESS packer.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cstdint>
#include <memory>

#include <pelib/PeLib.h>

#include "retdec/loader/loader.h"
#include "retdec/unpacker/plugin.h"
#include "retdec/unpacker/decompression/lzma/lzma_data.h"
#include "retdec/unpacker/decompression/lzmat/lzmat_data.h"
#include "retdec/unpacker/unpacker_exception.h"

#include "unpackertool/plugins/mpress/mpress.h"
#include "unpackertool/plugins/mpress/mpress_exceptions.h"

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

	if (!_file->getFileFormat()->isPe())
		throw UnsupportedFileException();

	// We currently don't support PE32+ as the decompiler doesn't support them anyways
	if (static_cast<retdec::fileformat::PeFormat*>(_file->getFileFormat())->getPeClass() != PeLib::PEFILE32)
		throw UnsupportedFileException();

	if (!_file->getEpSegment())
		throw NoEntryPointException();

	_peFile = static_cast<PeLib::PeFile32*>(PeLib::openPeFile(getStartupArguments()->inputFile));
	_peFile->readMzHeader();
	_peFile->readPeHeader();

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
	unsigned long long ep;
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
	unsigned long long ep, epOffset;
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
	std::uint32_t maxAddr = buffer.getRealDataSize() - 0x1000;
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
	// At the offset from EP is written EIP relative offset of fix import stub
	// Fix import stub is then located at the <EP Address> + offset + <loaded offset>
	// This stub was packed together with code and data in .MPRESS1 section and also contains hints for import table rebuild
	std::uint32_t fixStubAddr = getFixStub();

	// Offet to the hints is located at the <Fix Import Stub Address> + offset
	// Import hints are located at the <Fix Import Stub Address> + offset + <Import Hints Offset>
	std::uint32_t importHints = fixStubAddr + mpressFixStubData[_fixStub].importHintsOffset + buffer.read<std::uint32_t>(fixStubAddr + mpressFixStubData[_fixStub].importHintsOffset);

	// Go through MPRESS import hints and fill the import directory
	std::int32_t destOffset = _peFile->peHeader().getVirtualAddress(_packedContentSect->getSecSeg()->getIndex()) + importHints;
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
		int fileIndex = _peFile->impDir().getFileIndex(moduleName, PeLib::NEWDIR);
		if (fileIndex == -1)
			throw InvalidImportHintsException();

		_peFile->impDir().setFirstThunk(fileIndex, PeLib::NEWDIR, destOffset);
		lowestDestOffset = std::min(destOffset, lowestDestOffset);
		highestDestOffset = std::max(destOffset, highestDestOffset);
		destOffset += destOffsetDiff;
	}

	buffer.writeRepeatingByte(0, readPos, 4); // clear out last -1 from the hint list

	// Fix the import directory and import address directory addresses
	// Since ILT is lost we need to make them from scratch in the whole new section
	// Ensure the .imports section will be large enough, resize if there are more data
	std::uint32_t importSectSize = _peFile->impDir().size() & ~(_peFile->peHeader().getFileAlignment() - 1);
	if (_peFile->impDir().size() & (_peFile->peHeader().getFileAlignment() - 1))
		importSectSize += _peFile->peHeader().getFileAlignment();
	_peFile->peHeader().addSection(".imports", importSectSize);
	_peFile->peHeader().setCharacteristics(_peFile->peHeader().calcNumberOfSections() - 1, PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA);
	_peFile->peHeader().setIddImportRva(_peFile->peHeader().getVirtualAddress(_peFile->peHeader().calcNumberOfSections() - 1));
	_peFile->peHeader().setIddImportSize(importSectSize);
	_peFile->peHeader().makeValid(_peFile->mzHeader().size());

	// IAT needs to be put at the desired offset
	std::uint32_t iatOffset = lowestDestOffset;
	_peFile->peHeader().setIddIatRva(iatOffset);
	_peFile->peHeader().setIddIatSize(highestDestOffset + 4 - lowestDestOffset);
	_peFile->peHeader().makeValid(_peFile->mzHeader().size());

	// Offset to OEP is stored at the offset from the <Fix Import Stub Address>
	// This offset is addressed from the <Fix Import Stub Address> + offset
	std::uint32_t oepOffset = _peFile->peHeader().getVirtualAddress(_packedContentSect->getSecSeg()->getIndex()) + fixStubAddr +
			mpressFixStubData[_fixStub].importHintsOffset + buffer.read<std::uint32_t>(fixStubAddr + mpressFixStubData[_fixStub].oepOffset);
	_peFile->peHeader().setAddressOfEntryPoint(oepOffset);
	_peFile->peHeader().makeValid(_peFile->mzHeader().size());

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
	std::uint32_t fixStubOffset = getFixStub();
	std::uint32_t dataFlags = PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
	std::uint32_t codeFlags = dataFlags | PeLib::PELIB_IMAGE_SCN_CNT_CODE | PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE;

	// Remove the .MPRESS2 section as the getEpSection()->getIndex() will be shifted by newly created
	// sections and we can do it safely here
	//_peFile->peHeader().removeSection(_file->getEpSection()->getIndex());
	// @todo There is some problem with removing a section and valid PE file in some cases
	_peFile->peHeader().setCharacteristics(_file->getEpSegment()->getSecSeg()->getIndex(), dataFlags);

	// Resize packed content section so we can put unpacked content into it
	size_t diff = buffer.getRealDataSize() - _peFile->peHeader().getSizeOfRawData(_packedContentSect->getSecSeg()->getIndex());
	_peFile->peHeader().setSizeOfRawData(_packedContentSect->getSecSeg()->getIndex(), buffer.getRealDataSize());
	for (size_t i = _packedContentSect->getSecSeg()->getIndex() + 1; i < _peFile->peHeader().calcNumberOfSections(); ++i)
	{
		auto ii = static_cast<unsigned short>(i);
		auto tmp = _peFile->peHeader().getPointerToRawData(ii) + diff;
		_peFile->peHeader().setPointerToRawData(ii, static_cast<unsigned int>(tmp));
	}

	// Here we will split the big unpacked section into the more data sections and try to locate the code section as much as possible
	// We will use import hints, IAT, fix stub address and OEP to locate the original sections
	// We know that hints and fix stub are located at the end of original sections
	// We also know that IAT is its own section
	std::uint32_t oepOffset = _oepVa - _peFile->peHeader().getVirtualAddress(_packedContentSect->getSecSeg()->getIndex());
	std::uint32_t iatOffset = (_iatVa & ~(_peFile->peHeader().getSectionAlignment() - 1)) - _peFile->peHeader().getVirtualAddress(_packedContentSect->getSecSeg()->getIndex());

	// We will need this as all other heuristics are based on the shrinking of .text section
	std::uint32_t moveOffset = 0;

	// Hints are located before the OEP, we suspect that there is data section before the code
	if (_importHintsOffset < oepOffset)
	{
		// Split the section into .data0|.text
		if (_peFile->peHeader().splitSection(_packedContentSect->getSecSeg()->getIndex(), ".data0", ".text",
				(_importHintsOffset & ~(_peFile->peHeader().getSectionAlignment() - 1)) + _peFile->peHeader().getSectionAlignment()) == 0)
		{
			_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex(), dataFlags);
			_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + 1, codeFlags);
			_addedSectionCount++;

			// We will need this as all other heuristics are based on the shrinking of .text section
			// We need to subtract this from every split offset calculation
			moveOffset = _peFile->peHeader().getSizeOfRawData(_packedContentSect->getSecSeg()->getIndex());
		}

		// We don't mind if IAT is at the beginning of the data, since it is treated properly as data
		// However there can be IAT between data and code
		if (_importHintsOffset < iatOffset && iatOffset < oepOffset)
		{
			// Split the layout into .data0|.data2|.text
			if (_peFile->peHeader().splitSection(_packedContentSect->getSecSeg()->getIndex() + 1, ".data2", ".text",
					((iatOffset + _iatSize) & ~(_peFile->peHeader().getSectionAlignment() - 1)) + _peFile->peHeader().getSectionAlignment() - moveOffset) == 0)
			{
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + 1, dataFlags);
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + 2, codeFlags);
				_addedSectionCount++;
				moveOffset += _peFile->peHeader().getSizeOfRawData(_packedContentSect->getSecSeg()->getIndex() + 1);
			}
		}

		// Another heuristic is based on the fact that fix stub can be located behind the code
		// There we can get original code section almost perfectly
		if (fixStubOffset > oepOffset)
		{
			// Split into .data0|.text|.data1 or .data0|.data2|.text|.data1
			if (_peFile->peHeader().splitSection(_packedContentSect->getSecSeg()->getIndex() + _addedSectionCount, ".text", ".data1",
					(fixStubOffset & ~(_peFile->peHeader().getSectionAlignment() - 1)) + _peFile->peHeader().getSectionAlignment() - moveOffset) == 0)
			{
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + _addedSectionCount, codeFlags);
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + _addedSectionCount + 1, dataFlags);
				_addedSectionCount++;
			}
		}
	}
	// The OEP is before the hints, so code section is probably the first one in this big section
	else
	{
		// Split into .text|.data0
		if (_peFile->peHeader().splitSection(_packedContentSect->getSecSeg()->getIndex(), ".text", ".data0",
				(_importHintsOffset & ~(_peFile->peHeader().getSectionAlignment() - 1)) + _peFile->peHeader().getSectionAlignment()) == 0)
		{
			_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex(), codeFlags);
			_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + 1, dataFlags);
			_addedSectionCount++;
		}

		// There can be even IAT between the .text and .data0 if the hints were placed far behind
		if (oepOffset < iatOffset && iatOffset < _importHintsOffset)
		{
			// Split into .text|.data2|.data0
			if (_peFile->peHeader().splitSection(_packedContentSect->getSecSeg()->getIndex(), ".text", ".data2",
					(iatOffset + _iatSize) & ~(_peFile->peHeader().getSectionAlignment() - 1)) == 0)
			{
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex(), codeFlags);
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + 1, dataFlags);
				_addedSectionCount++;
			}
		}

		// This will probably never happen because if there would be space for fix stub, the hints would be there more probably, but just in case
		if (fixStubOffset < oepOffset)
		{
			// Split into .data1|.text|.data0 or .data1|.text|.data2|.data0
			if (_peFile->peHeader().splitSection(_packedContentSect->getSecSeg()->getIndex(), ".data1", ".text",
					(fixStubOffset & ~(_peFile->peHeader().getSectionAlignment() - 1)) + _peFile->peHeader().getSectionAlignment()) == 0)
			{
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex(), dataFlags);
				_peFile->peHeader().setCharacteristics(_packedContentSect->getSecSeg()->getIndex() + 1, codeFlags);
				_addedSectionCount++;
			}
		}
	}

	_peFile->peHeader().makeValid(_peFile->mzHeader().size());
}

void MpressPlugin::trailingBytesAnalysis(const DynamicBuffer& buffer)
{
	// Analysis of the trailing bytes of the section
	// 64 bytes at the every section alignment multiple are checked, if they are all 0, the new section is probably here so it is created
	// Only code section left after this function is the one containing the OEP, the code will execute even if some of the code is in data sections
	// and decompiler will take care of this in front-end instruction decoder
	std::uint32_t sectionAlignment = _peFile->peHeader().getSectionAlignment();
	std::uint32_t section = _peFile->peHeader().getSectionWithRva(_peFile->peHeader().getAddressOfEntryPoint());
	std::uint32_t startOffset = _peFile->peHeader().getPointerToRawData(section) - _peFile->peHeader().getPointerToRawData(_packedContentSect->getSecSeg()->getIndex());
	std::uint32_t endOffset = startOffset + _peFile->peHeader().getSizeOfRawData(section);
	std::uint32_t oepOffset = _peFile->peHeader().getAddressOfEntryPoint() - _peFile->peHeader().getVirtualAddress(_packedContentSect->getSecSeg()->getIndex());

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
		// OEP doesn't lie in neither of these two parts, this can happen if .text section was already created and we are analysis the rest after that
		else
		{
			ssFirst << ".data" << nameCounter++;
			ssSecond << ".data" << nameCounter++;
			flags[0] = PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA;
			flags[1] = flags[0];
		}

		_peFile->peHeader().splitSection(section, ssFirst.str(), ssSecond.str(), offset - startOffset);
		_peFile->peHeader().setCharacteristics(section, flags[0]);
		_peFile->peHeader().setCharacteristics(section + 1, flags[1]);
		_peFile->peHeader().makeValid(_peFile->mzHeader().size());
		_addedSectionCount++;
		section++;
		startOffset = offset;
	}
}

void MpressPlugin::fixRelocations()
{
	// We will only manipulate this section as all information are stored here
	const retdec::loader::Segment* epSegment = _file->getEpSegment();

	// Calculate the offset of EP in EP section
	unsigned long long epAddress;
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
	_peFile->peHeader().setIddBaseRelocRva(relocRva);
	_peFile->peHeader().setIddBaseRelocSize(relocSize);
	_peFile->peHeader().makeValid(_peFile->mzHeader().size());
}

MpressUnpackerStub MpressPlugin::detectUnpackerStubVersion()
{
	unsigned long long ep;
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
	// Removes the file if it already exists
	std::remove(fileName.c_str());

	// Headers
	_peFile->mzHeader().write(fileName, 0);
	_peFile->peHeader().write(fileName, _peFile->mzHeader().size());
	_peFile->peHeader().writeSections(fileName);

	// Copy the section bytes from original file for the sections preceding the packed section
	for (std::uint32_t index = 0; index < _packedContentSect->getSecSeg()->getIndex(); ++index)
		copySectionFromOriginalFile(index, fileName, index);

	// Copy the section bytes in between packed section and EP section
	for (std::uint32_t index = _packedContentSect->getSecSeg()->getIndex() + _addedSectionCount; index < _file->getEpSegment()->getSecSeg()->getIndex(); ++index)
		copySectionFromOriginalFile(index, fileName, index + _addedSectionCount);

	// Copy the section bytes from original file for sections after EP section excluded
	for (std::uint32_t index = _file->getEpSegment()->getSecSeg()->getIndex() + 1; index < _file->getNumberOfSegments(); ++index)
		copySectionFromOriginalFile(index, fileName, index + _addedSectionCount);

	// Write content of new import section
	_peFile->impDir().write(fileName, _peFile->peHeader().rvaToOffset(_peFile->peHeader().getIddImportRva()), _peFile->peHeader().getIddImportRva());

	// After this all we need to update the IAT with the contents of ILT
	// since Import Directory in PeLib is built after the write to the file
	for (size_t fileIndex = 0; fileIndex < _peFile->impDir().getNumberOfFiles(PeLib::OLDDIR); ++fileIndex)
	{
		auto tmp = static_cast<unsigned int>(fileIndex);
		auto w = static_cast<unsigned short>(_packedContentSect->getSecSeg()->getIndex());
		size_t destOffset = _peFile->impDir().getFirstThunk(tmp, PeLib::OLDDIR) - _peFile->peHeader().getVirtualAddress(w);
		for (size_t funcIndex = 0; funcIndex < _peFile->impDir().getNumberOfFunctions(tmp, PeLib::OLDDIR); ++funcIndex, destOffset += 4)
		{
			content.write<std::uint32_t>(
					_peFile->impDir().getOriginalFirstThunk(tmp, static_cast<unsigned int>(funcIndex), PeLib::OLDDIR),
					static_cast<uint32_t>(destOffset));
		}
	}

	// Write the unpacked content to the packed content section
	// Use regular file as we will write more sections at once
	std::fstream outputFile(fileName, std::ios::binary | std::ios::out | std::ios::in);
	outputFile.seekp(_peFile->peHeader().getPointerToRawData(_packedContentSect->getSecSeg()->getIndex()), std::ios_base::beg);
	outputFile.write(reinterpret_cast<const char*>(content.getRawBuffer()), content.getRealDataSize());
	outputFile.close();
}

void MpressPlugin::copySectionFromOriginalFile(std::uint32_t origSectIndex, const std::string& newFileName, std::uint32_t newSectIndex)
{
	const retdec::loader::Segment* seg = _file->getSegment(origSectIndex);
	std::vector<std::uint8_t> bytes;
	seg->getBytes(bytes);
	_peFile->peHeader().writeSectionData(newFileName, newSectIndex, bytes);
}

} // namespace mpress
} // namespace unpackertool
} // namespace retdec
