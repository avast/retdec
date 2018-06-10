/**
 * @file src/unpackertool/plugins/upx/pe/pe_upx_stub.cpp
 * @brief Implementation of UPX unpacking stub in PE files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cstring>

#include <pelib/PeLib.h>

#include "retdec/utils/alignment.h"
#include "retdec/utils/file_io.h"
#include "unpackertool/plugins/upx/decompressors/decompressors.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/unfilter.h"
#include "unpackertool/plugins/upx/upx.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub_signatures.h"

using namespace retdec::utils;
using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

namespace {

// UPX unfilter stubs signatures
// x86 - Jump Filter 11
Signature x86Unfilter11Signature =
{
	0x89, 0xF7, // MOV EDI, ESI
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Number of Jumps to Unfilter>
	0xB0, 0xE8, // MOV AL, 0E8h
	0xF2, 0xAE, // REPNE SCASB
	0x75, 0x09, // JNZ rel +0x9
	0x8B, 0x07, // MOV EAX, EDI
	0x29, 0xF8, // SUB EAX, EDI
	0x01, 0xF0, // ADD EAX, ESI
	0xAB, // STOSD
	0xEB, 0xF1 // JMP rel -15
};

// x86 - Jump Filter 16
Signature x86Unfilter16Signature =
{
	0x89, 0xF7, // MOV EDI, ESI
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Number of Jumps to Unfilter>
	0x8A, 0x07, // MOV AL, [EDI]
	0x47, // INC EDI
	0x2C, 0xE8, // SUB AL, 0E8h
	0x3C, 0x01, // CMP AL, 1
	0x77, 0xF7, // JA rel -9
	0x8B, 0x07, // MOV EAX, [EDI]
	0x8A, 0x5F, 0x04, // MOV BL, [EDI + 4]
	0x86, 0xC4, // XCHG AL, AH
	0xC1, 0xC0, 0x10, // ROL EAX, 10h
	0x86, 0xC4, // XCHG AL, AH
	0x29, 0xF8, // SUB EAX, EDI
	0x80, 0xEB, 0xE8, // SUB BL, 0E8h
	0x01, 0xF0, // ADD EAX, ESI
	0x89, 0x07, // MOV [EDI], EAX
	0x83, 0xC7, 0x05 // ADD EDI, 5
};

// x86 - Jump Filter 24
Signature x86Unfilter24Signature =
{
	0x89, 0xF7, // MOV EDI, ESI
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Number of Jumps to Unfilter>
	0xB0, 0xE8, // MOV AL, 0E8h
	0xF2, 0xAE, // REPNE SCASB
	0x75, 0x17, // JNZ rel +0x17
	0x80, 0x3F, CAP, // CMP BYTE PTR [EDI], <Filter parameter>
	0x75, 0xF7, // JMP rel -7
	0x8B, 0x07, // MOV EAX, [EDI]
	0x66, 0xC1, 0xE8, 0x08, // SHR AX, 8
	0xC1, 0xC0, 0x10, // ROL EAX, 10h
	0x86, 0xC4, // XCHG AL, AH
	0x29, 0xF8 // SUB EAX, EDI
};

// x86 - Jump Filter 26/46
Signature x86Unfilter26_46Signature =
{
	0x89, 0xF7, // MOV EDI, ESI`
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Number of Jumps to Unfilter>
	0x8A, 0x07, // MOV AL, [EDI]
	0x47, // INC EDI
	0x2C, 0xE8, // SUB AL, 0E8h
	0x3C, 0x01, // CMP AL, 1
	0x77, 0xF7, // JA rel -9
	0x80, 0x3F, CAP // CMP BYTE PTR [EDI], <Filter parameter>
};

// x86 - Jump Filter 0x49
Signature x86Unfilter49Signature =
{
	0x89, 0xF7, // MOV EDI, ESI
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Number of Jumps to Unfilter>
	0xEB, 0x32, // JMP rel +0x32
	0x8A, 0x07, // MOV AL, [EDI]
	0x83, 0xC7, 0x01, // ADD EDI, 1
	0x3C, 0x80, // CMP AL, 80h
	0x72, 0x0A, // JB rel +0x0A
	0x3C, 0x8F, // CMP AL, 8Fh
	0x77, 0x06, // JA rel +0x06
	0x80, 0x7F, 0xFE, 0x0F, // CMP BYTE PTR [EDI - 2], 0Fh
	0x74, 0x06, // JZ rel +0x6
	0x2C, 0xE8, // SUB AL, 0E8h
	0x3C, 0x01, // CMP AL, 1
	0x77, 0x23, // JA rel +0x23
	0x80, 0x3F, CAP // CMP BYTE PTR [EDI], <Filter parameter>
};

// x64 - Jump Filter 0x49
Signature x64Unfilter49Signature =
{
	0x48, 0x89, 0xF7, // MOV RDI, RSI
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Number of Jumps to Unfilter>
	0xB2, CAP, // MOV DL, <Filter parameter>
	0x48, 0x89, 0xFB, // MOV RDX, RDI
	0xEB, 0x2C, // JMP rel +0x2C
	0x8A, 0x07, // MOV AL, [RDI]
	0x48, 0x83, 0xC7, 0x01, // ADD RDI, 1
	0x3C, 0x80, // CMP AL, 0x80
	0x72, 0x0A, // JB rel +0x0A
	0x3C, 0x8F, // CMP AL, 0x8F
	0x77, 0x06, // JA rel +0x06
	0x80, 0x7F, 0xFE, 0x0F, // CMP BYTE PTR [RDI - 2], 0x0F
	0x74, 0x06, // JZ rel +0x06
	0x2C, 0xE8 // SUB AL, 0xE8
};

std::vector<UnfilterSignatureData> unfilterSignatures =
{
	{ &x86Unfilter11Signature,    FILTER_11 },
	{ &x86Unfilter16Signature,    FILTER_16 },
	{ &x86Unfilter24Signature,    FILTER_24 },
	{ &x86Unfilter26_46Signature, FILTER_26 },
	{ &x86Unfilter49Signature,    FILTER_49 },
	{ &x64Unfilter49Signature,    FILTER_49 }
};

} // anonymous namespace

/**
 * Constructor.
 *
 * @param inputFile Packed input file.
 * @param stubData @ref UpxStubData associated with this unpacking stub.
 * @param stubCapturedData Data captured from signature matching.
 * @param decompressor Associated decompressor with this unpacking stub.
 * @param metadata The UPX metadata associated with this unpacking stub.
 */
template <int bits> PeUpxStub<bits>::PeUpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const DynamicBuffer& stubCapturedData,
		std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata)
	: UpxStub(inputFile, stubData, stubCapturedData, std::move(decompressor), metadata), _upx0Sect(nullptr),
		_realEpAddress(0), _newPeFile(nullptr), _rvaShift(0), _exportsCompressed(false),
		_filterId(FILTER_UNKNOWN), _filterCount(0), _filterParam(0)
{
	unsigned long long ep;
	_file->getFileFormat()->getEpAddress(ep);
	_realEpAddress = ep;
}

/**
 * Destructor.
 */
template <int bits> PeUpxStub<bits>::~PeUpxStub()
{
}

/**
 * Performs the whole process of unpacking. This is the method that is being run from @ref UpxPlugin to start
 * unpacking stub.
 *
 * @param outputFile Path to unpacked output file.
 */
template <int bits> void PeUpxStub<bits>::unpack(const std::string& outputFile)
{
	// Prepare unpacking stub for unpacking.
	prepare();

	// Read the unpacking stub
	DynamicBuffer unpackingStub;
	readUnpackingStub(unpackingStub);

	// Detect auxiliary stubs
	detectUnfilter(unpackingStub);

	std::string inputFilePath = _file->getFileFormat()->getPathToFile();
	PeLib::PeFile* peFile = PeLib::openPeFile(inputFilePath);
	_newPeFile = static_cast<PeLibFileType*>(peFile);

	// Read MZ & PE headers
	_newPeFile->readMzHeader();
	_newPeFile->readPeHeader();

	// We won't copy the DOS program so let's just set the pointer to PE header right after MZ header
	_newPeFile->mzHeader().setAddressOfPeHeader(_newPeFile->mzHeader().size());

	// Perform unpacking
	DynamicBuffer unpackedData(_file->getFileFormat()->getEndianness());
	unpackData(unpackedData);

	// Parse extra data and original header from the tail of the unpacked data
	DynamicBuffer originalHeader(_file->getFileFormat()->getEndianness());
	UpxExtraData extraData = parseExtraData(unpackedData, originalHeader);

	// Read the ILT data, since it is going to be used for fixing
	DynamicBuffer ilt(_file->getFileFormat()->getEndianness());
	readPackedFileILT(ilt);

	// Fix the raw size and raw address of all sections
	fixSizeOfSections(unpackedData);

	// Fix certain PE header values
	fixPeHeader(originalHeader);

	// Unfilter unpacked data
	unfilterData(unpackedData);

	// Fix the imports
	fixImports(unpackedData, extraData, ilt);

	// Fix the relocation entries
	fixRelocations(unpackedData, extraData);

	// Fix TLS
	fixTls(originalHeader);

	// Fix the OEP address
	fixOep(originalHeader);

	// Fix exports directory
	fixExports(originalHeader);

	// Fix load configuration directory
	fixLoadConfiguration(originalHeader);

	// Fix resources
	fixResources(unpackedData, originalHeader);

	// Fix section count and names
	fixSectionHeaders(originalHeader);

	// Fix COFF symbol table
	fixCoffSymbolTable();

	// Fix certificate table
	fixCertificates();

	// Cut hints data from unpacked data before writing it into file
	cutHintsData(unpackedData, extraData);

	// Save the output to the file
	saveFile(outputFile, unpackedData);
}

/**
 * Accepts the visitor-like decompressor and runs checking of packing method.
 *
 * @param packingMethod The packing method to check.
 */
template <int bits> void PeUpxStub<bits>::setupPackingMethod(std::uint8_t packingMethod)
{
	_decompressor->setupPackingMethod(this, packingMethod);
}

/**
 * Reads the unpacking stub (from EP up to the end of the EP section) and stores it into @ref retdec::unpacker::DynamicBuffer.
 *
 * @param unpackingStub Buffer where to store unpacking stub.
 */
template <int bits> void PeUpxStub<bits>::readUnpackingStub(DynamicBuffer& unpackingStub)
{
	_decompressor->readUnpackingStub(this, unpackingStub);
}

/**
 * Reads the packed data based on signature or metadata information.
 *
 * @param packedData Buffer where to store packed data.
 * @param trustMetadata False if signature has more priority, otherwise metadata is prioritized.
 */
template <int bits> void PeUpxStub<bits>::readPackedData(DynamicBuffer& packedData, bool trustMetadata)
{
	_decompressor->readPackedData(this, packedData, trustMetadata);
}

/**
 * Decompresses the packed data and stores result in @ref retdec::unpacker::DynamicBuffer.
 *
 * @param packedData Data to decompress.
 * @param unpackedData Buffer where to store the result.
 * @param trustMetadata False if signature has more priority, otherwise metadata is prioritized.
 */
template <int bits> void PeUpxStub<bits>::decompress(DynamicBuffer& packedData, DynamicBuffer& unpackedData, bool trustMetadata)
{
	_decompressor->decompress(this, packedData, unpackedData, trustMetadata);
}

/**
 * Performs releasing of owned resources.
 */
template <int bits> void PeUpxStub<bits>::cleanup()
{
	delete _newPeFile;
	_newPeFile = nullptr;
}

/**
 * Returns the entry point address.
 *
 * @return Entry point address.
 */
template <int bits> std::uint32_t PeUpxStub<bits>::getRealEpAddress() const
{
	return _realEpAddress;
}

/**
 * Sets the entry point address.
 *
 * @param realEpAddress Entry point address to set.
 */
template <int bits> void PeUpxStub<bits>::setRealEpAddress(std::uint32_t realEpAddress)
{
	_realEpAddress = realEpAddress;
}

/**
 * Prepares the unpacking stub for unpacking.
 */
template <int bits> void PeUpxStub<bits>::prepare()
{
	// Load section UPX0 (destination for unpacked data)
	_upx0Sect = _file->getSegment(0);
}

/**
 * Detects used unfilter based on signature. If no signature is matched, UPX metadata are used if present in the file.
 *
 * @param unpackingStub The unpacking stub buffer.
 */
template <int bits> void PeUpxStub<bits>::detectUnfilter(const DynamicBuffer& unpackingStub)
{
	// We need to look for signatures of known filters
	std::uint32_t matchStartOffset = 0;
	if (getStubData() != nullptr)
		matchStartOffset = getStubData()->size;

	std::string detectionBasedOn = "signature";
	DynamicBuffer unfilterCapturedData(_file->getFileFormat()->getEndianness());
	Signature::MatchSettings settings(matchStartOffset, unpackingStub.getRealDataSize());
	for (const auto& unfilterSignature : unfilterSignatures)
	{
		if (!unfilterSignature.signature->match(settings, unpackingStub, unfilterCapturedData))
			continue;

		_filterId = unfilterSignature.filterId;
		_filterCount = unfilterCapturedData.read<std::uint32_t>(0);
		_filterParam = unfilterCapturedData.read<std::uint8_t>(4);
		break;
	}

	// Detect filter based on metadata if we have one, but trust only if no signature was matched
	if (_filterId == FILTER_UNKNOWN && getUpxMetadata()->isDefined())
	{
		_filterId = getUpxMetadata()->getFilterId();
		_filterCount = 0;
		_filterParam = getUpxMetadata()->getFilterParameter();
		detectionBasedOn = "UPX metadata";
	}

	// No filter used probably, we can't say for sure
	// There may be some filter, but we don't have signature and metadata can be modified
	if (_filterId == FILTER_UNKNOWN)
	{
		_filterId = FILTER_NONE;
		_filterCount = 0;
		_filterParam = 0;
		upx_plugin->log("No filter detected, or unknown filter present in the file.");
		return;
	}

	upx_plugin->log("Detected filter 0x", std::hex, _filterId, " with parameter 0x", _filterParam, " based on ", detectionBasedOn, ".");
}

template <int bits> void PeUpxStub<bits>::unpackData(DynamicBuffer& unpackedData)
{
	bool tryAgain = false;

	// First we try not to rely on UPX metadata and trust only signatures
	// However, unpacking may fail so we will try again if there are UPX metadata present while trusting them
	while (true)
	{
		try
		{
			// Setup packing method
			setupPackingMethod(getPackingMethod(tryAgain));

			// Read packed data
			DynamicBuffer packedData(_file->getFileFormat()->getEndianness());
			readPackedData(packedData, tryAgain);

			// Decompress the data
			decompress(packedData, unpackedData, tryAgain);
			break;
		}
		catch (const DecompressionFailedException&)
		{
			if (!tryAgain && getUpxMetadata()->isDefined())
			{
				tryAgain = true;
				continue;
			}
			else
				throw;
		}
	}

	upx_plugin->log("Unpacked data based on ", tryAgain ? "UPX metadata." : "signature.");
}

/**
 * Reads the ILT (Import Lookup Table) of the packed file and stores it into @ref retdec::unpacker::DynamicBuffer.
 *
 * @param ilt Buffer where to store ILT.
 */
template <int bits> void PeUpxStub<bits>::readPackedFileILT(DynamicBuffer& ilt)
{
	// We don't use PeLib for reading ILT because it is going to populate impDir(), but we want to it to build it all ourselves manually
	std::vector<std::uint8_t> iltBytes;
	const retdec::loader::Segment* importsSection = _file->getSegmentFromAddress(_newPeFile->peHeader().getIddImportRva() + _newPeFile->peHeader().getImageBase());

	if (importsSection == nullptr)
		throw ImportNamesNotFoundException();

	importsSection->getBytes(iltBytes,
			_newPeFile->peHeader().rvaToOffset(_newPeFile->peHeader().getIddImportRva()) - importsSection->getSecSeg()->getOffset(),
			_newPeFile->peHeader().getIddImportSize());

	ilt = DynamicBuffer(iltBytes, _file->getFileFormat()->getEndianness());
}

/**
 * Fixes the size of the sections in the unpacked output file. Raw size of section UPX0 is set to match its
 * virtual size so unpacked data can be placed into it. It is also enlarged in case there is an overlap
 * between UPX0 and UPX1 sections. UPX1 and UPX2/rsrc sections are removed from the unpacked file.
 *
 * @param unpackedData The unpacked data.
 */
template <int bits> void PeUpxStub<bits>::fixSizeOfSections(const DynamicBuffer& unpackedData)
{
	// Always make sure that UPX0 points to same raw pointer as UPX1 before we process sections
	// This allows us to use much more simpler algorithm, than calculating with all possible positions of UPX0
	_newPeFile->peHeader().setPointerToRawData(0, _newPeFile->peHeader().getPointerToRawData(1));

	// Set the proper raw size for UPX0 section, thus moving pointer to raw data of all following sections
	std::uint32_t diff = _newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex()) - _newPeFile->peHeader().getSizeOfRawData(_upx0Sect->getSecSeg()->getIndex());
	_newPeFile->peHeader().setSizeOfRawData(_upx0Sect->getSecSeg()->getIndex(), _newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex()));
	for (std::uint32_t i = _upx0Sect->getSecSeg()->getIndex() + 1; i < _newPeFile->peHeader().calcNumberOfSections(); ++i)
		_newPeFile->peHeader().setPointerToRawData(i, _newPeFile->peHeader().getPointerToRawData(i) + diff);

	// If the section UPX0 is lesser than all the unpacked data, we need to move boundaries of UPX0/UPX1 section
	// Since UPX0 and UPX1 have continuous address space, we can just resize UPX0 and shrink UPX1
	if (_newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex()) < unpackedData.getRealDataSize())
	{
		// Make sure the new size is section aligned
		std::uint32_t newSize = retdec::utils::alignUp(unpackedData.getRealDataSize(), _newPeFile->peHeader().getSectionAlignment());

		diff = newSize - _newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex());

		_newPeFile->peHeader().setVirtualSize(_upx0Sect->getSecSeg()->getIndex(), _newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex()) + diff);
		_newPeFile->peHeader().setSizeOfRawData(_upx0Sect->getSecSeg()->getIndex(), _newPeFile->peHeader().getSizeOfRawData(_upx0Sect->getSecSeg()->getIndex()) + diff);

		_newPeFile->peHeader().setVirtualAddress(_upx0Sect->getSecSeg()->getIndex() + 1, _newPeFile->peHeader().getVirtualAddress(_upx0Sect->getSecSeg()->getIndex() + 1) + diff);
		_newPeFile->peHeader().setVirtualSize(_upx0Sect->getSecSeg()->getIndex() + 1, _newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex() + 1) - diff);
		_newPeFile->peHeader().setPointerToRawData(_upx0Sect->getSecSeg()->getIndex() + 1, _newPeFile->peHeader().getPointerToRawData(_upx0Sect->getSecSeg()->getIndex() + 1) + diff);
		_newPeFile->peHeader().setSizeOfRawData(_upx0Sect->getSecSeg()->getIndex() + 1, _newPeFile->peHeader().getSizeOfRawData(_upx0Sect->getSecSeg()->getIndex() + 1) - diff);
	}

	// Remove UPX1 section
	unsigned long long upx1Size = _file->getEpSegment()->getSize();
	_rvaShift = upx1Size;

	// Not every file has UPX2 section
	if (_file->getSegment(_file->getEpSegment()->getSecSeg()->getIndex() + 1) != nullptr)
	{
		unsigned long long upx2Size = _file->getSegment(_file->getEpSegment()->getSecSeg()->getIndex() + 1)->getSize();
		_rvaShift += upx2Size;

		_newPeFile->peHeader().removeSection(_file->getEpSegment()->getSecSeg()->getIndex() + 1);
	}

	_newPeFile->peHeader().removeSection(_file->getEpSegment()->getSecSeg()->getIndex());
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());
}

/**
 * Parses the extra data from the tail of the unpacked data. There are data such as offset to original PE header,
 * offset to import hints, offset to relocations hints and lot more we don't use recently.
 *
 * @param unpackedData The unpacked data.
 * @param originalHeader Buffer where to write original PE header.
 *
 * @return @ref UpxExtraData structure.
 */
template <int bits> UpxExtraData PeUpxStub<bits>::parseExtraData(retdec::unpacker::DynamicBuffer& unpackedData, retdec::unpacker::DynamicBuffer& originalHeader)
{
	// First we need to find original PE header. If we have metadata, we can easily find it using unpacked data size.
	// However, if we don't have, we need to use heuristic that looks in the last 1024 bytes (should be more than enough)
	// of the unpacked data and try to find PE header signature.
	std::uint32_t originalHeaderOffset = 0;
	if (getUpxMetadata()->isDefined())
	{
		originalHeaderOffset = unpackedData.read<std::uint32_t>(getUpxMetadata()->getUnpackedDataSize() - 4);

		// Check whether metadata are OK
		if (unpackedData.read<std::uint32_t>(originalHeaderOffset) != PeLib::PELIB_IMAGE_NT_SIGNATURE)
			originalHeaderOffset = 0;

		// Check if we found PE header magic
		if (unpackedData.read<std::uint16_t>(originalHeaderOffset + sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + PeLib::PELIB_IMAGE_FILE_HEADER::size())
				!= PeUpxStubTraits<bits>::HeaderMagic)
			originalHeaderOffset = 0;
	}

	// If metadata aren't present or they are bogus, we need to look for PE signature in unpacked data
	if (originalHeaderOffset == 0)
	{
		for (std::uint32_t i = unpackedData.getRealDataSize(); i > 0; --i)
		{
			// Check if we found PE header signature
			if (unpackedData.read<std::uint32_t>(i) != PeLib::PELIB_IMAGE_NT_SIGNATURE)
				continue;

			// Check if we found PE header magic
			if (unpackedData.read<std::uint16_t>(i + sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + PeLib::PELIB_IMAGE_FILE_HEADER::size())
					!= PeUpxStubTraits<bits>::HeaderMagic)
				continue;

			originalHeaderOffset = i;
			break;
		}
	}

	// No original PE header found
	if (originalHeaderOffset == 0)
		throw OriginalHeaderNotFoundException();

	// No signature present
	if (unpackedData.read<std::uint32_t>(originalHeaderOffset) != PeLib::PELIB_IMAGE_NT_SIGNATURE)
		throw OriginalHeaderCorruptedException();

	// Check if we found PE header magic
	if (unpackedData.read<std::uint16_t>(originalHeaderOffset + sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + PeLib::PELIB_IMAGE_FILE_HEADER::size())
			!= PeUpxStubTraits<bits>::HeaderMagic)
		throw OriginalHeaderCorruptedException();

	std::uint16_t numberOfSections = unpackedData.read<std::uint16_t>(originalHeaderOffset + sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + 0x2);
	std::uint32_t numberOfDirectories = unpackedData.read<std::uint32_t>(originalHeaderOffset + PeUpxStubTraits<bits>::NumberOfRvaAndSizesOffset);
	std::uint32_t dataDirectoriesStart = sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + PeLib::PELIB_IMAGE_FILE_HEADER::size() + PeLib::PELIB_IMAGE_OPTIONAL_HEADER<bits>::size();
	std::uint32_t sectionHeadersStart = dataDirectoriesStart + numberOfDirectories * PeLib::PELIB_IMAGE_DATA_DIRECTORY::size();
	std::uint32_t sectionHeadersEnd = sectionHeadersStart + PeLib::PELIB_IMAGE_SECTION_HEADER::size() * numberOfSections;

	// Check overflow
	if (originalHeaderOffset + sectionHeadersEnd < originalHeaderOffset)
		throw OriginalHeaderCorruptedException();

	// Check if there is enough space in the unpacked data
	if (originalHeaderOffset + sectionHeadersEnd >= unpackedData.getRealDataSize())
		throw OriginalHeaderCorruptedException();

	originalHeader = DynamicBuffer(unpackedData, originalHeaderOffset, sectionHeadersEnd);
	upx_plugin->log("Original header found at address 0x", std::hex, originalHeaderOffset, std::dec, " in extra data.");

	// Extra data starts right after original PE header
	std::uint32_t upxExtraDataOffset = originalHeaderOffset + sectionHeadersEnd;
	UpxExtraData extraData;
	extraData.setOriginalHeaderOffset(originalHeaderOffset);

	// If RVA in imports directory is set
	std::uint32_t importsRva = originalHeader.read<std::uint32_t>(dataDirectoriesStart + PeLib::PELIB_IMAGE_DATA_DIRECTORY::size() * PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsRva != 0)
	{
		extraData.setImportsOffset(unpackedData.read<std::uint32_t>(upxExtraDataOffset));
		upxExtraDataOffset += 8;
		upx_plugin->log("Import hints address 0x", std::hex, extraData.getImportsOffset(), std::dec, " found in extra data.");
	}

	// If RVA in relocations directory is set (relocs RVA and size must be non-zero and RELOCS_STRIPPED flag cannot be set)
	std::uint32_t fileCharacteristicsOffset = sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + 18;
	std::uint32_t relocsDir = dataDirectoriesStart + PeLib::PELIB_IMAGE_DATA_DIRECTORY::size() * PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC;
	std::uint32_t relocsRva = originalHeader.read<std::uint32_t>(relocsDir);
	std::uint32_t relocsSize = originalHeader.read<std::uint32_t>(relocsDir + 4);
	if ((relocsRva != 0) && (relocsSize != 0) && ((originalHeader.read<std::uint16_t>(fileCharacteristicsOffset) & PeLib::PELIB_IMAGE_FILE_RELOCS_STRIPPED) == 0))
	{
		extraData.setRelocationsOffset(unpackedData.read<std::uint32_t>(upxExtraDataOffset));
		extraData.setRelocationsBigEndian(unpackedData.read<std::uint8_t>(upxExtraDataOffset + 4));
		upxExtraDataOffset += 5;
		upx_plugin->log("Relocations hints address 0x", std::hex, extraData.getRelocationsOffset(), std::dec, " found in extra data.");
	}

	return extraData;
}

/**
 * Fixes certain attributes in PE header.
 *
 * @param originalHeader Original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixPeHeader(const DynamicBuffer& originalHeader)
{
	// SizeOfCode and BaseOfCode define the range where to unfilter the unpacked data, so we will need it
	std::uint32_t sizeOfCode = originalHeader.read<std::uint32_t>(sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + PeLib::PELIB_IMAGE_FILE_HEADER::size() + 0x04);
	std::uint32_t baseOfCode = originalHeader.read<std::uint32_t>(sizeof(PeLib::PELIB_IMAGE_NT_SIGNATURE) + PeLib::PELIB_IMAGE_FILE_HEADER::size() + 0x14);

	_newPeFile->peHeader().setSizeOfCode(sizeOfCode);
	_newPeFile->peHeader().setBaseOfCode(baseOfCode);
}

/**
 * Performs unfiltering of unpacked data.
 *
 * @param unpackedData The unpacked data.
 */
template <int bits> void PeUpxStub<bits>::unfilterData(DynamicBuffer& unpackedData)
{
	std::uint32_t startOffset = _newPeFile->peHeader().getBaseOfCode() - _newPeFile->peHeader().getVirtualAddress(0);
	std::uint32_t size = _newPeFile->peHeader().getSizeOfCode();

	if (!Unfilter::run(unpackedData, _filterId, _filterParam, _filterCount, startOffset, size))
		throw UnsupportedFilterException(_filterId);
}

/**
 * Performs the import fixing based on the hints data and the packed file ILT (Import Lookup Table).
 *
 * @param unpackedData The unpacked data with hints.
 * @param extraData @ref UpxExtraData structure.
 * @param ilt ILT of the packed file.
 */
template <int bits> void PeUpxStub<bits>::fixImports(const DynamicBuffer& unpackedData, const UpxExtraData& extraData, const DynamicBuffer& ilt)
{
	if (extraData.getImportsOffset() == 0)
	{
		_newPeFile->peHeader().setIddImportRva(0);
		_newPeFile->peHeader().setIddImportSize(0);
		return;
	}

	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_IAT) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	if (unpackedData.getRealDataSize() <= extraData.getImportsOffset())
		throw InvalidDataDirectoryException("Imports");

	DynamicBuffer importHints = DynamicBuffer(unpackedData, extraData.getImportsOffset(), unpackedData.getRealDataSize() - extraData.getImportsOffset());

	// UPX leaves the slightly populated ILT (one symbol per library to know what libraries it is going to fix)
	// Imports are stored in the following way
	// 1st 4 bytes are offset to the ILT for the library name we are going to repair
	// 2nd 4 bytes are FirstThunk to IAT which is in UPX0 section
	// Then the individual symbols are stored sequentially
	std::uint32_t readPos = 4;
	std::uint32_t iltOffset = importHints.read<std::uint32_t>(0);
	std::uint32_t lowestFirstThunk = std::numeric_limits<std::uint32_t>::max();

	// ILT offset 0 means end of import hints
	while (iltOffset != 0)
	{
		// ILT is read for the library name
		std::string libraryName = ilt.readString(iltOffset);

		std::uint32_t firstThunk = importHints.read<std::uint32_t>(readPos) + _newPeFile->peHeader().getVirtualAddress(_upx0Sect->getSecSeg()->getIndex());
		lowestFirstThunk = std::min(lowestFirstThunk, firstThunk);
		readPos += 4;

		// There is some kind of 1 byte "hint"
		// Recognizes between import by name and by ordinal
		// Hint 0 means end of the symbols in this library
		std::uint8_t hint;
		while ((hint = importHints.read<std::uint8_t>(readPos++)) != 0)
		{
			// Import by name
			if (hint < 0x80)
			{
				std::string symbolName = importHints.readString(readPos);
				_newPeFile->impDir().addFunction(libraryName, symbolName);
				readPos += static_cast<std::uint32_t>(symbolName.length() + 1);
			}
			// Import by ordinal
			else
			{
				std::uint16_t ordinal = importHints.read<std::uint16_t>(readPos);
				_newPeFile->impDir().addFunction(libraryName, ordinal);
				readPos += 2;
			}
		}

		// Sets the proper FirstThunk for new record in import directory
		if (_newPeFile->impDir().getFileIndex(libraryName, PeLib::NEWDIR) != static_cast<std::uint32_t>(-1))
			_newPeFile->impDir().setFirstThunk(_newPeFile->impDir().getFileIndex(libraryName, PeLib::NEWDIR), PeLib::NEWDIR, firstThunk);

		iltOffset = importHints.read<std::uint32_t>(readPos);
		readPos += 4;
	}

	// Align the size of the impots to the file alignment to properly create the new section
	std::uint32_t importSectSize = retdec::utils::alignUp(_newPeFile->impDir().size(), _newPeFile->peHeader().getFileAlignment());

	// Create the .imports section after all other sections with the ILT
	_newPeFile->peHeader().addSection("gu_idata", importSectSize);
	_newPeFile->peHeader().setCharacteristics(_newPeFile->peHeader().calcNumberOfSections() - 1, PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA);
	_newPeFile->peHeader().setIddImportRva(_newPeFile->peHeader().getVirtualAddress(_newPeFile->peHeader().calcNumberOfSections() - 1));
	_newPeFile->peHeader().setIddImportSize(importSectSize);
	_newPeFile->peHeader().setIddIatRva(lowestFirstThunk);
	_newPeFile->peHeader().setIddIatSize(4); // @todo Probably set proper size???
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());
}

/**
 * Performs fixing of relocations. Relocations are not fixed by reconstruction of relocation directory. Instead, they are fixed
 * "in-place" and the file is marked as "RELOCS_STRIPPED". This tells the loader not to relocate the image base of the file at all.
 * Data from hints are used to fix them.
 *
 * @todo Properly fix relocations by reloc directory reconstruction.
 *
 * @param unpackedData The unpacked data.
 * @param extraData @ref UpxExtraData structure.
 */
template <int bits> void PeUpxStub<bits>::fixRelocations(DynamicBuffer& unpackedData, const UpxExtraData& extraData)
{
	if (extraData.getRelocationsOffset() == 0)
		return;

	if (unpackedData.getRealDataSize() <= extraData.getRelocationsOffset())
		throw InvalidDataDirectoryException("Relocations");

	DynamicBuffer relocHints = DynamicBuffer(unpackedData, extraData.getRelocationsOffset(), unpackedData.getRealDataSize() - extraData.getRelocationsOffset());

	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	// We will solve relocations in place, so all relocations will be fixed statically and app will be marked as RELOCS_STRIPPED
	// This way, it is not going to be relocated and we don't have to repair the whole reloc directory
	_newPeFile->peHeader().setCharacteristics(_newPeFile->peHeader().getCharacteristics() | PeLib::PELIB_IMAGE_FILE_RELOCS_STRIPPED);
	_newPeFile->peHeader().setIddBaseRelocRva(0);
	_newPeFile->peHeader().setIddBaseRelocSize(0);
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	std::uint32_t readPos = 0;
	std::uint32_t hint;
	std::int64_t addr = -4;
	while ((hint = relocHints.read<std::uint8_t>(readPos++)) != 0)
	{
		if (hint > 0xEF)
		{
			hint = ((hint & 0x0F) << 0x10) | relocHints.read<std::uint16_t>(readPos);
			readPos += 2;
		}

		addr += hint;
		std::uint32_t relocAddr = unpackedData.read<std::uint32_t>(addr, extraData.areRelocationsBigEndian() ? Endianness::BIG : unpackedData.getEndianness());

		// Add virtual address base of unpacked data section to get the absolute address
		relocAddr += _newPeFile->peHeader().getImageBase() + _newPeFile->peHeader().getVirtualAddress(_upx0Sect->getSecSeg()->getIndex());

		// Rewrite the relocated address
		unpackedData.write<std::uint32_t>(relocAddr, addr);
	}
}

/**
 * Performs fixing of TLS directory using original PE header.
 * TLS directory data are already in the unpacked data, only directory RVA and size needs to be fixed.
 *
 * @param originalHeader The original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixTls(const DynamicBuffer& originalHeader)
{
	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_TLS) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	// Read original TLS data directory
	std::uint32_t tlsRva = originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::TlsDirectoryRvaOffset);
	std::uint32_t tlsSize = originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::TlsDirectorySizeOffset);

	_newPeFile->peHeader().setIddTlsRva(tlsRva);
	_newPeFile->peHeader().setIddTlsSize(tlsSize);

	if (tlsRva == 0)
		return;

	if (tlsRva >= _newPeFile->peHeader().getSizeOfImage())
		throw InvalidDataDirectoryException("TLS");

	upx_plugin->log("Original TLS directory found at RVA 0x", std::hex, tlsRva, " with size 0x", tlsSize, std::dec, ".");
}

/**
 * Performs fixing of OEP based on the value in original PE header.
 *
 * @param originalHeader The original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixOep(const DynamicBuffer& originalHeader)
{
	// At the oepOffset is operand of JMP instruction, so the address is relative to the jump instruction
	// We need to take the address of the JMP instruction + its size and add this relative address
	// Everything needs to be calculated in virtual addresses, not RVAs since we don't want to get into negative numbers
	_newPeFile->peHeader().setAddressOfEntryPoint(originalHeader.read<std::uint32_t>(0x28));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	upx_plugin->log("Original entry point address set to 0x", std::hex, _newPeFile->peHeader().getAddressOfEntryPoint(), std::dec, ".");
}

/**
 * Performs fixing of exports directory using original PE header. This directory is used especially by DLLs.
 * Export directory data are already in the unpacked data, only directory RVA and size needs to be fixed.
 *
 * @param originalHeader The original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixExports(const retdec::unpacker::DynamicBuffer& originalHeader)
{
	// Assumption is that exports are compressed
	_exportsCompressed = true;

	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	// Read original exports data directory
	std::uint32_t exportsRva = std::min(originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::ExportsDirectoryRvaOffset), _newPeFile->peHeader().getIddExportRva());
	std::uint32_t exportsSize = std::min(originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::ExportsDirectorySizeOffset), _newPeFile->peHeader().getIddExportSize());
	std::uint32_t oldExportsRva =_newPeFile->peHeader().getIddExportRva();

	// Set proper RVA and size for export directory
	_newPeFile->peHeader().setIddExportRva(exportsRva);
	_newPeFile->peHeader().setIddExportSize(exportsSize);

	if ((exportsRva == 0) || (exportsRva == oldExportsRva))
		return;

	// If we got here, we know that exports are not compressed
	_exportsCompressed = false;

	if (exportsRva >= _newPeFile->peHeader().getSizeOfImage())
		throw InvalidDataDirectoryException("Exports");

	upx_plugin->log("Original exports directory found at RVA 0x", std::hex, exportsRva, " with size 0x", exportsSize, std::dec, ".");

	// Calculate the offset of exports in UPX2 section
	std::uint32_t exportsVa = _newPeFile->peHeader().rvaToVa(oldExportsRva);
	const retdec::loader::Segment* exportsSection = _file->getSegmentFromAddress(exportsVa);
	if (exportsSection == nullptr)
		throw InvalidDataDirectoryException("Exports");

	std::uint32_t exportsOffset = exportsVa - exportsSection->getAddress();

	// Load export data into buffer
	std::vector<std::uint8_t> exportsDataBytes;
	exportsSection->getBytes(exportsDataBytes, exportsOffset, exportsSection->getSize() - exportsOffset);
	DynamicBuffer exportsData(exportsDataBytes, _file->getFileFormat()->getEndianness());

	if (PeLib::PELIB_IMAGE_EXPORT_DIRECTORY::size() >= exportsData.getRealDataSize())
		throw InvalidDataDirectoryException("Exports");

	// Load export directory information
	_newPeFile->expDir().setCharacteristics(exportsData.read<std::uint32_t>(0));
	_newPeFile->expDir().setTimeDateStamp(exportsData.read<std::uint32_t>(4));
	_newPeFile->expDir().setMajorVersion(exportsData.read<std::uint16_t>(8));
	_newPeFile->expDir().setMinorVersion(exportsData.read<std::uint16_t>(10));
	_newPeFile->expDir().setName(0); // This value doesn't matter, PeLib will put it into its own position
	_newPeFile->expDir().setBase(exportsData.read<std::uint32_t>(16));
	_newPeFile->expDir().setNumberOfFunctions(exportsData.read<std::uint32_t>(20));
	_newPeFile->expDir().setNumberOfNames(exportsData.read<std::uint32_t>(24));
	_newPeFile->expDir().setAddressOfFunctions(0); // This value doesn't matter, PeLib will put it into its own position
	_newPeFile->expDir().setAddressOfNames(0); // This value doesn't matter, PeLib will put it into its own position
	_newPeFile->expDir().setAddressOfNameOrdinals(0); // This value doesn't matter, PeLib will put it into its own position

	// Load the export directory name (this is usually library name)
	std::uint32_t exportsNameOffset = _newPeFile->peHeader().rvaToVa(exportsData.read<std::uint32_t>(12)) - exportsSection->getAddress() - exportsOffset;
	_newPeFile->expDir().setNameString(exportsData.readString(exportsNameOffset));

	// Calculate the offset of function addresses, function names and ordinals
	std::uint32_t exportsAddressesOffset = _newPeFile->peHeader().rvaToVa(exportsData.read<std::uint32_t>(28)) - exportsSection->getAddress() - exportsOffset;
	std::uint32_t exportsNamesOffset = _newPeFile->peHeader().rvaToVa(exportsData.read<std::uint32_t>(32)) - exportsSection->getAddress() - exportsOffset;
	std::uint32_t exportsOrdinalsOffset = _newPeFile->peHeader().rvaToVa(exportsData.read<std::uint32_t>(36)) - exportsSection->getAddress() - exportsOffset;
	for (std::uint32_t i = 0; i < _newPeFile->expDir().getNumberOfFunctions(); ++i)
	{
		if (exportsNamesOffset + i * 4 >= exportsData.getRealDataSize())
			throw InvalidDataDirectoryException("Exports");

		// Calculate the offset of name
		std::uint32_t nameOffset = _newPeFile->peHeader().rvaToVa(exportsData.read<std::uint32_t>(exportsNamesOffset + i * 4)) - exportsSection->getAddress() - exportsOffset;

		if (nameOffset >= exportsData.getRealDataSize())
			throw InvalidDataDirectoryException("Exports");

		std::string name = exportsData.readString(nameOffset);

		if ((exportsAddressesOffset + i * 4 >= exportsData.getRealDataSize()) || (exportsOrdinalsOffset + i * 2 >= exportsData.getRealDataSize()))
			throw InvalidDataDirectoryException("Exports");

		// Add function into directory and set proper ordinal
		_newPeFile->expDir().addFunction(name, exportsData.read<std::uint32_t>(exportsAddressesOffset + i * 4));
		_newPeFile->expDir().setFunctionOrdinal(i, exportsData.read<std::uint16_t>(exportsOrdinalsOffset + i * 2));
	}
}

/**
 * Performs fixing of Load Configuration directory using original PE header. This directory is used especially by MSVC compiler for security cookie.
 * Load configuration directory data are already in the unpacked data, only directory RVA and size needs to be fixed.
 *
 * @param originalHeader The original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixLoadConfiguration(const DynamicBuffer& originalHeader)
{
	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	// Read original Load Configuration data directory
	std::uint32_t loadConfigRva = originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::LoadConfigDirectoryRvaOffset);
	std::uint32_t loadConfigSize = originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::LoadConfigDirectorySizeOffset);

	_newPeFile->peHeader().setIddLoadConfigRva(loadConfigRva);
	_newPeFile->peHeader().setIddLoadConfigSize(loadConfigSize);

	if (loadConfigRva == 0)
		return;

	if (loadConfigRva >= _newPeFile->peHeader().getSizeOfImage())
		throw InvalidDataDirectoryException("Load configuration");

	upx_plugin->log("Original load configuration directory found at RVA 0x", std::hex, loadConfigRva, " with size 0x", loadConfigSize, std::dec, ".");
}

/**
 * Performs fixing of resources. Resources are very specific part of UPX since they can be either packed and unpacked simultaneously.
 * The section UPX2 is usually renamed to rsrc and is populated with the new resource directory. The tree structure of the resources is mantained across
 * the original and the packed file. Icons, manifest, version info etc. are not packed. They are put into new rsrc section. Resources that are packed are
 * kept in its original place, so can be found in the unpacked data. This method builds the new resource tree combining the packed and non-packed resources.
 *
 * @param unpackedData The unpacked data.
 * @param originalHeader The original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixResources(const DynamicBuffer& unpackedData, const DynamicBuffer& originalHeader)
{
	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	// Check whether file contains resources
	std::uint32_t uncompressedRsrcRva = _newPeFile->peHeader().getIddResourceRva();
	std::uint32_t uncompressedRsrcSize = _newPeFile->peHeader().getIddResourceSize();
	if (uncompressedRsrcRva == 0)
		return;

	// Read original resources directory
	std::uint32_t compressedRsrcRva = originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::RsrcsDirectoryRvaOffset);
	std::uint32_t compressedRsrcSize = std::max(uncompressedRsrcSize, originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::RsrcsDirectorySizeOffset));

	// AVG Samples: There are cases when resource directory RVA is 0, but the binary can still be unpacked by copying uncompressed rsrc RVA
	if (compressedRsrcRva == 0)
		compressedRsrcRva = uncompressedRsrcRva - _rvaShift;

	if (compressedRsrcRva >= _newPeFile->peHeader().getSizeOfImage())
		throw InvalidDataDirectoryException("Resources");

	upx_plugin->log("Original resources directory found at RVA 0x", std::hex, compressedRsrcRva, " with size 0x", compressedRsrcSize, std::dec, ".");

	unsigned long long imageBase = _file->getBaseAddress();

	// Read the contents of the resources
	std::vector<std::uint8_t> uncompressedRsrcsBytes;
	const retdec::loader::Segment* sect = _file->getSegmentFromAddress(uncompressedRsrcRva + imageBase);
	if (sect == nullptr)
		throw InvalidDataDirectoryException("Resources");

	sect->getBytes(uncompressedRsrcsBytes, 0, sect->getSize());
	DynamicBuffer uncompressedRsrcs(uncompressedRsrcsBytes, _file->getFileFormat()->getEndianness());

	std::unordered_set<std::uint32_t> visitedNodes;
	loadResources(_newPeFile->resDir().getRoot(), 0, uncompressedRsrcRva, compressedRsrcRva, uncompressedRsrcs, unpackedData, visitedNodes);

	_newPeFile->peHeader().addSection("gu_rsrcs", _newPeFile->peHeader().getSectionAlignment());
	_newPeFile->peHeader().setCharacteristics(_newPeFile->peHeader().calcNumberOfSections() - 1, PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA);

	// After we have loaded resources, we need to set proper addresses
	// The reason for this is that some samples can have overlapped compressed and uncompressed resources (their RVAs)
	// Instead of just finding conflicts and moving nodes around in the resource tree, it is much more easier for us to just
	//    simulate writing of the resource tree and calculate new offsets for every single node
	std::uint32_t newRsrcRva = _newPeFile->peHeader().getVirtualAddress(_newPeFile->peHeader().calcNumberOfSections() - 1);
	std::uint32_t newRsrcSize = 0;
	_newPeFile->resDir().recalculate(newRsrcSize, newRsrcRva);

	_newPeFile->peHeader().enlargeLastSection(newRsrcSize);
	_newPeFile->peHeader().setIddResourceRva(newRsrcRva);
	_newPeFile->peHeader().setIddResourceSize(newRsrcRva);
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());
}

/**
 * Performs the section header fixing using original PE header. The section UPX0 is divided into smaller sections based on the section
 * headers in the original PE header.
 *
 * @param originalHeader The original PE header.
 */
template <int bits> void PeUpxStub<bits>::fixSectionHeaders(const DynamicBuffer& originalHeader)
{
	std::uint16_t numberOfSections = originalHeader.read<std::uint16_t>(6);
	std::uint32_t numberOfDirectories = originalHeader.read<std::uint32_t>(PeUpxStubTraits<bits>::NumberOfRvaAndSizesOffset);
	std::uint32_t sectionHeadersOffset = PeUpxStubTraits<bits>::ExportsDirectoryRvaOffset + numberOfDirectories * 8;
	std::uint32_t sectionHeadersEnd = sectionHeadersOffset + PeLib::PELIB_IMAGE_SECTION_HEADER::size() * numberOfSections;

	std::uint32_t readPos = sectionHeadersOffset;
	std::vector<PeLib::PELIB_IMAGE_SECTION_HEADER> newSectionHeaders;
	while (readPos < sectionHeadersEnd)
	{
		// If there is not enough data for section header from readPos, this is not valid section header and just end
		if (readPos + PeLib::PELIB_IMAGE_SECTION_HEADER::size() > originalHeader.getRealDataSize())
			break;

		PeLib::PELIB_IMAGE_SECTION_HEADER newSectionHeader;

		// Parse the information about the section
		std::string sectionName = originalHeader.readString(readPos, PeLib::PELIB_IMAGE_SIZEOF_SHORT_NAME);
		// PE section names should have a fixed size of PELIB_IMAGE_SIZEOF_SHORT_NAME bytes.
		// However, for safety reasons, ensure that there are that many bytes. If not,
		// copy just what is available so we do not overflow the buffer.
		const auto sectionNameSize = std::min(
			static_cast<std::string::size_type>(PeLib::PELIB_IMAGE_SIZEOF_SHORT_NAME),
			sectionName.size()
		);
		std::memcpy(newSectionHeader.Name, sectionName.data(), sectionNameSize);

		// Other information about the sections are not needed so we will just skip them
		newSectionHeader.VirtualSize        = originalHeader.read<std::uint32_t>(readPos + 8);
		newSectionHeader.SizeOfRawData      = originalHeader.read<std::uint32_t>(readPos + 16);
		newSectionHeader.Characteristics    = originalHeader.read<std::uint32_t>(readPos + 36);
		readPos += PeLib::PELIB_IMAGE_SECTION_HEADER::size();
		newSectionHeaders.push_back(newSectionHeader);
	}

	// If we didn't read all sections, original header must have been corrupted
	if (newSectionHeaders.size() != numberOfSections)
		throw OriginalHeaderCorruptedException();

	// The UPX0 section consists of all the section that were parsed
	// We split it at the VirtualSize offset of every section and set the proper name
	if (!newSectionHeaders.empty())
	{
		for (std::uint32_t index = 0; index < newSectionHeaders.size() - 1; ++index)
		{
			// Remove the executable flag from all sections that has size of raw data of 0 in original header
			// These sections are probably BSS sections and shouldn't be passed into decompiler as executable
			if (newSectionHeaders[index].SizeOfRawData == 0)
				newSectionHeaders[index].Characteristics &= ~(PeLib::PELIB_IMAGE_SCN_CNT_CODE | PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE);

			std::string prevSectName = std::string(reinterpret_cast<char*>(newSectionHeaders[index].Name), PeLib::PELIB_IMAGE_SIZEOF_SHORT_NAME);
			std::string nextSectName = std::string(reinterpret_cast<char*>(newSectionHeaders[index + 1].Name), PeLib::PELIB_IMAGE_SIZEOF_SHORT_NAME);

			// Align the size to the section alignment, since we have to split at the multiples of section alignment
			std::uint32_t splitOffset = newSectionHeaders[index].VirtualSize & ~(_newPeFile->peHeader().getSectionAlignment() - 1);
			if (newSectionHeaders[index].VirtualSize & (_newPeFile->peHeader().getSectionAlignment() - 1))
				splitOffset += _newPeFile->peHeader().getSectionAlignment();

			// If split offset would make one section with 0 size, then don't split, just end
			// This solves problem if the UPX0 overlaps to UPX1 so much, that it covers some section
			if (splitOffset != _newPeFile->peHeader().getVirtualSize(_upx0Sect->getSecSeg()->getIndex() + index))
			{
				if (_newPeFile->peHeader().splitSection(_upx0Sect->getSecSeg()->getIndex() + index, prevSectName, nextSectName, splitOffset) != PeLib::ERROR_NONE)
					throw OriginalHeaderCorruptedException();
			}
			else
				_newPeFile->peHeader().setSectionName(_upx0Sect->getSecSeg()->getIndex() + index + 1, nextSectName);

			_newPeFile->peHeader().setCharacteristics(_upx0Sect->getSecSeg()->getIndex() + index, newSectionHeaders[index].Characteristics);
			_newPeFile->peHeader().setCharacteristics(_upx0Sect->getSecSeg()->getIndex() + index + 1, newSectionHeaders[index + 1].Characteristics);
			_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());
		}
	}
}

/**
 * Loads COFF symbol table if any exists into @c _coffSymbolTable attribute and sets the pointer to the
 * offset that equals to the sum of all raw sizes of the sections in the unpacked file.
 */
template <int bits> void PeUpxStub<bits>::fixCoffSymbolTable()
{
	_coffSymbolTable.clear();

	// MinGW files use COFF symbols even though it shouldn't be used for EXEs
	if (_newPeFile->peHeader().getPointerToSymbolTable() > 0) // Check whether COFF symbol table exists
	{
		upx_plugin->log("Detected COFF symbol table. Packed file may contain DWARF debug info.");

		// Calculate the starting offset of COFF symbols by calculating raw sizes of all sections in packed file
		std::uint32_t totalSectionSize = _file->getSegment(0)->getSecSeg()->getOffset();
		for (std::uint32_t i = 0; i < _file->getFileFormat()->getNumberOfSections(); ++i)
			totalSectionSize += _file->getSegment(i)->getSecSeg()->getSizeInFile();

		if (_file->getFileFormat()->getLoadedFileLength() > totalSectionSize)
		{
			// Read whole COFF symbol table
			std::ifstream inputFileHandle(_file->getFileFormat()->getPathToFile(), std::ios::binary | std::ios::in);
			retdec::utils::readFile(inputFileHandle, _coffSymbolTable, totalSectionSize, _file->getFileFormat()->getLoadedFileLength() - totalSectionSize);
			inputFileHandle.close();

			// Calculate the offset where to write COFF symbols in unpacked file by calculating raw sizes of all sections in unpacked file
			std::uint32_t newSymbolTablePointer = _newPeFile->peHeader().getPointerToRawData(0);
			for (std::uint32_t i = 0; i < _newPeFile->peHeader().calcNumberOfSections(); ++i)
				newSymbolTablePointer += _newPeFile->peHeader().getSizeOfRawData(i);

			_newPeFile->peHeader().setPointerToSymbolTable(newSymbolTablePointer);
		}
		else
			upx_plugin->log("Packed file seems to be truncated. Not copying DWARF debug info.");
	}
}

/**
 * Fixes certificate (security) directory in the unpacked file.
 */
template <int bits> void PeUpxStub<bits>::fixCertificates()
{
	// Make sure there is enough data directories
	_newPeFile->peHeader().setNumberOfRvaAndSizes(std::max(_newPeFile->peHeader().calcNumberOfRvaAndSizes(), static_cast<std::uint32_t>(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY) + 1));
	_newPeFile->peHeader().makeValid(_newPeFile->mzHeader().size());

	// Read original Load Configuration data directory
	std::uint32_t securityOffset = _newPeFile->peHeader().getIddSecurityRva();
	std::uint32_t securitySize = _newPeFile->peHeader().getIddSecuritySize();

	if (securityOffset == 0)
		return;

	upx_plugin->log("Original certificates directory found at offset 0x", std::hex, securityOffset, " with size 0x", securitySize, std::dec, ".");

	// Calculate the offset of certificates in the overlay because certificates does not always begin
	//   at the start of overlay.
	std::uint32_t offsetDist = static_cast<std::uint32_t>(securityOffset - _file->getFileFormat()->getDeclaredFileLength());

	// Certificates are always stored in the overlay, so just calculate the new offset by
	//   summing all raw sizes of sections in the unpacked files and add COFF symbol table size.
	if (securityOffset > 0)
	{
		securityOffset = offsetDist + _newPeFile->peHeader().getPointerToRawData(0);
		for (std::uint32_t i = 0; i < _newPeFile->peHeader().calcNumberOfSections(); ++i)
			securityOffset += _newPeFile->peHeader().getSizeOfRawData(i);

		securityOffset += static_cast<std::uint32_t>(_coffSymbolTable.size());
	}

	_newPeFile->peHeader().setIddSecurityRva(securityOffset);
}

/**
 * Unpacked data contains the original file content and hints for unpacking. This method separates these data
 * by erasing it from unpacked data and storing it in another buffer.
 *
 * @param unpackedData The unpacked data.
 * @param extraData @ref UpxExtraData structure.
 */
template <int bits> void PeUpxStub<bits>::cutHintsData(retdec::unpacker::DynamicBuffer& unpackedData, const UpxExtraData& extraData)
{
	// We need to find lowest possible address where we can cut the unpacked data and remove hints.
	// We always know the address of original PE header, we need to check whether import hints or reloc hints are at lower address.
	std::uint32_t cutAddress = extraData.getOriginalHeaderOffset();

	if (extraData.getImportsOffset() != 0)
		cutAddress = std::min(cutAddress, extraData.getImportsOffset());

	if (extraData.getRelocationsOffset() != 0)
		cutAddress = std::min(cutAddress, extraData.getRelocationsOffset());

	// Erase these data from the unpacked data buffer
	unpackedData.erase(cutAddress, unpackedData.getRealDataSize() - cutAddress);
}

/**
 * Saves the unpacked data to the output file.
 *
 * @param outputFile Path to the unpacked output file.
 * @param unpackedData Unpacked data to write.
 */
template <int bits> void PeUpxStub<bits>::saveFile(const std::string& outputFile, DynamicBuffer& unpackedData)
{
	// Remove the file if it already exists
	std::remove(outputFile.c_str());

	_newPeFile->mzHeader().write(outputFile, 0);
	_newPeFile->peHeader().write(outputFile, _newPeFile->mzHeader().size());
	_newPeFile->peHeader().writeSections(outputFile);

	if (_newPeFile->peHeader().getIddImportRva() != 0)
	{
		_newPeFile->impDir().write(outputFile, _newPeFile->peHeader().rvaToOffset(_newPeFile->peHeader().getIddImportRva()), _newPeFile->peHeader().getIddImportRva());

		// OrignalFirstThunk-s are known only after the impDir is written into the file
		// We then need to read it function by function and set the contents of IAT to be same as ILT
		// If it isn't, the windows loader refuses to load the executable file
		for (std::uint32_t fileIndex = 0; fileIndex < _newPeFile->impDir().getNumberOfFiles(PeLib::OLDDIR); ++fileIndex)
		{
			AddressType destOffset = _newPeFile->impDir().getFirstThunk(fileIndex, PeLib::OLDDIR) -
				_newPeFile->peHeader().getVirtualAddress(_upx0Sect->getSecSeg()->getIndex());

			for (std::uint32_t funcIndex = 0; funcIndex < _newPeFile->impDir().getNumberOfFunctions(fileIndex, PeLib::OLDDIR); ++funcIndex, destOffset += 4)
			{
				unpackedData.write<AddressType>(_newPeFile->impDir().getOriginalFirstThunk(fileIndex, funcIndex, PeLib::OLDDIR), destOffset);
			}
		}
	}

	// Write the unpacked content to the packed content section
	// Use regular file as we will write more sections at once
	std::fstream outputFileHandle(outputFile, std::ios::binary | std::ios::out | std::ios::in);
	retdec::utils::writeFile(outputFileHandle, unpackedData.getBuffer(), _newPeFile->peHeader().getPointerToRawData(_upx0Sect->getSecSeg()->getIndex()));
	// If there were COFF symbols in the original file, write them also to the new one
	if (!_coffSymbolTable.empty())
		retdec::utils::writeFile(outputFileHandle, _coffSymbolTable, _newPeFile->peHeader().getPointerToSymbolTable());
	outputFileHandle.close();

	// Write resources at the end, because they would be rewritten by unpackedData which have them zeroed
	if (_newPeFile->peHeader().getIddResourceRva() != 0)
		_newPeFile->resDir().write(outputFile, _newPeFile->peHeader().rvaToOffset(_newPeFile->peHeader().getIddResourceRva()), _newPeFile->peHeader().getIddResourceRva());

	// Write exportss at the end, because they would be rewritten by unpackedData which have them zeroed
	// Write them only when exports are not compressed
	if ((_newPeFile->peHeader().getIddExportRva() != 0) && !_exportsCompressed)
		_newPeFile->expDir().write(outputFile, _newPeFile->peHeader().rvaToOffset(_newPeFile->peHeader().getIddExportRva()), _newPeFile->peHeader().getIddExportRva());

	// Copy file overlay if any
	if (_file->getFileFormat()->getDeclaredFileLength() < _file->getFileFormat()->getLoadedFileLength())
	{
		std::uint32_t overlaySize = static_cast<std::uint32_t>(_file->getFileFormat()->getLoadedFileLength() - _file->getFileFormat()->getDeclaredFileLength());
		std::vector<std::uint8_t> overlay(overlaySize);

		upx_plugin->log("Packed file has overlay with size of 0x", std::hex, overlaySize, std::dec, " bytes. Copying into unpacked file.");

		std::fstream inputFileHandle(_file->getFileFormat()->getPathToFile(), std::ios::binary | std::ios::in);
		retdec::utils::readFile(inputFileHandle, overlay, _file->getFileFormat()->getDeclaredFileLength(), overlaySize);

		std::fstream outputFileHandle(outputFile, std::ios::binary | std::ios::out | std::ios::in);
		outputFileHandle.seekp(0, std::ios::end);
		retdec::utils::writeFile(outputFileHandle, overlay, outputFileHandle.tellp());
	}
}

/**
 * Loads all child resources from the node in the resource tree. Method is used to recursively load resources from the whole tree.
 * Leaf nodes, which point directly to data, are loaded either from unpacked data or directly from uncompressed resources.
 *
 * @param rootNode The parent node from which to load resources.
 * @param offset The offset of the current node in the resource directory.
 * @param uncompressedRsrcRva Resource directory RVA in the packed file.
 * @param compressedRsrcRva Resource directory RVA in the unpacked file/the original file.
 * @param uncompressedRsrcs The non-packed resources.
 * @param unpackedData The unpacked data.
 * @param visitedNodes The set that contains already visited nodes in resource tree to avoid stack overflow.
 */
template <int bits> void PeUpxStub<bits>::loadResources(PeLib::ResourceNode* rootNode, std::uint32_t offset, std::uint32_t uncompressedRsrcRva, std::uint32_t compressedRsrcRva,
		const DynamicBuffer& uncompressedRsrcs, const DynamicBuffer& unpackedData, std::unordered_set<std::uint32_t>& visitedNodes)
{
	std::uint32_t readPos = offset;

	if (readPos + PeLib::PELIB_IMAGE_RESOURCE_DIRECTORY::size() >= uncompressedRsrcs.getRealDataSize())
		throw InvalidDataDirectoryException("Resources");

	// Load information about the current root node
	rootNode->setCharacteristics(uncompressedRsrcs.read<std::uint32_t>(readPos));
	rootNode->setTimeDateStamp(uncompressedRsrcs.read<std::uint32_t>(readPos + 4));
	rootNode->setMajorVersion(uncompressedRsrcs.read<std::uint16_t>(readPos + 8));
	rootNode->setMinorVersion(uncompressedRsrcs.read<std::uint16_t>(readPos + 10));
	rootNode->setNumberOfNamedEntries(uncompressedRsrcs.read<std::uint16_t>(readPos + 12));
	rootNode->setNumberOfIdEntries(uncompressedRsrcs.read<std::uint16_t>(readPos + 14));
	readPos += PeLib::PELIB_IMAGE_RESOURCE_DIRECTORY::size();

	// Iterate over all children nodes
	for (std::uint32_t i = 0; i < static_cast<std::uint32_t>(rootNode->getNumberOfNamedEntries() + rootNode->getNumberOfIdEntries()); ++i)
	{
		PeLib::ResourceChild* child = rootNode->addChild();

		if (readPos + PeLib::PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size() >= uncompressedRsrcs.getRealDataSize())
			throw InvalidDataDirectoryException("Resources");

		// Load information about the directory entries
		std::uint32_t offsetToName = uncompressedRsrcs.read<std::uint32_t>(readPos);
		std::uint32_t offsetToData = uncompressedRsrcs.read<std::uint32_t>(readPos + 4);
		readPos += PeLib::PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size();

		child->setOffsetToName(offsetToName);
		child->setOffsetToData(offsetToData);

		// Check whether the name is string or just ID
		if (offsetToName & PeLib::PELIB_IMAGE_RESOURCE_NAME_IS_STRING)
		{
			// Get the real offset to the string by masking out highest bit
			std::uint32_t realOffsetToName = offsetToName & ~PeLib::PELIB_IMAGE_RESOURCE_NAME_IS_STRING;

			if (realOffsetToName >= uncompressedRsrcs.getRealDataSize())
				throw InvalidDataDirectoryException("Resources");

			// First 2 bytes are string length
			std::uint16_t nameLength = uncompressedRsrcs.read<std::uint16_t>(realOffsetToName);
			std::string name = "";

			// It is wide string, but rarely contains any unicode characters
			// We will use regular ASCII string and pretend we are reading 1-byte characters
			std::uint16_t charsRead = 0;
			while (charsRead < nameLength)
			{
				if (realOffsetToName + 2 + (charsRead << 1) >= uncompressedRsrcs.getRealDataSize())
					throw InvalidDataDirectoryException("Resources");

				name += uncompressedRsrcs.read<std::uint16_t>(realOffsetToName + 2 + (charsRead << 1));
				charsRead++;
			}

			// Associate the name
			child->setName(name);
		}

		// If the offset to data points to another directory, or it is leaf node and points directly to resource data
		if (offsetToData & PeLib::PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY)
		{
			// Get the offset to the directory by masking out the hightest bit
			std::uint32_t offsetToDirectory = offsetToData & ~PeLib::PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY;

			// Prevent stack overflow with recursion
			if (visitedNodes.find(offsetToDirectory) != visitedNodes.end())
				throw InvalidDataDirectoryException("Resources");

			PeLib::ResourceNode* node = new PeLib::ResourceNode;
			child->setNode(node);

			// Recursively call the same routine on the loaded directory
			visitedNodes.insert(offsetToDirectory);
			loadResources(node, offsetToDirectory, uncompressedRsrcRva, compressedRsrcRva, uncompressedRsrcs, unpackedData, visitedNodes);
		}
		else
		{

			// We need to determine where are data, they can be compressed on uncompressed
			// Uncompressed resources are in the packed file resources therefore they are exposed with no modification (often icons or manifest)
			// Compressed resources were left at its original position in the original file resources and were compressed, we need to look for them in uncompressed data
			PeLib::ResourceLeaf* leaf = new PeLib::ResourceLeaf;
			child->setNode(leaf);

			// Load information about the data entry
			std::uint32_t dataEntryOffset = child->getOffsetToData();
			leaf->setOffsetToData(uncompressedRsrcs.read<std::uint32_t>(dataEntryOffset));
			leaf->setSize(uncompressedRsrcs.read<std::uint32_t>(dataEntryOffset + 4));
			leaf->setCodePage(uncompressedRsrcs.read<std::uint32_t>(dataEntryOffset + 8));
			leaf->setReserved(uncompressedRsrcs.read<std::uint32_t>(dataEntryOffset + 12));

			// Original file resources will always have lesser RVA therefore we know these were packed
			std::vector<std::uint8_t> data;
			if (leaf->getOffsetToData() < uncompressedRsrcRva)
			{
				std::uint32_t dataOffset = leaf->getOffsetToData() - _newPeFile->peHeader().vaToRva(_file->getSegment(0)->getAddress());
				if (dataOffset >= unpackedData.getRealDataSize())
					throw InvalidDataDirectoryException("Resources");

				if (dataOffset + leaf->getSize() >= unpackedData.getRealDataSize())
					throw InvalidDataDirectoryException("Resources");

				data = DynamicBuffer(unpackedData, dataOffset, leaf->getSize()).getBuffer();
			}
			else
			{
				std::uint32_t dataOffset = leaf->getOffsetToData() - uncompressedRsrcRva;
				if (dataOffset >= uncompressedRsrcs.getRealDataSize())
					throw InvalidDataDirectoryException("Resources");

				if (dataOffset + leaf->getSize() >= uncompressedRsrcs.getRealDataSize())
					throw InvalidDataDirectoryException("Resources");

				data = DynamicBuffer(uncompressedRsrcs, dataOffset, leaf->getSize()).getBuffer();

				// Update offset for uncompressed resource because it is going to containg data at different position
				leaf->setOffsetToData(dataOffset + compressedRsrcRva);
			}

			leaf->setData(data);
		}
	}
}

template <int bits> std::uint8_t PeUpxStub<bits>::getPackingMethod(bool trustMetadata) const
{
	if (trustMetadata && getUpxMetadata()->isDefined())
		return getUpxMetadata()->getPackingMethod();

	switch (getVersion())
	{
		case UpxStubVersion::NRV2B:
			return UPX_PACKING_METHOD_NRV2B_LE32;
		case UpxStubVersion::NRV2D:
			return UPX_PACKING_METHOD_NRV2D_LE32;
		case UpxStubVersion::NRV2E:
			return UPX_PACKING_METHOD_NRV2E_LE32;
		case UpxStubVersion::LZMA:
			return UPX_PACKING_METHOD_LZMA;
		default:
			return 0;
	}
}

// Explicit instantiation.
template class PeUpxStub<32>;
template class PeUpxStub<64>;

} // namespace upx
} // namespace unpackertool
} // namespace retdec
