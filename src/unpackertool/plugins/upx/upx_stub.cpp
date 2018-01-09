/**
 * @file src/unpackertool/plugins/upx/upx_stub.cpp
 * @brief Implementation of abstract UPX stub class that represents the unpacking procedure itself.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/fileformat.h"
#include "unpackertool/plugins/upx/decompressors/decompressors.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/macho/macho_upx_stub.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/upx.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub.h"
#include "unpackertool/plugins/upx/upx_stub_signatures.h"
#include "retdec/unpacker/decompression/compressed_data.h"
#include "retdec/unpacker/dynamic_buffer.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

UpxMetadata::UpxMetadata() : _defined(false), _usesPackingMethod(true), _fileOffset(0), _fileSize(0), _packingMethod(0), _packedDataSize(0),
	_unpackedDataSize(0), _filterId(0), _filterParam(0) {}

UpxMetadata::UpxMetadata(const UpxMetadata& metadata) : _defined(metadata._defined), _usesPackingMethod(metadata._usesPackingMethod),
	_fileOffset(metadata._fileOffset), _fileSize(metadata._fileSize),
	_packingMethod(metadata._packingMethod), _packedDataSize(metadata._packedDataSize),
	_unpackedDataSize(metadata._unpackedDataSize), _filterId(metadata._filterId), _filterParam(metadata._filterParam) {}

UpxMetadata UpxMetadata::read(retdec::loader::Image* file)
{
	UpxMetadata metadata;

	std::vector<std::uint8_t> dataBuffer(1024);
	std::ifstream inputFile(file->getFileFormat()->getPathToFile(), std::ios::binary | std::ios::in);

	bool useChecksum = true;
	bool usePackingMethod = true;
	switch (file->getFileFormat()->getFileFormat())
	{
		// UPX metadata should be in the first 1024 bytes in PE
		case retdec::fileformat::Format::PE:
		{
			inputFile.seekg(0, std::ios::beg);
			break;
		}
		// UPX metadata should be in the last 1024 bytes in ELF
		case retdec::fileformat::Format::ELF:
		{
			// ELF does not use packing method.
			usePackingMethod = false;

			inputFile.seekg(-1024, std::ios::end);
			break;
		}
		// UPX metadata should be in the first 1024 bytes from the chosen architecture offset in Mach-O
		case retdec::fileformat::Format::MACHO:
		{
			// Mach-O does not use checksums and packing method.
			useChecksum = false;
			usePackingMethod = false;

			auto machoFormat = static_cast<retdec::fileformat::MachOFormat*>(file->getFileFormat());
			inputFile.seekg(machoFormat->getChosenArchitectureOffset(), std::ios::beg);
			break;
		}
		default:
			return metadata;
	}

	inputFile.read(reinterpret_cast<char*>(&dataBuffer[0]), 1024);
	retdec::unpacker::DynamicBuffer data(dataBuffer, file->getFileFormat()->getEndianness());

	std::string pattern = "UPX!";
	for (size_t i = 0; i < 1024 - pattern.length(); ++i)
	{
		std::string needle = data.readString(static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(pattern.length()));
		if (needle == pattern)
		{
			std::uint32_t metadataSize = UpxMetadata::getSizeOfVersion(data.read<std::uint8_t>(static_cast<std::uint32_t>(i) + 4));
			retdec::unpacker::DynamicBuffer metadataBuffer(data, static_cast<std::uint32_t>(i), metadataSize);

			// Check whether calculated checksum and checksum in header matches
			// This is the only way how we can validate the metadata
			std::uint8_t checksum = UpxMetadata::calcChecksum(metadataBuffer);
			if (useChecksum && checksum != metadataBuffer.read<std::uint8_t>(metadataSize - 1))
				continue;

			metadata.setDefined(true);
			metadata.setFileOffset(static_cast<std::uint32_t>(i));
			metadata.setFileSize(metadataSize);
			metadata.setUsesPackingMethod(usePackingMethod);
			metadata.setPackingMethod(metadataBuffer.read<std::uint8_t>(6));
			metadata.setUnpackedDataSize(metadataBuffer.read<std::uint32_t>(16));
			metadata.setPackedDataSize(metadataBuffer.read<std::uint32_t>(20));
			metadata.setFilterId(metadataBuffer.read<std::uint8_t>(28));
			metadata.setFilterParameter(metadataBuffer.read<std::uint8_t>(29));
			return metadata;
		}
	}

	return metadata;
}

uint8_t UpxMetadata::calcChecksum(const retdec::unpacker::DynamicBuffer& data)
{
	std::uint32_t sum = 0;
	for (std::uint32_t i = 4; i < data.getRealDataSize() - 1; ++i)
		sum += data.read<std::uint8_t>(i);

	return sum % 251;
}

uint32_t UpxMetadata::getSizeOfVersion(std::uint8_t version)
{
	if (version <= 3)
		return 24;
	else if (version <= 9)
		return 28;
	else
		return 32;
}

UpxStubVersion UpxMetadata::getStubVersion() const
{
	if (!usesPackingMethod())
		return UpxStubVersion::UNIVERSAL;

	switch (getPackingMethod())
	{
		case UPX_PACKING_METHOD_LZMA:
			return UpxStubVersion::LZMA;
		case UPX_PACKING_METHOD_NRV2B_8:
		case UPX_PACKING_METHOD_NRV2B_LE32:
			return UpxStubVersion::NRV2B;
		case UPX_PACKING_METHOD_NRV2D_8:
		case UPX_PACKING_METHOD_NRV2D_LE32:
			return UpxStubVersion::NRV2D;
		case UPX_PACKING_METHOD_NRV2E_8:
		case UPX_PACKING_METHOD_NRV2E_LE32:
			return UpxStubVersion::NRV2E;
		default:
			return UpxStubVersion::UNKNOWN;
	}

	return UpxStubVersion::UNKNOWN;
}

/**
 * Creates a new UPX unpacking stub object.
 *
 * @param inputFile The packed input file.
 * @param stubData The additional information about the unpacking stub.
 * @param stubCapturedData Data that were captured during the signature matching.
 * @param decompressor Associated decompressor with this unpacking stub.
 * @param metadata The UPX metadata associated with this unpacking stub.
 */
UpxStub::UpxStub(retdec::loader::Image* inputFile, const UpxStubData* stubData, const DynamicBuffer& stubCapturedData,
		std::unique_ptr<Decompressor> decompressor, const UpxMetadata& metadata)
	: UnpackingStub(inputFile), _stubData(stubData), _stubCapturedData(stubCapturedData), _decompressor(std::move(decompressor)), _metadata(metadata)
{
}

/**
 * Destructor.
 */
UpxStub::~UpxStub()
{
}

std::shared_ptr<UpxStub> UpxStub::createStub(retdec::loader::Image* file)
{
	return _createStubImpl(file, nullptr);
}

std::shared_ptr<UpxStub> UpxStub::createStub(retdec::loader::Image* file, const DynamicBuffer& stubBytes)
{
	return _createStubImpl(file, &stubBytes);
}

std::shared_ptr<UpxStub> UpxStub::_createStubImpl(retdec::loader::Image* file, const retdec::unpacker::DynamicBuffer* stubBytes)
{
	UpxMetadata metadata = UpxMetadata::read(file);

	DynamicBuffer capturedData(file->getFileFormat()->getEndianness());
	const UpxStubData* stubData = nullptr;

	if (stubBytes == nullptr)
	{
		// Throw exception only in case when metadata are not defined
		// We still might get all required info from metadata if there is no known signature
		if ((stubData = UpxStubSignatures::matchSignatures(file, capturedData)) == nullptr)
			if (!metadata.isDefined())
				throw UnsupportedStubException();
	}
	else
	{
		// Throw exception only in case when metadata are not defined
		// We still might get all required info from metadata if there is no known signature
		if ((stubData = UpxStubSignatures::matchSignatures(*stubBytes, capturedData, file->getFileFormat()->getTargetArchitecture(),
						file->getFileFormat()->getFileFormat())) == nullptr)
			if (!metadata.isDefined())
				throw UnsupportedStubException();
	}

	// Always trust signatures before metadata
	// Metadata can be bogus as they are easily modified if one knows where is checksum and how it is calculated
	UpxStubVersion version;
	if (stubData != nullptr)
		version = stubData->version;
	else
		version = metadata.getStubVersion();

	// If we already have scrambler stub and we are trying to find the stub that was scrambled
	// but we instead run into another scrambler, rather trust metadata if they are defined
	// Otherwise, end with error.
	bool isScrambler = stubBytes != nullptr;
	if (isScrambler)
	{
		if (version == UpxStubVersion::DIRECT_JUMP || version == UpxStubVersion::UPXSHIT)
		{
			if (metadata.isDefined())
			{
				version = metadata.getStubVersion();
				stubData = nullptr;
			}
			else
				throw UnsupportedStubException();
		}
	}

	std::string compressionName;
	std::unique_ptr<Decompressor> decompressor = nullptr;
	switch (version)
	{
		case UpxStubVersion::LZMA:
			compressionName = "LZMA";
			decompressor = std::make_unique<DecompressorLzma>();
			break;
		case UpxStubVersion::NRV2B:
			compressionName = "NRV2B";
			decompressor = std::make_unique<DecompressorNrv>();
			break;
		case UpxStubVersion::NRV2D:
			compressionName = "NRV2D";
			decompressor = std::make_unique<DecompressorNrv>();
			break;
		case UpxStubVersion::NRV2E:
			compressionName = "NRV2E";
			decompressor = std::make_unique<DecompressorNrv>();
			break;
		case UpxStubVersion::UPXSHIT:
			compressionName = "UPX$HIT scrambler";
			decompressor = std::make_unique<DecompressorUpxshit>();
			break;
		case UpxStubVersion::DIRECT_JUMP:
			compressionName = "DIRECT JUMP scrambler";
			decompressor = std::make_unique<DecompressorDirectJump>();
			break;
		case UpxStubVersion::UNIVERSAL:
			compressionName = "universal";
			decompressor = nullptr;
			break;
		default:
			throw UnsupportedStubException();
	}

	// Just print what was source of our information
	std::string detectionBasedOn;
	if (metadata.isDefined() && stubData != nullptr)
		detectionBasedOn = "signature & metadata";
	else if (stubData != nullptr)
		detectionBasedOn = "signature";
	else if (metadata.isDefined())
		detectionBasedOn = "metadata";

	upx_plugin->log("Detected ", compressionName, " unpacking stub based on ", detectionBasedOn, ".");

	UpxStub* stub = nullptr;
	switch (file->getFileFormat()->getFileFormat())
	{
		case retdec::fileformat::Format::ELF:
		{
			if (static_cast<retdec::fileformat::ElfFormat*>(file->getFileFormat())->getElfClass() == ELFCLASS32)
				stub = new ElfUpxStub<32>(file, stubData, capturedData, std::move(decompressor), metadata);
			else
				stub = new ElfUpxStub<64>(file, stubData, capturedData, std::move(decompressor), metadata);
			break;
		}
		case retdec::fileformat::Format::PE:
		{
			if (static_cast<retdec::fileformat::PeFormat*>(file->getFileFormat())->getPeClass() == PeLib::PEFILE32)
				stub = new PeUpxStub<32>(file, stubData, capturedData, std::move(decompressor), metadata);
			else
				stub = new PeUpxStub<64>(file, stubData, capturedData, std::move(decompressor), metadata);
			break;
		}
		case retdec::fileformat::Format::MACHO:
		{
			if (static_cast<retdec::fileformat::MachOFormat*>(file->getFileFormat())->is32Bit())
				stub = new MachOUpxStub<32>(file, stubData, capturedData, std::move(decompressor), metadata);
			else
				stub = new MachOUpxStub<64>(file, stubData, capturedData, std::move(decompressor), metadata);
			break;
		}
		case retdec::fileformat::Format::COFF:
		case retdec::fileformat::Format::UNKNOWN:
		case retdec::fileformat::Format::UNDETECTABLE:
		default:
			throw UnsupportedFileException();
	}

	return std::shared_ptr<UpxStub>(stub);
}

/**
 * Returns a @ref UpxStubData containg all the information about this stub.
 *
 * @return UPX unpacking stab data.
 */
const UpxStubData* UpxStub::getStubData() const
{
	return _stubData;
}

/**
 * Returns a version of this UPX unpacking stub.
 *
 * @return UPX unpacking stub version.
 */
UpxStubVersion UpxStub::getVersion() const
{
	if (getStubData() != nullptr)
		return getStubData()->version;

	if (getUpxMetadata()->isDefined())
		return getUpxMetadata()->getStubVersion();

	return UpxStubVersion::UNKNOWN;
}

/**
 * Returns the captured data that were captured during signature matching.
 *
 * @return Captured data.
 */
const DynamicBuffer* UpxStub::getStubCapturedData() const
{
	return &_stubCapturedData;
}

/**
 * Returns the decompressor associated with this stub.
 *
 * @return Decompressor.
 */
Decompressor* UpxStub::getDecompressor() const
{
	return _decompressor.get();
}

/**
 * Returns the UPX metadata aka UPX packheader.
 *
 * @return UPX metadata.
 */
const UpxMetadata* UpxStub::getUpxMetadata() const
{
	return &_metadata;
}

void UpxStub::setStubData(const UpxStubData* stubData)
{
	_stubData = stubData;
}

void UpxStub::setStubCapturedData(const retdec::unpacker::DynamicBuffer& stubCapturedData)
{
	_stubCapturedData = stubCapturedData;
}

/**
 * Returns the EP address of the packed input file. This method shouldn't be overridden until
 * you really want to change the way EP address is being parsed. You may override this in case of
 * UPX scramblers. Their real EP address lies somewhere else than the file EP address is set to.
 *
 * @return Entry point address.
 */
uint32_t UpxStub::getRealEpAddress() const
{
	unsigned long long ep;
	_file->getFileFormat()->getEpAddress(ep);
	return ep;
}

std::unique_ptr<Decompressor> UpxStub::decodePackingMethod(std::uint8_t packingMethod) const
{
	switch (packingMethod)
	{
		case UPX_PACKING_METHOD_LZMA:
			return std::make_unique<DecompressorLzma>();
		case UPX_PACKING_METHOD_NRV2B_8:
		case UPX_PACKING_METHOD_NRV2B_LE32:
		case UPX_PACKING_METHOD_NRV2D_8:
		case UPX_PACKING_METHOD_NRV2D_LE32:
		case UPX_PACKING_METHOD_NRV2E_8:
		case UPX_PACKING_METHOD_NRV2E_LE32:
			return std::make_unique<DecompressorNrv>();
		default:
			throw UnsupportedPackingMethodException(packingMethod);
	}
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
