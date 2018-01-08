/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_direct_jump.cpp
 * @brief Implementation of UPX scrambler with direct jump decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdlib>
#include <vector>

#include "unpackertool/plugins/upx/decompressors/decompressor_direct_jump.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub.h"
#include "unpackertool/plugins/upx/upx_stub_signatures.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Constructor.
 */
DecompressorDirectJump::DecompressorDirectJump()
{
}

/**
 * Destructor.
 */
DecompressorDirectJump::~DecompressorDirectJump()
{
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorDirectJump::readUnpackingStub(PeUpxStub<32>* stub, DynamicBuffer& unpackingStub)
{
	// We just need to load the EIP-dependant offset from JMP instruction and calculate UPX EP
	std::int32_t upxEpDist = stub->getStubCapturedData()->read<std::int32_t>(0);
	std::uint32_t upxEpAddress = stub->getRealEpAddress() + upxEpDist + 5; // 5 is size of JMP instruction
	std::uint32_t upxEpOffset = upxEpAddress - stub->getFile()->getEpSegment()->getAddress();

	// We don't know exact stub size, so we use the only information we have and that is distance of EP and original UPX EP
	// If distance is positive, we can assume that UPX unpacking stub is somewhere between upxEpAddress and the end of the section
	// If distance is negative, we can assume that UPX unpacking stub is somewhere between upxEpAddress and upxEpAddress + std::abs(upxEpDist)
	std::uint32_t upxStubSize = 0;
	if (upxEpDist < 0)
		upxStubSize = std::abs(upxEpDist);
	else
		upxStubSize = stub->getFile()->getEpSegment()->getEndAddress() - upxEpAddress;

	std::vector<std::uint8_t> upxStubBytes;
	stub->getFile()->getEpSegment()->getBytes(upxStubBytes, upxEpOffset, upxStubSize);
	DynamicBuffer upxStub(upxStubBytes, stub->getFile()->getFileFormat()->getEndianness());

	try
	{
		_scrambledStub = UpxStub::createStub(stub->getFile(), upxStub);
	}
	catch (const UnsupportedStubException&)
	{
		throw UnsupportedStubException();
	}
	catch (const UnsupportedFileException&)
	{
		throw UnsupportedFileException();
	}

	unpackingStub = upxStub;
	stub->setStubData(_scrambledStub->getStubData());
	stub->setStubCapturedData(*_scrambledStub->getStubCapturedData());
	stub->setRealEpAddress(upxEpAddress);
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorDirectJump::readUnpackingStub(PeUpxStub<64>* stub, DynamicBuffer& unpackingStub)
{
	// We just need to load the EIP-dependant offset from JMP instruction and calculate UPX EP
	std::int32_t upxEpDist = stub->getStubCapturedData()->read<std::int32_t>(0);
	std::uint32_t upxEpAddress = stub->getRealEpAddress() + upxEpDist + 5; // 5 is size of JMP instruction
	std::uint32_t upxEpOffset = upxEpAddress - stub->getFile()->getEpSegment()->getAddress();

	// We don't know exact stub size, so we use the only information we have and that is distance of EP and original UPX EP
	// If distance is positive, we can assume that UPX unpacking stub is somewhere between upxEpAddress and the end of the section
	// If distance is negative, we can assume that UPX unpacking stub is somewhere between upxEpAddress and upxEpAddress + std::abs(upxEpDist)
	std::uint32_t upxStubSize = 0;
	if (upxEpDist < 0)
		upxStubSize = std::abs(upxEpDist);
	else
		upxStubSize = stub->getFile()->getEpSegment()->getEndAddress() - upxEpAddress;

	std::vector<std::uint8_t> upxStubBytes;
	stub->getFile()->getEpSegment()->getBytes(upxStubBytes, upxEpOffset, upxStubSize);
	DynamicBuffer upxStub(upxStubBytes, stub->getFile()->getFileFormat()->getEndianness());

	try
	{
		_scrambledStub = UpxStub::createStub(stub->getFile(), upxStub);
	}
	catch (const UnsupportedStubException&)
	{
		throw UnsupportedStubException();
	}
	catch (const UnsupportedFileException&)
	{
		throw UnsupportedFileException();
	}

	unpackingStub = upxStub;
	stub->setStubData(_scrambledStub->getStubData());
	stub->setStubCapturedData(*_scrambledStub->getStubCapturedData());
	stub->setRealEpAddress(upxEpAddress);
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
