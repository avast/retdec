/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor_upxshit.cpp
 * @brief Implementation of UPX scrambler UPX$HIT decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdlib>
#include <vector>

#include "unpackertool/plugins/upx/decompressors/decompressor_upxshit.h"
#include "unpackertool/plugins/upx/elf/elf_upx_stub.h"
#include "unpackertool/plugins/upx/pe/pe_upx_stub.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"
#include "unpackertool/plugins/upx/upx_stub.h"
#include "unpackertool/plugins/upx/upx_stub_signatures.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

Signature secondStubSignature =
{
	0xB8, CAP, CAP, CAP, CAP, // MOV EAX, <UPX unpacking stub address>
	0xB9, CAP, CAP, CAP, CAP, // MOV ECX, <Size of UPX unpacking stub>
	0x80, 0x34, 0x08, CAP, // XOR BYTE PTR [EAX+ECX], <XOR constant>
	0xE2, 0xFA, // LOOP rel -6
	0xFF, 0xE0 // JMP EAX
};

/**
 * Constructor.
 */
DecompressorUpxshit::DecompressorUpxshit()
{
}

/**
 * Destructor.
 */
DecompressorUpxshit::~DecompressorUpxshit()
{
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE32 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorUpxshit::readUnpackingStub(PeUpxStub<32>* stub, DynamicBuffer& unpackingStub)
{
	// We just need to parse XOR value and how much bytes is XORed, then read the data from EP - how much bytes are XORed
	// XOR these data, look again for XOR value and the base address and the amount of bytes XORed, this value should be UPX OEP
	// XOR again, run standard signatures again and we should have the original version

	// First load information about second stub where we can get information about original UPX unpacking stub
	std::uint32_t secondStubOffset = stub->getStubCapturedData()->read<std::uint32_t>(0) - stub->getFile()->getEpSegment()->getAddress();
	std::uint32_t secondStubSize = stub->getStubCapturedData()->read<std::uint32_t>(4);
	std::uint8_t secondStubXorValue = stub->getStubCapturedData()->read<std::uint8_t>(8);

	// Load XORed second stub
	std::vector<std::uint8_t> secondStubBytes;
	stub->getFile()->getEpSegment()->getBytes(secondStubBytes, secondStubOffset, secondStubSize);

	// XOR it back with the constant value
	DynamicBuffer secondStub(secondStubBytes, stub->getFile()->getFileFormat()->getEndianness());
	secondStub.forEachReverse([secondStubXorValue, &secondStubSize](std::uint8_t& byte) {
			// We need to use prefix decrement since this is also being done on assembly level
			if (--secondStubSize == 0)
				return;

			byte ^= secondStubXorValue;
		});

	// Match it against known signature of second UPX$HIT stub
	DynamicBuffer secondStubCapturedData(stub->getFile()->getFileFormat()->getEndianness());
	Signature::MatchSettings settings(0, 0);
	if (!secondStubSignature.match(settings, secondStub, secondStubCapturedData))
		throw UnsupportedStubException();

	// Load information about original UPX unpacking stub
	std::uint32_t epAddress = secondStubCapturedData.read<std::uint32_t>(0);
	std::uint32_t upxStubOffset = epAddress - stub->getFile()->getEpSegment()->getAddress();
	std::uint32_t upxStubSize = secondStubCapturedData.read<std::uint32_t>(4);
	std::uint8_t upxStubXorValue = secondStubCapturedData.read<std::uint8_t>(8);

	// Load XORed original UPX unpacking stub
	std::vector<std::uint8_t> upxStubBytes;
	stub->getFile()->getEpSegment()->getBytes(upxStubBytes, upxStubOffset, upxStubSize);

	// XOR it back with the constant value
	DynamicBuffer upxStub(upxStubBytes, stub->getFile()->getFileFormat()->getEndianness());
	upxStub.forEachReverse([upxStubXorValue, &upxStubSize](std::uint8_t& byte) {
			// We need to use prefix decrement since this is also being done on assembly level
			if (--upxStubSize == 0)
				return;

			byte ^= upxStubXorValue;
		});

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
	stub->setRealEpAddress(epAddress);
}

/**
 * Reads the unpacking stub into buffer.
 *
 * @param stub The PE64 UPX unpacking stub object.
 * @param unpackingStub Buffer where to place unpacking stub.
 */
void DecompressorUpxshit::readUnpackingStub(PeUpxStub<64>* stub, DynamicBuffer& unpackingStub)
{
	// We just need to parse XOR value and how much bytes is XORed, then read the data from EP - how much bytes are XORed
	// XOR these data, look again for XOR value and the base address and the amount of bytes XORed, this value should be UPX OEP
	// XOR again, run standard signatures again and we should have the original version

	// First load information about second stub where we can get information about original UPX unpacking stub
	std::uint32_t secondStubOffset = stub->getStubCapturedData()->read<std::uint32_t>(0) - stub->getFile()->getEpSegment()->getAddress();
	std::uint32_t secondStubSize = stub->getStubCapturedData()->read<std::uint32_t>(4);
	std::uint8_t secondStubXorValue = stub->getStubCapturedData()->read<std::uint8_t>(8);

	// Load XORed second stub
	std::vector<std::uint8_t> secondStubBytes;
	stub->getFile()->getEpSegment()->getBytes(secondStubBytes, secondStubOffset, secondStubSize);

	// XOR it back with the constant value
	DynamicBuffer secondStub(secondStubBytes, stub->getFile()->getFileFormat()->getEndianness());
	secondStub.forEachReverse([secondStubXorValue, &secondStubSize](std::uint8_t& byte) {
			// We need to use prefix decrement since this is also being done on assembly level
			if (--secondStubSize == 0)
				return;

			byte ^= secondStubXorValue;
		});

	// Match it against known signature of second UPX$HIT stub
	DynamicBuffer secondStubCapturedData(stub->getFile()->getFileFormat()->getEndianness());
	Signature::MatchSettings settings(0, 0);
	if (!secondStubSignature.match(settings, secondStub, secondStubCapturedData))
		throw UnsupportedStubException();

	// Load information about original UPX unpacking stub
	std::uint32_t epAddress = secondStubCapturedData.read<std::uint32_t>(0);
	std::uint32_t upxStubOffset = epAddress - stub->getFile()->getEpSegment()->getAddress();
	std::uint32_t upxStubSize = secondStubCapturedData.read<std::uint32_t>(4);
	std::uint8_t upxStubXorValue = secondStubCapturedData.read<std::uint8_t>(8);

	// Load XORed original UPX unpacking stub
	std::vector<std::uint8_t> upxStubBytes;
	stub->getFile()->getEpSegment()->getBytes(upxStubBytes, upxStubOffset, upxStubSize);

	// XOR it back with the constant value
	DynamicBuffer upxStub(upxStubBytes, stub->getFile()->getFileFormat()->getEndianness());
	upxStub.forEachReverse([upxStubXorValue, &upxStubSize](std::uint8_t& byte) {
			// We need to use prefix decrement since this is also being done on assembly level
			if (--upxStubSize == 0)
				return;

			byte ^= upxStubXorValue;
		});

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
	stub->setRealEpAddress(epAddress);
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
