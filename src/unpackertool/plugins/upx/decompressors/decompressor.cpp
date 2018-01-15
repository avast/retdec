/**
 * @file src/unpackertool/plugins/upx/decompressors/decompressor.cpp
 * @brief Implementation of base decompressor visitor for unpacking packed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "unpackertool/plugins/upx/decompressors/decompressor.h"
#include "unpackertool/plugins/upx/upx.h"
#include "unpackertool/plugins/upx/upx_exceptions.h"

using namespace retdec::unpacker;

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Constructor.
 */
Decompressor::Decompressor()
{
}

/**
 * Destructor.
 */
Decompressor::~Decompressor()
{
}

/**
 * Performs decompression using provided compressed data and decompresses it into provided buffer.
 * If it fails to decompress them, it uses XOR bruteforce on the packed data.
 *
 * @param compressedDataWptr The compressed data.
 * @param unpackedData Buffer where to decompress data.
 */
void Decompressor::performDecompression(const std::weak_ptr<CompressedData>& compressedDataWptr, DynamicBuffer& unpackedData)
{
	auto compressedData = compressedDataWptr.lock();
	if (!compressedData->decompress(unpackedData))
	{
		if (upx_plugin->getStartupArguments()->brute)
		{
			upx_plugin->log("Bruteforcing compressed data with XOR.");

			// If we failed, try to bruteforce the data with XOR
			DynamicBuffer originalData = compressedData->getBuffer();
			for (std::uint32_t i = 0x01; i <= 0xFF; ++i)
			{
				DynamicBuffer xoredData = originalData;
				xoredData.forEach([i](std::uint8_t& byte) { byte ^= i; });
				compressedData->setBuffer(xoredData);

				if (compressedData->decompress(unpackedData))
				{
					upx_plugin->log("Bruteforcing compressed data with XOR succeeded on XOR value 0x", std::hex, i, std::dec, ".");
					return;
				}
			}
		}

		throw DecompressionFailedException();
	}
}

} // namespace upx
} // namespace unpackertool
} // namespace retdec
