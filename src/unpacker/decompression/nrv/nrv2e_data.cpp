/**
 * @file src/unpacker/decompression/nrv/nrv2e_data.cpp
 * @brief Implementation of class for NRV2E compressed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/fftypes.h"
#include "retdec/unpacker/decompression/nrv/nrv2e_data.h"

namespace retdec {
namespace unpacker {

Nrv2eData::Nrv2eData(const DynamicBuffer& buffer, BitParser* bitParser) : NrvData(buffer, bitParser)
{
}

Nrv2eData::~Nrv2eData()
{
}

bool Nrv2eData::decompress(DynamicBuffer& outputBuffer)
{
	// Reset just in case decompress() is called more times in row
	reset();

	int32_t lastDist = 1;
	uint8_t bit;

	while (true)
	{
		if (!_bitParser->getBit(bit, _buffer, _readPos))
			return false;

		while (bit == 1)
		{
			if (_writePos >= outputBuffer.getCapacity() || _readPos >= _buffer.getRealDataSize())
				return false;

			outputBuffer.write<uint8_t>(_buffer.read<uint8_t>(_readPos++), _writePos++);

			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;
		}

		int32_t dist = 1;
		while (true)
		{
			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			dist += dist + bit;

			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			if (bit == 1)
				break;

			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			dist = ((dist - 1) << 1) + bit;
		}

		int32_t count = 0;
		if (dist == 2)
		{
			dist = lastDist;

			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			count = bit;
		}
		else
		{
			if (_readPos >= _buffer.getRealDataSize())
				return false;

			dist = ((dist - 3) << 8) | _buffer.read<uint8_t>(_readPos++);

			if (dist == -1)
				return true;

			count = (dist ^ 0xFFFFFFFF) & 1;
			dist >>= 1;

			lastDist = ++dist;
		}

		if (count != 0)
		{
			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			count = 1 + bit;
		}
		else
		{
			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			if (bit == 1)
			{
				if (!_bitParser->getBit(bit, _buffer, _readPos))
					return false;

				count = 3 + bit;
			}
			else
			{
				count++;

				do
				{
					if (!_bitParser->getBit(bit, _buffer, _readPos))
						return false;

					count += count + bit;

					if (!_bitParser->getBit(bit, _buffer, _readPos))
						return false;
				} while (bit == 0);

				count += 3;
			}
		}

		count += (dist > 0x500) + 1;

		uint32_t srcPos = static_cast<int32_t>(_writePos) - dist;
		do
		{
			if (_writePos >= outputBuffer.getCapacity())
				return false;

			outputBuffer.write<uint8_t>(outputBuffer.read<uint8_t>(srcPos++), _writePos++);
		}
		while (--count);
	}
}

} // namespace unpacker
} // namespace retdec
