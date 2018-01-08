/**
 * @file src/unpacker/decompression/nrv/nrv2b_data.cpp
 * @brief Implementation of class for NRV2B compressed data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/fftypes.h"
#include "retdec/unpacker/decompression/nrv/nrv2b_data.h"

namespace retdec {
namespace unpacker {

Nrv2bData::Nrv2bData(const DynamicBuffer& buffer, BitParser* bitParser) : NrvData(buffer, bitParser)
{
}

Nrv2bData::~Nrv2bData()
{
}

bool Nrv2bData::decompress(DynamicBuffer& outputBuffer)
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
		do
		{
			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;

			dist += dist + bit;

			if (!_bitParser->getBit(bit, _buffer, _readPos))
				return false;
		} while (bit == 0);

		if (dist == 2)
		{
			dist = lastDist;
		}
		else
		{
			if (_readPos >= _buffer.getRealDataSize())
				return false;

			dist = ((dist - 3) << 8) | _buffer.read<uint8_t>(_readPos++);
			if (dist == -1)
				return true;

			lastDist = ++dist;
		}

		if (!_bitParser->getBit(bit, _buffer, _readPos))
			return false;

		int32_t count = bit << 1;

		if (!_bitParser->getBit(bit, _buffer, _readPos))
			return false;

		count += bit;

		if (count == 0)
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

			count += 2;
		}

		count += (dist > 0xD00) + 1;

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
