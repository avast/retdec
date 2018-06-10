/**
 * @file src/unpacker/decompression/lzma/lzma_data.cpp
 * @brief Implementation of class for compressed LZMA data representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <limits>

#include "retdec/unpacker/decompression/lzma/lzma_data.h"

namespace retdec {
namespace unpacker {

/**
 * Constructor.
 *
 * @param buffer The LZMA compressed data.
 * @param pb Property of LZMA.
 * @param lp Property of LZMA.
 * @param lc Property of LZMA.
 */
LzmaData::LzmaData(const DynamicBuffer& buffer, uint8_t pb, uint8_t lp, uint8_t lc) : CompressedData(buffer),
		_readPos(0), _pb(pb), _lp(lp), _lc(lc), _rangeDecoder()
{
}

/**
 * Destructor.
 */
LzmaData::~LzmaData()
{
}

/**
 * Decompresses the LZMA compressed data.
 *
 * @ param outputBuffer The buffer in which the datas are decompressed.
 *
 * @return True if the decompression was successful, otherwise false.
 */
bool LzmaData::decompress(DynamicBuffer& outputBuffer)
{
	if (!checkProperties())
		return false;

	// Reset just in case decompress() is called more times in row
	_readPos = 0;
	_rangeDecoder.reset();

	// 42D175
	uint8_t previousByte = 0;
	uint32_t state = 0;
	uint32_t pos = 0;
	uint32_t posStateMask = (1 << _pb) - 1;
	uint32_t literalPosMask = (1 << _lp) - 1;
	uint32_t rep[4] = { 1, 1, 1, 1 };
	uint32_t len = 0;
	_rangeDecoder.decoder.resize((0x300 << (_lc + _lp)) + 0x736, 0x400);
	_rangeDecoder.range = std::numeric_limits<uint32_t>::max();
	for (uint8_t i = 0; i < 5; ++i)
		_rangeDecoder.code = (_rangeDecoder.code << 8) | _buffer.read<uint8_t>(_readPos++);

	while (pos < outputBuffer.getCapacity() && _readPos < _buffer.getRealDataSize())
	{
		uint32_t bit;
		uint32_t posState = pos & posStateMask;

		if (!decodeBit((state << 4) + posState, bit))
			return false;

		if (bit == 0)
		{
			// 42d2c8
			uint32_t literalPos = pos & literalPosMask;
			literalPos = (((literalPos << _lc) + (previousByte >> (8 - _lc)) * 0x300) + 0x736);
			if (state <= 6)
			{
				if (!decodeLiteral(literalPos, previousByte, false, 0))
					return false;
			}
			else
			{
				// 42d322
				if (!decodeLiteral(literalPos, previousByte, true, outputBuffer.read<uint8_t>(pos - rep[0])))
					return false;
			}

			// 42d45d
			outputBuffer.write<uint8_t>(previousByte, pos++);
			state = (state <= 3) ? 0 : ((state <= 9) ? (state - 3) : (state - 6));
		}
		else
		{
			if (!decodeBit(state + 0xC0, bit))
				return false;

			if (bit == 1)
			{
				if (!decodeBit(state + 0xCC, bit))
					return false;

				if (bit == 1)
				{
					if (!decodeBit(state + 0xD8, bit))
						return false;

					if (bit == 1)
					{
						if (!decodeBit(state + 0xE4, bit))
							return false;

						// 42d772
						if (bit == 1)
							rotateRep(rep, 3);
						else
							rotateRep(rep, 2);
					}
					// 42d6dd
					else
					{
						rotateRep(rep, 1);
					}

					// 42d7ac
					state = (state <= 6) ? 8 : 11;
					if (!decodeLen(0x534, posState, len))
						return false;

					// 42d956 - dead code for this one

					// 42db5d
					if (rep[0] > pos)
						return false;

					len += 2;
					do
					{
						previousByte = outputBuffer.read<uint8_t>(pos - rep[0]);
						outputBuffer.write<uint8_t>(previousByte, pos++);
					} while (--len && pos < outputBuffer.getCapacity());
				}
				// 42d5aa
				else
				{
					if (!decodeBit((state << 4) + posState + 0xF0, bit))
						return false;

					// 42d674
					if (bit == 1)
					{
						// 42d7ac
						state = (state <= 6) ? 8 : 11;
						if (!decodeLen(0x534, posState, len))
							return false;

						// 42d956 - dead code for this one

						// 42db5d
						if (rep[0] > pos)
							return false;

						len += 2;
						do
						{
							previousByte = outputBuffer.read<uint8_t>(pos - rep[0]);
							outputBuffer.write<uint8_t>(previousByte, pos++);
						} while (--len && pos < outputBuffer.getCapacity());
					}
					// 42d614
					else
					{
						if (pos == 0)
							return false;

						state = (state <= 6) ? 9 : 11;
						previousByte = outputBuffer.read<uint8_t>(pos - rep[0]);
						outputBuffer.write<uint8_t>(previousByte, pos++);
					}
				}
			}
			// 42d502
			else
			{
				rotateRep(rep, 3);
				state = (state <= 6) ? 0 : 3;
				if (!decodeLen(0x332, posState, len))
					return false;

				// 42d956
				uint32_t bits;
				uint32_t posSlot;
				uint32_t revBitTreePos;
				uint32_t numDirectBits;
				state += 7;
				if (!decodeBitTree((((len <= 3) ? len : 3) << 6) + 0x1B0, 6, 0, posSlot))
					return false;

				// 42da1d
				if (posSlot > 3)
				{
					numDirectBits = (posSlot >> 1) - 1;
					if (posSlot > 0x0D)
					{
						if (!decodeDirectBits(numDirectBits - 4, (posSlot & 1) | 2, bits))
							return false;

						posSlot = bits << 4;
						numDirectBits = 4;
						revBitTreePos = 0x322;
					}
					else
					{
						revBitTreePos = (((posSlot & 1) | 2) << numDirectBits) - posSlot + 0x2AF;
						posSlot = ((posSlot & 1) | 2) << numDirectBits;
					}

					// 42dab6
					if (!decodeRevBitTree(revBitTreePos, numDirectBits, posSlot))
						return false;
				}

				rep[0] = posSlot + 1;

				// 42db5d
				if (rep[0] > pos)
					return false;

				len += 2;
				do
				{
					previousByte = outputBuffer.read<uint8_t>(pos - rep[0]);
					outputBuffer.write<uint8_t>(previousByte, pos++);
				} while (--len && pos < outputBuffer.getCapacity());
			}
		}
	}

	return true;
}

bool LzmaData::decodeBit(uint32_t pos, uint32_t& bit)
{
	// Normalization
	if (_rangeDecoder.range <= 0xFFFFFF)
	{
		_rangeDecoder.range <<= 8;
		_rangeDecoder.code = (_rangeDecoder.code << 8) | _buffer.read<uint8_t>(_readPos++);
	}

	if (pos >= _rangeDecoder.decoder.size())
		return false;

	uint32_t bound = (_rangeDecoder.range >> 0x0B) * _rangeDecoder.decoder[pos];
	if (_rangeDecoder.code < bound)
	{
		_rangeDecoder.range = bound;
		_rangeDecoder.decoder[pos] += (0x800 - _rangeDecoder.decoder[pos]) >> 5;
		bit = 0;
	}
	else
	{
		_rangeDecoder.code -= bound;
		_rangeDecoder.range -= bound;
		_rangeDecoder.decoder[pos] -= _rangeDecoder.decoder[pos] >> 5;
		bit = 1;
	}

	return true;
}

bool LzmaData::decodeLiteral(uint32_t pos, uint8_t& returnByte, bool useRep, uint32_t rep)
{
	uint32_t bit;
	uint32_t symbol = 1;
	uint32_t expectedBit;

	if (useRep)
	{
		do
		{
			rep <<= 1;
			expectedBit = (rep & 0x100) >> 8;
			if (!decodeBit(pos + (rep & 0x100) + symbol + 0x100, bit))
				return false;

			symbol = (symbol << 1) + bit;
		} while (bit == expectedBit && symbol <= 0xFF);

		while (symbol <= 0xFF)
		{
			if (!decodeBit(pos + symbol, bit))
				return false;

			symbol = (symbol << 1) + bit;
		}
	}
	else
	{
		do
		{
			if (!decodeBit(pos + symbol, bit))
				return false;

			symbol = (symbol << 1) + bit;
		} while (symbol <= 0xFF);
	}

	returnByte = symbol;
	return true;
}

void LzmaData::rotateRep(uint32_t rep[4], uint32_t amount)
{
	uint32_t newRep0 = rep[amount];
	while (amount--)
		rep[amount + 1] = rep[amount];

	rep[0] = newRep0;
}

bool LzmaData::decodeLen(uint32_t pos, uint32_t posState, uint32_t& len)
{
	uint32_t bit;

	// 42d7e6
	if (!decodeBit(pos, bit))
		return false;

	if (bit == 0)
	{
		// 42d7f8
		if (!decodeBitTree(pos + (posState << 3) + 2, 3, 0, len))
			return false;

		return true;
	}

	// 42d855
	if (!decodeBit(pos + 1, bit))
		return false;

	if (bit == 0)
	{
		// 42d868
		if (!decodeBitTree(pos + (posState << 3) + 0x82, 3, 8, len))
			return false;

		return true;
	}

	// 42d8a3
	if (!decodeBitTree(pos + 0x102, 8, 0x10, len))
		return false;

	return true;
}

bool LzmaData::decodeBitTree(uint32_t pos, uint32_t rep, uint32_t add, uint32_t& ret)
{
	// 42d8df
	uint32_t value = 1;
	uint32_t bit;

	for (uint32_t i = rep; i > 0; --i)
	{
		if (!decodeBit(pos + value, bit))
			return false;

		value = (value << 1) + bit;
	}

	ret = value - (1 << rep) + add;
	return true;
}

bool LzmaData::decodeRevBitTree(uint32_t pos, uint32_t rep, uint32_t& posSlot)
{
	uint32_t value = 1;
	uint32_t unk = 1;
	uint32_t bit;

	do
	{
		if (!decodeBit(pos + value, bit))
			return false;

		value = (value << 1) | bit;
		if (bit == 1)
			posSlot |= unk;
		unk <<= 1;
	} while (--rep);

	return true;
}

bool LzmaData::decodeDirectBits(uint32_t count, uint32_t initValue, uint32_t& ret)
{
	uint32_t value = initValue;

	do
	{
		if (_rangeDecoder.range <= 0xFFFFFF)
		{
			_rangeDecoder.range <<= 8;
			_rangeDecoder.code = (_rangeDecoder.code << 8) | _buffer.read<uint8_t>(_readPos++);
		}

		_rangeDecoder.range >>= 1;
		value <<= 1;

		if (_rangeDecoder.code >= _rangeDecoder.range)
		{
			_rangeDecoder.code -= _rangeDecoder.range;
			value |= 1;
		}
	} while (--count);

	ret = value;
	return true;
}

bool LzmaData::checkProperties()
{
	if (_pb > 4 || _lp > 4 || _lc > 8)
		return false;

	return true;
}

} // namespace unpacker
} // namespace retdec
