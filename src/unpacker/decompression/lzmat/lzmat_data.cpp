/**
 * @file src/unpacker/decompression/lzmat/lzmat_data.cpp
 * @brief Implementation of class for compressed LZMAT data representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/unpacker/decompression/lzmat/lzmat_data.h"

namespace retdec {
namespace unpacker {

LzmatData::LzmatData(const DynamicBuffer& buffer) : CompressedData(buffer)
{
}

LzmatData::~LzmatData()
{
}

bool LzmatData::decompress(DynamicBuffer& outputBuffer)
{
	outputBuffer.write<uint8_t>(_buffer.read<uint8_t>(0), 0); // First byte is just copied

	uint32_t inputPos = 1;
	uint32_t outputPos = 1;
	bool unaligned = false;
	while (inputPos < (_buffer.getRealDataSize() - unaligned))
	{
		uint8_t unk_byte0 = get8Bits(inputPos++, unaligned);
		for (uint32_t i = 0; (i < 8) && (inputPos < (_buffer.getRealDataSize() - unaligned)); ++i, unk_byte0 <<= 1)
		{
			if (unk_byte0 & 0x80)
			{
				uint32_t unk_dword0 = get16Bits(inputPos++, unaligned);
				uint32_t unk_dword1, unk_dword2;
				if (outputPos < 0x881)
				{
					unk_dword2 = unk_dword0 >> 1;
					if (unk_dword0 & 1)
					{
						unk_dword2 = (unk_dword2 & 0x7FF) + 0x81;
						inputPos += unaligned;
						unaligned = !unaligned;
					}
					else
						unk_dword2 = (unk_dword2 & 0x7F) + 1;
				}
				else
				{
					unk_dword2 = unk_dword0 >> 2;
					switch (unk_dword0 & 3)
					{
						case 0:
							unk_dword2 = (unk_dword2 & 0x3F) + 1;
							break;
						case 1:
							unk_dword2 = (unk_dword2 & 0x3FF) + 0x41;
							inputPos += unaligned;
							unaligned = !unaligned;
							break;
						case 2:
							unk_dword2 = unk_dword2 + 0x441;
							inputPos++;
							break;
						case 3:
						{
							if ((inputPos + 2 + unaligned) > _buffer.getRealDataSize())
								return false;

							++inputPos;
							uint32_t highBits = get4Bits(inputPos, unaligned);
							unk_dword2 = (unk_dword2 + (highBits << 14)) + 0x4441;
							break;
						}
						default: // never happens, just to satisfy compiler
							break;
					}
				}

				unk_dword0 = get4Bits(inputPos, unaligned);
				if (unk_dword0 != 0xF)
				{
					unk_dword0 += 3;
				}
				else
				{
					if ((inputPos + 1 + unaligned) > _buffer.getRealDataSize())
						return false;

					unk_dword0 = get8Bits(inputPos, unaligned);
					++inputPos;
					if (unk_dword0 != 0xFF)
					{
						unk_dword0 += 0x12;
					}
					else
					{
						if ((inputPos + 2 + unaligned) > _buffer.getRealDataSize())
							return false;

						unk_dword0 = get16Bits(inputPos, unaligned) + 0x111;
						inputPos += 2;
						if (unk_dword0 == 0x10110)
						{
							if (unaligned)
							{
								unk_dword0 = static_cast<uint32_t>((get8Bits(inputPos - 4, false) & 0xFC)) << 5;
								++inputPos;
								unaligned = false;
							}
							else
							{
								unk_dword0 = static_cast<uint32_t>((get16Bits(inputPos - 5, false) & 0xFC0)) << 1;
							}

							unk_dword0 = (unk_dword0 + (unk_byte0 & 0x7F) + 4) << 1;

							if ((outputPos + (unk_dword0 << 2)) > outputBuffer.getCapacity())
								return false;

							while (unk_dword0-- && outputPos < outputBuffer.getCapacity())
							{
								outputBuffer.write<uint32_t>(_buffer.read<uint32_t>(inputPos), outputPos);
								outputPos += 4;
								inputPos += 4;
							}
							break;
						}
					}
				}

				if (outputPos < unk_dword2)
					return false;

				if ((outputPos + unk_dword0) > outputBuffer.getCapacity())
					return false;

				unk_dword1 = outputPos - unk_dword2;
				while (unk_dword0-- && outputPos < outputBuffer.getCapacity())
				{
					outputBuffer.write<uint8_t>(outputBuffer.read<uint8_t>(unk_dword1++), outputPos++);
				}
			}
			else
			{
				outputBuffer.write<uint8_t>(get8Bits(inputPos++, unaligned), outputPos++);
			}
		}
	}

	return true;
}

uint8_t LzmatData::get4Bits(uint32_t& pos, bool& unaligned)
{
	uint8_t value = _buffer.read<uint8_t>(pos);
	if (!unaligned)
	{
		value &= 0xF;
	}
	else
	{
		value >>= 4;
		pos++;
	}

	unaligned = !unaligned;
	return value;
}

uint8_t LzmatData::get8Bits(uint32_t pos, bool unaligned)
{
	uint8_t value = _buffer.read<uint8_t>(pos);
	if (unaligned)
		value = (value >> 4) | (_buffer.read<uint8_t>(pos + 1) << 4);

	return value;
}

uint16_t LzmatData::get12Bits(uint32_t pos, bool unaligned)
{
	uint16_t value = _buffer.read<uint16_t>(pos);
	if (unaligned)
		value >>= 4;

	return (value & 0xFFF);
}

uint16_t LzmatData::get16Bits(uint32_t pos, bool unaligned)
{
	uint32_t value = _buffer.read<uint32_t>(pos);
	if (unaligned)
		value >>= 4;

	return (value & 0xFFFF);
}

} // namespace unpacker
} // namespace retdec
