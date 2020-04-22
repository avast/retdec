/**
 * @file include/retdec/unpacker/decompression/nrv/bit_parsers.h
 * @brief Bit getters for NRV decompression algorithms.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DECOMPRESSION_NRV_BIT_PARSERS_H
#define RETDEC_UNPACKER_DECOMPRESSION_NRV_BIT_PARSERS_H

#include "retdec/fileformat/fftypes.h"
#include "retdec/utils/dynamic_buffer.h"

using namespace retdec::utils;

namespace retdec {
namespace unpacker {

class BitParser
{
public:
	BitParser() {}
	BitParser(const BitParser&) = delete;
	virtual ~BitParser() = default;

	virtual bool getBit(uint8_t& bit, const DynamicBuffer& data, uint32_t& pos) = 0;

private:
	BitParser& operator =(const BitParser&);
};

template <typename T> class BitParserN : public BitParser
{
public:
	BitParserN() : _value()
	{
		static_assert(std::is_integral<T>::value, "BitParser requires integral type");
	}

	BitParserN(const BitParser&) = delete;

protected:
	T _value;

private:
	BitParserN& operator =(const BitParserN&);
};

class BitParser8 : public BitParserN<uint32_t>
{
public:
	BitParser8() = default;
	BitParser8(const BitParser8&) = delete;

	virtual bool getBit(uint8_t& bit, const DynamicBuffer& data, uint32_t& pos) override
	{
		bit = (_value >> 7) & 1;
		_value <<= 1;
		if ((_value & 0xFF) == 0)
		{
			if (pos >= data.getRealDataSize())
				return false;

			_value = data.read<uint8_t>(pos++, retdec::utils::Endianness::LITTLE);

			bit = (_value >> 7) & 1;
			_value <<= 1;
			_value += 1;
		}

		return true;
	}
};

class BitParserLe32 : public BitParserN<uint32_t>
{
public:
	BitParserLe32() = default;
	BitParserLe32(const BitParserLe32&) = delete;

	virtual bool getBit(uint8_t& bit, const DynamicBuffer& data, uint32_t& pos) override
	{
		bit = (_value >> 31) & 1;
		_value <<= 1;
		if (_value == 0)
		{
			if (pos >= data.getRealDataSize())
				return false;

			_value = data.read<uint32_t>(pos, retdec::utils::Endianness::LITTLE);
			pos += 4;

			bit = (_value >> 31) & 1;
			_value <<= 1;
			_value += 1;
		}

		return true;
	}
};

} // namespace unpacker
} // namespace retdec

#endif
