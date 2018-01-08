/**
 * @file include/retdec/unpacker/dynamic_buffer.h
 * @brief Declaration of class for buffered data mainpulation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_DYNAMIC_BUFFER_H
#define RETDEC_UNPACKER_DYNAMIC_BUFFER_H

#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

#include "retdec/fileformat/fileformat.h"

namespace retdec {
namespace unpacker {

/**
 * @brief The class for dynamic buffered data manipulation taking the endianness of the data in account.
 *
 * This class provides the wrapper around the vector of bytes. It allows to specify the endianness of the data.
 * The data can be read from or written to this buffer using templated methods allowing not only per-byte manipulation,
 * but also reading and writing of words, double words etc. The buffer has its initial capacity allowing it to grow into
 * specified size. If the read or write requests the data from position that still falls into the capacity, the buffer resizes itself
 * to this size dynamically. It also checks for out-of-bounds accesses. In case of reading it reads the bytes that would be
 * out-of-bounds as 0 bytes and for writing it simply ignores the data that would be out-of-bounds.
 */
class DynamicBuffer
{
public:
	DynamicBuffer(retdec::utils::Endianness endianness = retdec::utils::Endianness::LITTLE);
	DynamicBuffer(uint32_t capacity, retdec::utils::Endianness endianness = retdec::utils::Endianness::LITTLE);
	DynamicBuffer(const std::vector<uint8_t>& data, retdec::utils::Endianness endianness = retdec::utils::Endianness::LITTLE);
	DynamicBuffer(const DynamicBuffer& dynamicBuffer);
	DynamicBuffer(const DynamicBuffer& dynamicBuffer, uint32_t startPos, uint32_t amount);

	~DynamicBuffer();

	DynamicBuffer& operator =(DynamicBuffer dynamicBuffer);

	void setCapacity(uint32_t capacity);
	uint32_t getCapacity() const;

	void setEndianness(retdec::utils::Endianness endianness);
	retdec::utils::Endianness getEndianness() const;

	uint32_t getRealDataSize() const;

	void erase(uint32_t startPos, uint32_t amount);

	const uint8_t* getRawBuffer() const;
	std::vector<uint8_t> getBuffer() const;

	void forEach(const std::function<void(uint8_t&)>& func);
	void forEachReverse(const std::function<void(uint8_t&)>& func);

	/**
	 * Reads the data from the buffer. If the reading position is beyond the size of the real data, the real data are resized so this
	 * value can be read filling the new bytes with default (0) value. If the read overlaps the capacity of the buffer, only the bytes
	 * that still fall into the capacity are read and the rest is filled with default (0) value.
	 *
	 * @tparam The type of the data to read. This must be integral type.
	 *
	 * @param pos Position where to start the reading.
	 * @param endianness The endianness in which the data should be read. If not specified, default endianness assigned to DynamicBuffer is used.
	 *
	 * @return The read value from the buffer.
	 */
	template <typename T> T read(uint32_t pos, retdec::utils::Endianness endianness = retdec::utils::Endianness::UNKNOWN) const
	{
		static_assert(std::is_integral<T>::value, "retdec::unpacker::DynamicBuffer::read can only accept integral types");

		// In case of non-specified endianness, use the default one assigned to DynamicBuffer itself
		if (endianness == retdec::utils::Endianness::UNKNOWN)
			endianness = _endianness;

		return readImpl<T>(pos, endianness);
	}

	std::string readString(uint32_t pos, uint32_t maxLength = 0) const;

	/**
	 * Writes the data to the buffer. If the writing poisition is beyond the size of the real data, the real data are resized so this
	 * value can be written filling the new bytes with default (0) value. If the write overlaps the capacity of the buffer, only the bytes
	 * that still fall into the capacity are written and the rest is ignored.
	 *
	 * @tparam The type of the data to write. This must be integral type.
	 *
	 * @param data The data to write.
	 * @param pos The position where to start writing.
	 * @param endianness The endianness in which the data should be written. If not specified, default endianness assigned to DynamicBuffer is used.
	 */
	template <typename T> void write(const T& data, uint32_t pos, retdec::utils::Endianness endianness = retdec::utils::Endianness::UNKNOWN)
	{
		static_assert(std::is_integral<T>::value, "retdec::unpacker::DynamicBuffer::write can only accept integral types");

		// In case of non-specified endianness, use the default one assigned to DynamicBuffer itself
		if (endianness == retdec::utils::Endianness::UNKNOWN)
			endianness = _endianness;

		writeImpl(data, pos, endianness);
	}

	void writeRepeatingByte(uint8_t byte, uint32_t pos, uint32_t repeatAmount);

private:
	template <typename T> void writeImpl(const T& data, uint32_t pos, retdec::utils::Endianness endianness)
	{
		// If the writing position is completely out of bounds, we just end
		if (pos >= _capacity)
			return;

		// Buffer would overlap the capacity, copy just the chunk that fits
		uint32_t bytesToWrite = sizeof(T);
		if (pos + bytesToWrite > getCapacity())
			bytesToWrite = getCapacity() - pos;

		if (bytesToWrite == 0)
			return;

		// Check whether there is enough space allocated
		if (pos + bytesToWrite > getRealDataSize())
			_data.resize(pos + bytesToWrite);

		for (uint32_t i = 0; i < bytesToWrite; ++i)
		{
			switch (endianness)
			{
				case retdec::utils::Endianness::LITTLE:
					_data[pos + i] = (data >> (i << 3)) & 0xFF;
					break;
				case retdec::utils::Endianness::BIG:
					_data[pos + i] = (data >> ((bytesToWrite - i - 1) << 3)) & 0xFF;
					break;
				default:
					break;
			}
		}
	}

	template <typename T> T readImpl(uint32_t pos, retdec::utils::Endianness endianness) const
	{
		// We are at the end, we are unable to read anything
		if (pos >= _data.size())
			return T{};

		// We are at the end, we are unable to read anything
		if (pos >= _capacity)
			return T{};

		// If reading overlaps over the size, make sure we don't access uninitialized memory
		uint32_t bytesToRead = sizeof(T);
		if (pos + bytesToRead > getCapacity())
			bytesToRead = getCapacity() - pos;

		if (pos + bytesToRead > getRealDataSize())
			bytesToRead = getRealDataSize() - pos;

		T ret = T{};
		for (uint32_t i = 0; i < bytesToRead; ++i)
		{
			switch (endianness)
			{
				case retdec::utils::Endianness::LITTLE:
					ret |= static_cast<uint64_t>(_data[pos + i]) << (i << 3);
					break;
				case retdec::utils::Endianness::BIG:
					ret |= static_cast<uint64_t>(_data[pos + i]) << ((bytesToRead - i - 1) << 3);
					break;
				default:
					break;
			}
		}

		return ret;
	}

	mutable std::vector<uint8_t> _data;
	retdec::utils::Endianness _endianness;
	uint32_t _capacity;
};

} // namespace unpacker
} // namespace retdec

#endif
