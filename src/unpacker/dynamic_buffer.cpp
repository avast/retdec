/**
 * @file src/unpacker/dynamic_buffer.cpp
 * @brief Implementation of class for buffered data mainpulation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/unpacker/dynamic_buffer.h"

using namespace retdec::utils;

namespace retdec {
namespace unpacker {

/**
 * Creates the empty DynamicBuffer object with no capacity and specified endianness.
 *
 * @param endianness Endianness of the bytes in the buffer.
 */
DynamicBuffer::DynamicBuffer(Endianness endianness /*= Endianness::LITTLE*/) : _data(), _endianness(endianness), _capacity(0)
{
}

/**
 * Creates the DynamicBuffer object with specified capacity and endianness.
 *
 * @param capacity Capacity of the buffer.
 * @param endianness Endianness of the bytes in the buffer.
 */
DynamicBuffer::DynamicBuffer(uint32_t capacity, Endianness endianness /*= Endianness::LITTLE*/)
	: _data(), _endianness(endianness), _capacity(capacity)
{
	_data.reserve(capacity);
}

/**
 * Creates the DynamicBuffer object and fills it with specified data with specified endianness.
 *
 * @param data The bytes to initialize the buffer with.
 * @param endianness Endiannes of the bytes in the buffer.
 */
DynamicBuffer::DynamicBuffer(const std::vector<uint8_t>& data, Endianness endianness /*= Endianness::LITTLE*/)
	: _data(data), _endianness(endianness), _capacity(static_cast<uint32_t>(data.size()))
{
}

/**
 * Creates the copy of the DynamicBuffer object.
 *
 * @param dynamicBuffer Buffer to copy.
 */
DynamicBuffer::DynamicBuffer(const DynamicBuffer& dynamicBuffer)
	: _data(dynamicBuffer._data), _endianness(dynamicBuffer._endianness), _capacity(dynamicBuffer._capacity)
{
}

/**
 * Creates the copy of the DynamicBuffer object, but only the specified subbuffer.
 *
 * @param dynamicBuffer Buffer to copy.
 * @param startPos Starting position in the specified buffer where to start the copying.
 * @param amount Number of bytes from startPos to copy.
 */
DynamicBuffer::DynamicBuffer(const DynamicBuffer& dynamicBuffer, uint32_t startPos, uint32_t amount)
{
	std::vector<uint8_t> tmpBuffer = dynamicBuffer.getBuffer();
	std::vector<uint8_t> buffer(tmpBuffer.begin() + startPos, tmpBuffer.begin() + startPos + amount);

	_data = buffer;
	_endianness = dynamicBuffer._endianness;
	_capacity = static_cast<uint32_t>(buffer.size());
}

/**
 * Destructor.
 */
DynamicBuffer::~DynamicBuffer()
{
}

/**
 * Assign operator, creates the copy of the DynamicBuffer.
 *
 * @param rhs Right hand side of the operator.
 *
 * @return The new DynamicBuffer object.
 */
DynamicBuffer& DynamicBuffer::operator =(DynamicBuffer rhs)
{
	std::swap(_data, rhs._data);
	std::swap(_endianness, rhs._endianness);
	std::swap(_capacity, rhs._capacity);
	return *this;
}

/**
 * Sets the capacity of the buffer.
 *
 * @param capacity The new capacity to set to the buffer.
 */
void DynamicBuffer::setCapacity(uint32_t capacity)
{
	_capacity = capacity;
	_data.reserve(_capacity);
}

/**
 * Gets the actual capacity of the buffer.
 *
 * @return The capacity of the buffer.
 */
uint32_t DynamicBuffer::getCapacity() const
{
	return _capacity;
}

/**
 * Sets the endianness of the bytes in the buffer. It doesn't result in any changes
 * to the actual bytes in the buffer. It reflects only when reading from or writing to
 * the buffer.
 *
 * @param endianness The endianness to set.
 */
void DynamicBuffer::setEndianness(Endianness endianness)
{
	_endianness = endianness;
}

/**
 * Gets the current endianness of the buffer.
 *
 * @return The endianness of the bytes in the buffer.
 */
Endianness DynamicBuffer::getEndianness() const
{
	return _endianness;
}

/**
 * Gets the size of the data that are actually written to the buffer.
 * This cannot be greater than the capacity of the buffer.
 *
 * @return The size of the written data to the buffer.
 */
uint32_t DynamicBuffer::getRealDataSize() const
{
	return static_cast<uint32_t>(_data.size());
}

/**
 * Erases the bytes from the buffer. Also reduces the capacity of the buffer.
 *
 * @param startPos The starting position where to start erasing.
 * @param amount Number of bytes from the startPos including to erase.
 */
void DynamicBuffer::erase(uint32_t startPos, uint32_t amount)
{
	if (startPos >= _data.size())
		return;

	amount = startPos + amount > _data.size() ? _data.size() - startPos : amount;
	_data.erase(_data.begin() + startPos, _data.begin() + startPos + amount);
}

/**
 * Gets the buffer as the vector of bytes.
 *
 * @return The vector with the bytes.
 */
std::vector<uint8_t> DynamicBuffer::getBuffer() const
{
	return _data;
}

/**
 * Gets the raw pointer to the bytes in the buffer.
 *
 * @return The pointer to the bytes in the buffer.
 */
const uint8_t* DynamicBuffer::getRawBuffer() const
{
	return _data.data();
}

/**
 * Runs the specified function for every single byte in the DynamicBuffer.
 *
 * @param func Function to run for every byte.
 */
void DynamicBuffer::forEach(const std::function<void(uint8_t&)>& func)
{
	for (uint8_t& byte : _data)
		func(byte);
}

/**
 * Runs the specified function for every single byte in the DynamicBuffer in the reverse order.
 *
 * @param func Function to run for every byte.
 */
void DynamicBuffer::forEachReverse(const std::function<void(uint8_t&)>& func)
{
	for (std::vector<uint8_t>::reverse_iterator itr = _data.rbegin(); itr != _data.rend(); ++itr)
	{
		uint8_t& byte = *itr;
		func(byte);
	}
}

/**
 * Reads the null or length terminated string from the buffer.
 *
 * @param pos The poisition in the buffer where to start reading.
 * @param maxLength The maximal length of the string that is read. If this is 0, the length limit is ignored and the string is read up to the next 0 byte.
 *
 * @return String read from buffer.
 */
std::string DynamicBuffer::readString(uint32_t pos, uint32_t maxLength /*= 0*/) const
{
	std::string str;
	char ch;

	while (((ch = read<char>(pos++)) != 0) && (!maxLength || str.length() < maxLength))
		str += ch;

	return str;
}

/**
 * Writes the single byte into the buffer for repeating amount of times.
 *
 * @param byte The byte to write into the buffer.
 * @param pos The position where to start writing the byte.
 * @param repeatAmount The number of times the byte is written into the buffer starting from pos including.
 */
void DynamicBuffer::writeRepeatingByte(uint8_t byte, uint32_t pos, uint32_t repeatAmount)
{
	if (pos + repeatAmount > _capacity)
		repeatAmount = _capacity - pos;

	if (pos + repeatAmount > _data.size())
		_data.resize(pos + repeatAmount);

	memset(&_data[pos], byte, repeatAmount);
}

} // namespace unpacker
} // namespace retdec
