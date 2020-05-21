/**
 * @file src/yaracpp/yara_match.cpp
 * @brief Library representation of one YARA match.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/yaracpp/yara_match.h"

namespace retdec {
namespace yaracpp {

/**
 * Get offset of detection
 * @return Offset of detection
 */
std::size_t YaraMatch::getOffset() const
{
	return offset;
}

/**
 * Get size of stored bytes
 * @return size of stored bytes
 */
std::size_t YaraMatch::getDataSize() const
{
	return data.size();
}

/**
 * Get stored bytes
 * @return Byte representation of match
 */
const std::vector<std::uint8_t>& YaraMatch::getData() const
{
	return data;
}

/**
 * Set offset of detection
 * @param offsetValue Offset of detection
 */
void YaraMatch::setOffset(std::size_t offsetValue)
{
	offset = offsetValue;
}

/**
 * Set detected data
 * @param dataBuffer Pointer to the beginning of the data
 * @param dataLength Length of the buffer
 */
void YaraMatch::setData(const std::uint8_t* dataBuffer, std::size_t dataLength)
{
	data.assign(dataBuffer, dataBuffer + dataLength);
}

/**
 * Add detected byte
 * @param byte Value of byte
 */
void YaraMatch::addByte(std::uint8_t byte)
{
	data.push_back(byte);
}

} // namespace yaracpp
} // namespace retdec
