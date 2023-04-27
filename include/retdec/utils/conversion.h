/**
* @file include/retdec/utils/conversion.h
* @brief Conversion utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_CONVERSION_H
#define RETDEC_UTILS_CONVERSION_H

#include <cstdint>
#include <iomanip>
#include <ios>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace retdec {
namespace utils {

/// @name Conversions
/// @{

char* byteToHexString(uint8_t b, bool uppercase = true);

/**
 * Converts the given array of numbers into a hexadecimal string representation
 * @param data Array to be converted into a hexadecimal string
 * @param dataSize Size of array
 * @param result Into this parameter the result is stored
 * @param offset First byte from @a data which will be converted
 * @param size Number of bytes from @a data for conversion
 *    (0 means all bytes from @a offset)
 * @param uppercase @c true if hex letters (A-F) should be uppercase
 * @param spacing insert ' ' between every byte
 */
template<typename N> void bytesToHexString(
		const N *data,
		std::size_t dataSize,
		std::string &result,
		std::size_t offset = 0,
		std::size_t size = 0,
		bool uppercase = true,
		bool spacing = false)
{
	if (data == nullptr || offset >= dataSize)
	{
		return;
	}

	size = (size == 0 || offset + size > dataSize)
			? dataSize - offset
			: size;

	std::size_t hexIndex = 0;

	std::size_t sz = spacing ? (size * 3 - 1) : (size * 2);
	result.resize(sz);

	for (std::size_t i = 0; i < size; ++i)
	{
		if (spacing && hexIndex > 0)
		{
			result[hexIndex++] = ' ';
		}
		auto res = byteToHexString(data[offset + i], uppercase);
		result[hexIndex++] = res[0];
		result[hexIndex++] = res[1];
	}
}

/**
 * Converts the given vector of numbers into a hexadecimal string representation
 * @param bytes Vector to be converted into a hexadecimal string
 * @param result Into this parameter the result is stored
 * @param offset First byte from @a bytes which will be converted
 * @param size Number of bytes from @a bytes for conversion
 *    (0 means all bytes from @a offset)
 * @param uppercase @c true if hex letters (A-F) should be uppercase
 * @param spacing insert ' ' between every byte
 */
template<typename N> void bytesToHexString(
		const std::vector<N> &bytes,
		std::string &result,
		std::size_t offset = 0,
		std::size_t size = 0,
		bool uppercase = true,
		bool spacing = false)
{
	bytesToHexString(
			bytes.data(),
			bytes.size(),
			result,
			offset,
			size,
			uppercase,
			spacing
	);
}

/**
* @brief Converts the given integer into its hexadecimal representation.
*
* @param[in] w Number to be converted.
* @param[in] addBase Prepends "0x" before the result.
* @param[in] fillToN If needed, prepends "0" before the result to get at least
*                    @c fillToN characters long string.
*
* All letters in the result are lowercase.
*/
template<typename I>
std::string intToHexString(I w, bool addBase = false, unsigned fillToN = 0)
{
	static const char* digits = "0123456789abcdef";

	size_t hex_len = sizeof(I)<<1;

	std::string rc(hex_len,'0');
	for (size_t i = 0, j = (hex_len-1)*4 ; i < hex_len; ++i, j -= 4)
	{
		rc[i] = digits[(w>>j) & 0x0f];
	}

	bool started = false;
	std::string res;
	size_t j = 0;
	if (addBase)
	{
		res.resize(rc.size() + 2);
		res[0] = '0';
		res[1] = 'x';
		j = 2;
	}
	else
	{
		res.resize(rc.size());
	}
	for (size_t i = 0; i < rc.size(); ++i)
	{
		if (started)
		{
			res[j++] = rc[i];
		}
		else if (rc[i] != '0' || (rc.size() - i <= fillToN) || (i == rc.size() - 1))
		{
			res[j++] = rc[i];
			started = true;
		}
	}
	res.resize(j);

	return res;
}

std::vector<uint8_t> hexStringToBytes(const std::string& hexIn);

/**
* @brief Converts the given string into a number.
*
* @param[in] str String to be converted into a number.
* @param[out] number Into this parameter the resulting number is stored.
* @param[in] format Number format (e.g. std::dec, std::hex).
*
* @return @c true if the conversion went ok, @c false otherwise.
*
* If the conversion fails, @a number is left unchanged.
*/
template<typename N>
inline bool strToNum(const std::string &str, N &number,
		std::ios_base &(* format)(std::ios_base &) = std::dec) {
	std::istringstream strStream(str);
	N convNumber = 0;
	strStream >> format >> convNumber;
	if (strStream.fail() || !strStream.eof()) {
		return false;
	}

	// The above checks do not detect conversion of a negative number into an
	// unsigned integer. We have to perform an additional check here.
	if (std::is_unsigned<N>::value && str[0] == '-') {
		return false;
	}

	number = convNumber;
	return true;
}

namespace
{
	const std::size_t BITS_IN_BYTE = 8;
}

/**
 * @brief Converts the given array of numbers into a bits.
 *
 * @param[in] data Array of numbers.
 * @param[in] dataSize Size of array.
 *
 * @return Resulting string.
 */
template<typename N>
std::string bytesToBits(const N *data, std::size_t dataSize) {
	if(!data) {
		dataSize = 0;
	}

	std::string result;
	result.reserve(dataSize * BITS_IN_BYTE);

	for (std::size_t i = 0; i < dataSize; ++i) {
		auto& item = data[i];

		for(std::size_t j = 0; j < BITS_IN_BYTE; ++j) {
			// 0x80 = 0b10000000
			result += ((item << j) & 0x80) ? '1' : '0';
		}
	}

	return result;
}

/**
 * @brief Converts the given vector of numbers into a bits.
 *
 * @param[in] bytes Vector to be converted into a bits.
 *
 * @return Resulting string.
 */
template<typename N>
std::string bytesToBits(const std::vector<N> &bytes) {
	return bytesToBits(bytes.data(), bytes.size());
}
/**
 * Converts the given array of numbers into a string
 * @param data Array to be converted into a string
 * @param dataSize Size of array
 * @param result Into this parameter the result is stored
 * @param offset First byte from @a data which will be converted to string
 * @param size Number of bytes from @a data for conversion
 *    (0 means all bytes from @a offset)
 */
template<typename N> void bytesToString(
		const N *data,
		std::size_t dataSize,
		std::string &result,
		std::size_t offset = 0,
		std::size_t size = 0)
{
	if(!data)
	{
		dataSize = 0;
	}

	if(offset >= dataSize)
	{
		size = 0;
	}
	else
	{
		size = (size == 0 || offset + size > dataSize)
				? dataSize - offset
				: size;
	}

	result.clear();
	result.reserve(size);
	result = std::string(reinterpret_cast<const char*>(data + offset), size);
}

/**
 * Converts the given vector of numbers into a string
 * @param bytes Vector to be converted into a string
 * @param result Into this parameter the result is stored
 * @param offset First byte from @a bytes which will be converted to string
 * @param size Number of bytes from @a bytes for conversion
 *    (0 means all bytes from @a offset)
 */
template<typename N> void bytesToString(
		const std::vector<N> &bytes,
		std::string &result,
		std::size_t offset = 0,
		std::size_t size = 0)
{
	bytesToString(bytes.data(), bytes.size(), result, offset, size);
}

void double10ToDouble8(std::vector<unsigned char> &dest,
	const std::vector<unsigned char> &src);

unsigned short byteSwap16(unsigned short val);
unsigned int byteSwap32(unsigned int val);
std::string byteSwap16(const std::string &val);
std::string byteSwap32(const std::string &val);

/// @}

} // namespace utils
} // namespace retdec

#endif
