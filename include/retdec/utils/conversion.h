/**
* @file include/retdec/utils/conversion.h
* @brief Conversion utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_CONVERSION_H
#define RETDEC_UTILS_CONVERSION_H

#include <iomanip>
#include <ios>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace retdec {
namespace utils {

/// @name Conversions
/// @{

std::string toHex(std::uint64_t i, bool addBase = false, unsigned fillToN = 0);

/**
* @brief Converts the given value into a string.
*
* @tparam T Type of @a value.
*/
template<typename T>
inline std::string toString(const T &value) {
	std::ostringstream out;
	out << value;
	return out.str();
}

// Specialization for bool
template<>
inline std::string toString<bool>(const bool &value) {
	std::ostringstream out;
	out << std::boolalpha << value;
	return out.str();
}

// Specialization for float
template<>
inline std::string toString<float>(const float &value) {
	const int sigDigits = std::numeric_limits<float>::digits10;
	std::ostringstream out;
	out << std::setprecision(sigDigits) << value;
	return out.str();
}

// Specialization for double
template<>
inline std::string toString<double>(const double &value) {
	const int sigDigits = std::numeric_limits<double>::digits10;
	std::ostringstream out;
	out << std::setprecision(sigDigits) << value;
	return out.str();
}

// Specialization for long double
template<>
inline std::string toString<long double>(const long double &value) {
	const int sigDigits = std::numeric_limits<long double>::digits10;
	std::ostringstream out;
	out << std::setprecision(sigDigits) << value;
	return out.str();
}

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
	if (!strStream.fail() && strStream.eof()) {
		number = convNumber;
		return true;
	}
	return false;
}

/**
* @brief Converts the given number into a string.
*
* @param[in] number Number for conversion.
* @param[in] format String format (e.g. std::dec, std::hex).
*
* @return Resulting string.
*/
template<typename N>
inline std::string numToStr(const N number,
		std::ios_base &(* format)(std::ios_base &) = std::dec) {
	std::ostringstream strStream;
	strStream << format << number;
	return strStream.str();
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
 * @brief Converts the given number into a bits.
 *
 * @param[in] byte Number to be converted into a bits.
 *
 * @return Resulting string.
 */
template<typename N>
std::string byteToBits(N byte) {
	std::vector<N> vect(1, byte);
	return bytesToBits(vect);
}

/**
 * Converts the single byte into a hexadecimal string representation
 * @param oStr Output stream
 * @param byte Data to be converted
 * @param uppercase @c true if hex letters (A-F) should be uppercase
 */
template<typename N> void byteToHexString(std::ostream& oStr, N byte, bool uppercase = true)
{
	oStr << std::hex << std::setfill('0') << std::setw(2) << (uppercase ? std::uppercase : std::nouppercase) << (byte & 0xFF);
}

/**
 * Converts the given array of numbers into a hexadecimal string representation
 * @param data Array to be converted into a hexadecimal string
 * @param dataSize Size of array
 * @param result Into this parameter the result is stored
 * @param offset First byte from @a data which will be converted
 * @param size Number of bytes from @a data for conversion
 *    (0 means all bytes from @a offset)
 * @param uppercase @c true if hex letters (A-F) should be uppercase
 */
template<typename N> void bytesToHexString(const N *data, std::size_t dataSize, std::string &result, std::size_t offset = 0, std::size_t size = 0, bool uppercase = true)
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
		size = (size == 0 || offset + size > dataSize) ? dataSize - offset : size;
	}

	// Sample: 4A2A008CF1AEE9BA49D8D1DAA22D8E868365ACE633823D464478239F27ED4F18
	// Tool: redec-fileinfo.exe, Debug, x64, data = image, dataSize = 0xE1BC00
	// Optimized: This code now takes 0.106 seconds to convert (measured in VS 2015 IDE)
	// (down from about 40 seconds)
	const char * intToHex = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
	std::size_t hexIndex = 0;

	// Reserve the necessary space for the hexa string
	result.resize(size * 2);

	// Convert to hexa byte-by-byte. No reallocations
	for (std::size_t i = 0; i < size; ++i, hexIndex += 2)
	{
		std::uint8_t oneByte = data[offset + i];

		result[hexIndex + 0] = intToHex[(oneByte >> 0x04) & 0x0F];
		result[hexIndex + 1] = intToHex[(oneByte >> 0x00) & 0x0F];
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
 */
template<typename N> void bytesToHexString(const std::vector<N> &bytes, std::string &result, std::size_t offset = 0, std::size_t size = 0, bool uppercase = true)
{
	bytesToHexString(bytes.data(), bytes.size(), result, offset, size, uppercase);
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
template<typename N> void bytesToString(const N *data, std::size_t dataSize, std::string &result, std::size_t offset = 0, std::size_t size = 0)
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
		size = (size == 0 || offset + size > dataSize) ? dataSize - offset : size;
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
template<typename N> void bytesToString(const std::vector<N> &bytes, std::string &result, std::size_t offset = 0, std::size_t size = 0)
{
	bytesToString(bytes.data(), bytes.size(), result, offset, size);
}

unsigned long byteToULong8(const char *sByte, bool switchBitsOrder);
unsigned long byteToULongVariable(const char *sByte, std::size_t iByteSize);
unsigned long byteToULong(const char *sByte, std::size_t iByteSize,
	bool switchBitsOrder = false);

void double10ToDouble8(std::vector<unsigned char> &dest,
	const std::vector<unsigned char> &src);

unsigned short byteSwap16(unsigned short val);
unsigned int byteSwap32(unsigned int val);
std::string byteSwap16(const std::string &val);
std::string byteSwap32(const std::string &val);

std::string unsignedToBinString(unsigned long long int nValue, int nLength);
unsigned long long int binStringToUnsigned(const char *sValue);
long long int binStringToSigned(const char *sValue);

std::vector<uint8_t> hexStringToBytes(const std::string& hexIn);
std::string bytesToHexString(const std::vector<uint8_t>& bytes);

/// @}

} // namespace utils
} // namespace retdec

#endif
