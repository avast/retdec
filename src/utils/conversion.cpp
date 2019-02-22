/**
* @file src/utils/conversion.cpp
* @brief Implementation of the conversion utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <bitset>
#include <cstring>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace utils {

/**
* @brief Converts the given integer into its hexadecimal representation.
*
* @param[in] i Number to be converted.
* @param[in] addBase Prepends "0x" before the result.
* @param[in] fillToN If needed, prepends "0" before the result to get at least
*                    @c fillToN characters long string.
*
* If @a addBase is @c false, the base ("0x") is omitted. For example, <tt>
* toHex(247)</tt> returns @c "f7", while <tt>toHex(247, true)</tt> returns @c
* "0xf7". All letters in the result are lowercase.
*/
std::string toHex(std::uint64_t i, bool addBase, unsigned fillToN) {
	std::stringstream s;
	if (fillToN) {
		s << std::setfill('0') << std::setw(fillToN) << std::hex << i;
	}
	else {
		s << std::hex << i;
	}
	return addBase ? "0x" + s.str() : s.str();
}

/**
* @brief Transforms an 8-bit byte (i.e. string consisting of 0s and 1s) to
*        <tt>unsigned long</tt>.
*
* @param[in] sByte String to be converted.
* @param[in] switchBitsOrder Whether to switch LSB and MSB or not.
*
* @return The resulting converted number or 0 if an error occurred.
*/
unsigned long byteToULong8(const char *sByte, bool switchBitsOrder) {
	std::bitset<8> byte;

	if (switchBitsOrder) {
		for (int k=7; k>=0; k--) {
			if (sByte[k] == '1')
				byte[k] = 1;
			else if (sByte[k] == '0')
				byte[k] = 0;
			else
				return 0;
		}
	} else {
		// This is the default behavior - we work only with big endian.
		for (int k=0; k<=7; k++) {
			if (sByte[k] == '1')
				byte[7-k] = 1;
			else if (sByte[k] == '0')
				byte[7-k] = 0;
			else
				return 0;
		}
	}

	return byte.to_ulong();
}

/**
* @brief Transforms a byte (i.e. string consisting of 0s and 1s) to
*        <tt>unsigned long</tt> for variable size of byte.
*
* @param[in] sByte String to be converted.
* @param[in] iByteSize Number of bits.
*
* @return The resulting converted number or 0 if an error occurred.
*/
unsigned long byteToULongVariable(const char *sByte, std::size_t iByteSize) {
	unsigned long value = 0;
	unsigned long add = 1;

	// We work only with big endian.
	for (int k = iByteSize - 1; k >= 0; k--) {
		if (sByte[k] == '1')
			value += add;
		else if (sByte[k] != '0')
			return 0;
		add *= 2;
	}
	return value;
}

/**
* @brief Transforms a byte (i.e. string consisting of 0s and 1s) to
*        <tt>unsigned long</tt> for variable size of byte.
*
* @param[in] sByte String to be converted.
* @param[in] iByteSize Number of bits.
* @param[in] switchBitsOrder Whether to switch LSB and MSB or not.
*
* @return The resulting converted number or 0 if an error occurred.
*/
unsigned long byteToULong(const char *sByte, std::size_t iByteSize, bool switchBitsOrder) {
	if (iByteSize == 8)
		return byteToULong8(sByte, switchBitsOrder);
	else
		return byteToULongVariable(sByte, iByteSize);
}

/**
* @brief Convert 80-bit (10-byte) <tt>long double</tt> binary data (byte array)
*        into 64-bit (8-byte) <tt>double</tt> binary data.
*
* @param[out] dest 64-bit double to create.
* @param[in] src 80-bit long double to convert.
*/
void double10ToDouble8(std::vector<unsigned char> &dest,
		const std::vector<unsigned char> &src) {
	// Taken from:
	// http://blogs.perl.org/users/rurban/2012/09/reading-binary-floating-point-numbers-numbers-part2.html
	dest.clear();
	dest.resize(8, 0);

	int expo, i, sign;
	// exponents 15 -> 11 bits
	sign = src[9] & 0x80;
	expo = (src[9] & 0x7f)<< 8 | src[8];
	if (expo == 0) {
	nul:
		if (sign)
			dest[7] |= 0x80;
		return;
	}
	expo -= 16383;       // - bias long double
	expo += 1023;        // + bias for double
	if (expo <= 0)       // underflow
		goto nul;
	if (expo > 0x7ff) {  // inf/nan
		dest[7] = 0x7f;
		dest[6] = src[7] == 0xc0 ? 0xf8 : 0xf0 ;
		goto nul;
	}
	expo <<= 4;
	dest[6] = expo & 0xff;
	dest[7] = (expo & 0x7f00) >> 8;
	if (sign)
		dest[7] |= 0x80;
	// long double frac 63 bits => 52 bits src[7] &= 0x7f; reset intbit 63.
	for (i = 0; i < 6; ++i) {
		dest[i + 1] |= (i == 5 ? src[7] & 0x7f : src[i + 2]) >> 3;
		dest[i] |= (src[i + 2] & 0x1f) << 5;
	}
	dest[0] |= src[1] >> 3;
}

/**
* @brief Swap bytes for Intel x86 16-bit little-endian immediate.
*
* @param val Original value.
*
* @return Value with swapped bytes
*/
unsigned short byteSwap16(unsigned short val) {
	return (0xFF00 & val) >> 8 | (0xFF & val) << 8;
}

/**
* @brief Swap bytes for Intel x86 32-bit little-endian immediate.
*
* @param val Original value.
*
* @return Value with swapped bytes
*/
unsigned int byteSwap32(unsigned int val) {
	return (0xFF000000 & val) >> 24 |
		(0xFF0000 & val) >> 8 |
		(0xFF00 & val) << 8 |
		(0xFF & val) << 24;
}

/**
* @brief Swap bytes for Intel x86 16-bit little-endian immediate.
*
* @param val Original value.
*
* @return Value with swapped bytes or original value if its size is not 16.
*/
std::string byteSwap16(const std::string &val) {
	if (val.length() != 16)
		return val;

	return val.substr(8, 8) + val.substr(0, 8);
}

/**
* @brief Swap bytes for Intel x86 32-bit little-endian immediate.
*
* @param val Original value.
*
* @return Value with swapped bytes or original value if its size is not 32.
*/
std::string byteSwap32(const std::string &val) {
	if (val.length() != 32)
		return val;

	return val.substr(24, 8) + val.substr(16, 8) +
		val.substr(8, 8) + val.substr(0, 8);
}

/**
 * @brief Convert unsigned integer to binary number in text format.
 * @param nValue Converted value.
 * @param nLength Bitlength of result.
 * @return Text representation of unsigned number in binary radix.
 **/
std::string unsignedToBinString(unsigned long long int nValue, int nLength) {
	auto r = std::bitset<64>(nValue).to_string();
	return r.substr(r.length() - nLength);
}

/**
 * @brief Convert binary number in text format to unsigned integer.
 * @param sValue text reprezentation of binary number
 * @return value in dec radix without sign
 **/
unsigned long long int binStringToUnsigned(const char *sValue) {
	char* end = nullptr;
	return strtoull(sValue, &end, 2);
}

/**
 * Convert binary number in text format to signed int
 * @param sValue text reprezentation of binary number in second supplement
 * @return value in dec radix with sign
 **/
long long int binStringToSigned(const char *sValue) {
	if (sValue[0] != '1') {
		return binStringToUnsigned(sValue);
	}

	bool bMeetOne = false;
	int ii = static_cast<int>(strlen(sValue)) - 1;
	unsigned long long int nExp = 1;
	unsigned long long int nReturn = 0;

	while (ii >= 0) {
		// if we meet number one, we start to inverse future number.
		if (!bMeetOne) {
			if (sValue[ii] == '1') {
				bMeetOne = true;
			}
			nReturn += sValue[ii] == '1' ? nExp : 0;
		}
		else {
			nReturn += sValue[ii] == '1' ? 0 : nExp;
		}
		nExp *= 2;
		ii--;
	}

	return nReturn * (-1);
}

/**
 * Convert hexadecimal string @c hexIn string into bytes.
 * There might be whitespaces in the string, e.g. "0b 84 d1 a0 80 60 40" is
 * the same as "0b84d1a0806040".
 */
std::vector<uint8_t> hexStringToBytes(const std::string& hexIn)
{
	std::vector<uint8_t> bytes;

	auto hex = removeWhitespace(hexIn);
	for (unsigned int i = 0; i < hex.length(); i += 2)
	{
		std::string byteString = hex.substr(i, 2);
		char byte = strtol(byteString.c_str(), nullptr, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

/**
 * Reverse function to @c hexStringToBytes(). It is using @c bytesToHexString()
 * to do the conversion, but inserts space afer every byte, e.g.
 * "0b 84 d1 a0 80 60 40".
 */
std::string bytesToHexString(const std::vector<uint8_t>& bytes)
{
	std::string str;
	bytesToHexString(bytes, str, 0, 0, false);

	std::stringstream ss;
	for (std::size_t i = 0; i < str.size(); ++i)
	{
		ss << str[i];
		if (i % 2 == 1 && i < (str.size()-1))
		{
			ss << " ";
		}
	}

	return ss.str();
}

} // namespace utils
} // namespace retdec
