/**
 * @file src/utils/byte_value_storage.cpp
 * @brief Implementation of @c ByteValueStorage.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */
#include <cassert>
#include <cstring>

#include "retdec/utils/byte_value_storage.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/utils/system.h"

namespace retdec {
namespace utils {

namespace {

/**
 * Convert endianness
 *
 * @param str String which will be converted
 * @param items Number of items in one word of converted string
 * @param length Length of one item in word
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool swapEndianness(std::string &str, std::size_t items, std::size_t length = 1)
{
	if (!length || !items || str.size() < items * length)
	{
		return false;
	}

	const auto middleWordIndex = items / 2;
	const auto middleLengthIndex = length / 2;
	const auto wasteLen = str.size() % (items * length);
	str.erase(str.size() - wasteLen, wasteLen);

	for (std::size_t i = 0, e = str.size(); i < e; i += items * length)
	{
		for (std::size_t j = 0; j < middleWordIndex; ++j)
		{
			for (std::size_t k = 0; k < length; ++k)
			{
				std::swap(str[i + j * length + k], str[i + (items - j) * length - k - 1]);
			}
		}

		if (middleWordIndex && middleLengthIndex)
		{
			for (std::size_t j = 0; j < items; ++j)
			{
				for (std::size_t k = 0; k < middleLengthIndex; ++k)
				{
					std::swap(str[i + j * length + k], str[i + (j + 1) * length - k - 1]);
				}
			}
		}
	}

	return true;
}

/**
 * Convert endianness
 *
 * @param values Values for conversion
 * @param items Number of bits in one value from @a values
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool swapEndianness(std::vector<unsigned char>& values, std::size_t items)
{
	if (!items)
	{
		return false;
	}

	for (std::size_t i = 0, e = values.size(); i < e; ++i)
	{
		unsigned char a = 1, b = 1, y = 0;
		a <<= (sizeof(a) * items) - 1;

		while (a)
		{
			if (values[i] & b)
			{
				y |= a;
			}
			a >>= 1;
			b <<= 1;
		}

		values[i] = y;
	}

	return true;
}

} // anonymous namespace

/**
 * Get opposite endianness
 *
 * @return Endianness::LITTLE if input file is in big endian and vice versa
 * @retval Endianness::UNKNOWN if file endianness is unknown
 */
Endianness ByteValueStorage::getInverseEndianness() const
{
	switch (getEndianness())
	{
		case Endianness::LITTLE:
			return Endianness::BIG;
		case Endianness::BIG:
			return Endianness::LITTLE;
		case Endianness::UNKNOWN:
			return Endianness::UNKNOWN;
		default:
			assert(false && "Unexpected value of a switch expression");
			return Endianness::UNKNOWN;
	}
}

/**
 * Find out if endianness is little
 *
 * @return @c true if endianness is little, @c false otherwise
 */
bool ByteValueStorage::isLittleEndian() const
{
	return getEndianness() == Endianness::LITTLE;
}

/**
 * Find out if endianness is big
 *
 * @return @c true if endianness is big, @c false otherwise
 */
bool ByteValueStorage::isBigEndian() const
{
	return getEndianness() == Endianness::BIG;
}

/**
 * Find out if endianness is unknown
 *
 * @return @c true if endianness is unknown, @c false otherwise
 */
bool ByteValueStorage::isUnknownEndian() const
{
	return getEndianness() == Endianness::UNKNOWN;
}

/**
 * Convert hexadecimal string to big endian
 *
 * @param str String which will be converted
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::hexToBig(std::string& str) const
{
	if (isUnknownEndian())
	{
		return false;
	}

	return isBigEndian() ? true : swapEndianness(str, getBytesPerWord(), getNumberOfNibblesInByte());
}

/**
 * Convert hexadecimal string to little endian
 *
 * @param str String which will be converted
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::hexToLittle(std::string& str) const
{
	if (isUnknownEndian())
	{
		return false;
	}

	return isLittleEndian() ? true : swapEndianness(str, getBytesPerWord(), getNumberOfNibblesInByte());
}

/**
 * Convert bit string to big endian
 *
 * @param str String which will be converted
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::bitsToBig(std::string& str) const
{
	if (isUnknownEndian())
	{
		return false;
	}

	return isBigEndian() ? true : swapEndianness(str, getByteLength());
}

/**
 * Convert bit string to little endian
 *
 * @param str String which will be converted
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::bitsToLittle(std::string& str) const
{
	if (isUnknownEndian())
	{
		return false;
	}

	return isLittleEndian() ? true : swapEndianness(str, getByteLength());
}

/**
 * Convert bits to big endian
 *
 * @param values Bits for conversion stored as bytes
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::bitsToBig(std::vector<unsigned char>& values) const
{
	if (isUnknownEndian())
	{
		return false;
	}

	return isBigEndian() ? true : swapEndianness(values, getByteLength());
}

/**
 * Convert bits to little endian
 *
 * @param values Bits for conversion stored as bytes
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::bitsToLittle(std::vector<unsigned char>& values) const
{
	if (isUnknownEndian())
	{
		return false;
	}

	return isLittleEndian() ? true : swapEndianness(values, getByteLength());
}

/**
 * Get integer (1B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get1Byte(std::uint64_t address, std::uint64_t& res, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByte(address, 1, res, e);
}

/**
 * Get integer (2B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get2Byte(std::uint64_t address, std::uint64_t& res, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByte(address, 2, res, e);
}

/**
 * Get integer (4B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get4Byte(std::uint64_t address, std::uint64_t& res, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByte(address, 4, res, e);
}

/**
 * Get integer (8B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get8Byte(std::uint64_t address, std::uint64_t& res, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByte(address, 8, res, e);
}

/**
 * Get long double from the specified address.
 * If system has 80-bit (10-byte) long double, copy data directly.
 * Else convert 80-bit (10-byte) long double into 64-bit (8-byte) double.
 *
 * @param address Address to get double from
 * @param res Result double
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get10Byte(std::uint64_t address, long double& res) const
{
	std::vector<std::uint8_t> d10;
	if (!getXBytes(address, 10, d10))
	{
		return false;
	}

	if (!get10ByteImpl(d10, res))
	{
		return false;
	}

	return true;
}

/**
 * Get word located at provided address using the specified endian or default file endian
 *
 * @param address Address to get integer from
 * @param res Result integer
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getWord(std::uint64_t address, std::uint64_t& res, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByte(address, getBytesPerWord(), res, e);
}

/**
 * Get float from the specified address.
 *
 * @param address Address to get float from
 * @param res Result float
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getFloat(std::uint64_t address, float& res) const
{
	std::vector<std::uint8_t> d;
	if (!getXBytes(address, sizeof(float), d) || d.size() != sizeof(float))
	{
		return false;
	}

	memcpy(&res, d.data(), d.size());
	return true;
}

/**
 * Get double from the specified address.
 *
 * @param address Address to get double from
 * @param res Result double
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getDouble(std::uint64_t address, double& res) const
{
	std::vector<std::uint8_t> d;
	if (!getXBytes(address, sizeof(double), d) || d.size() != sizeof(double))
	{
		return false;
	}

	// 2.33 (0x4002a3d7 0a3d70a4) in data section as: d7a30240 a4703d0a
	// but only on old (pre version 5?) ARM architecture with ELF format.
	if (hasMixedEndianForDouble())
	{
		for (std::size_t i = 0; i < sizeof(double) / 2; ++i)
		{
			std::swap(d[i], d[i + 4]);
		}
	}
	// 2.33 (0x4002a3d7 0a3d70a4) in data section as: a4703d0a d7a30240.
	// New ARM compilers are also generating this kind of double constants.
	// We are not sure, what part of binary determines which kind of double constants are used.
	// Currently we use new kind for ARMs > version 5.
	// To find relevant info, google: "ARM double mixed endian".

	memcpy(&res, d.data(), d.size());
	return true;
}

/**
 * Set integer (1B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to set integer at
 * @param val Integer to set
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::set1Byte(std::uint64_t address, std::uint64_t val, Endianness e /*= Endianness::UNKNOWN*/)
{
	return setXByte(address, 1, val, e);
}

/**
 * Set integer (2B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to set integer at
 * @param val Integer to set
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::set2Byte(std::uint64_t address, std::uint64_t val, Endianness e /*= Endianness::UNKNOWN*/)
{
	return setXByte(address, 2, val, e);
}

/**
 * Set integer (4B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to set integer at
 * @param val Integer to set
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::set4Byte(std::uint64_t address, std::uint64_t val, Endianness e /*= Endianness::UNKNOWN*/)
{
	return setXByte(address, 4, val, e);
}

/**
 * Set integer (8B) located at provided address using the specified endian or default file endian
 *
 * @param address Address to set integer at
 * @param val Integer to set
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::set8Byte(std::uint64_t address, std::uint64_t val, Endianness e /*= Endianness::UNKNOWN*/)
{
	return setXByte(address, 8, val, e);
}

/**
 * Set long double at the specified address.
 * If system has 80-bit (10-byte) long double, copy data directly.
 * Else convert 80-bit (10-byte) long double into 64-bit (8-byte) double.
 *
 * @param address Address to set double at
 * @param val Double to set
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::set10Byte(std::uint64_t address, long double val)
{
	std::vector<std::uint8_t> bytes;
	if (systemHasLongDouble())
		bytes.resize(10);
	else
		bytes.resize(8);

	memcpy(bytes.data(), &val, bytes.size());
	return setXBytes(address, bytes);
}

/**
 * Set word located at provided address using the specified endian or default file endian
 *
 * @param address Address to set integer at
 * @param val Integer to set
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::setWord(std::uint64_t address, std::uint64_t val, Endianness e /*= Endianness::UNKNOWN*/)
{
	return setXByte(address, getBytesPerWord(), val, e);
}

/**
 * Set float at the specified address.
 *
 * @param address Address to set float at
 * @param val Float to set
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::setFloat(std::uint64_t address, float val)
{
	std::vector<std::uint8_t> bytes(sizeof(float));
	memcpy(bytes.data(), &val, sizeof(float));
	return setXBytes(address, bytes);
}

/**
 * Set double at the specified address.
 *
 * @param address Address to set double at
 * @param val Double to set
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::setDouble(std::uint64_t address, double val)
{
	std::vector<std::uint8_t> bytes(sizeof(double));
	memcpy(bytes.data(), &val, sizeof(double));

	if (hasMixedEndianForDouble())
	{
		for (std::size_t i = 0; i < sizeof(double) / 2; ++i)
		{
			std::swap(bytes[i], bytes[i + 4]);
		}
	}

	return setXBytes(address, bytes);
}

/**
 * Get NTBS (null-terminated byte string) from specified address
 *
 * @param address Address to get string from
 * @param res Result string
 * @param size Requested size of string (if @a size is zero, read until zero byte)
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getNTBS(std::uint64_t address, std::string& res, std::size_t size/* = 0*/) const
{
	using namespace std::placeholders;

	GetNByteFn get1ByteFn = std::bind(&ByteValueStorage::get1Byte, this, _1, _2, _3);
	return getNTBSImpl(get1ByteFn, address, res, size);
}

/**
 * Get NTWS (null-terminated wide string) from the specified address
 *
 * @param address Address to get string from
 * @param width Byte width of one character
 * @param res Result character array
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 *
 * @note This will read items until it reaches zero (null terminator),
 *       it can potentially create huge non-nice vectors.
 *       Use this only if your are certain there is wide string on the address.
 *       See @c getNTWSNice() for a faster wide-string-probing method.
 */
bool ByteValueStorage::getNTWS(std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const
{
	using namespace std::placeholders;

	GetXByteFn getXByteFn = std::bind(&ByteValueStorage::getXByte, this, _1, _2, _3, _4);
	return getNTWSImpl(getXByteFn, address, width, res);
}

/**
 * Get nice NTWS (null-terminated wide string of ASCII characters) from the
 *
 * specified address
 * @param address Address to get string from
 * @param width Byte width of one character
 * @param res Result character array
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 *
 * @note This will read items until it reaches zero (null terminator) or
 *       non-ASCII character. Use this for fast wide string probing.
 *       See @c getNTWS() for a slower wide-string-forcing method.
 */
bool ByteValueStorage::getNTWSNice(std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const
{
	using namespace std::placeholders;

	GetXByteFn getXByteFn = std::bind(&ByteValueStorage::getXByte, this, _1, _2, _3, _4);
	return getNTWSNiceImpl(getXByteFn, address, width, res);
}

/**
 * Get integer (@a x bytes) array located at provided address using the specified array size and endian (or default file endian)
 *
 * @param address Address to get integer array from
 * @param x Number of bytes for one array item
 * @param res Result integer array
 * @param size Integer array size (how many items are to be read)
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getXByteArray(std::uint64_t address, std::uint64_t x, std::vector<std::uint64_t>& res, std::size_t size, Endianness e/* = Endianness::UNKNOWN*/) const
{
	std::uint64_t r = 0;

	for (std::size_t i = 0; i < size; ++i)
	{
		if (getXByte(address, x, r, e))
		{
			res.push_back(r);
			address += x;
		}
		else
		{
			return false;
		}
	}

	return true;
}

/**
 * Get integer (1B) array located at provided address using the specified array size and endian (or default file endian)
 *
 * @param address Address to get integer array from
 * @param res Result integer array
 * @param size Integer array size (how many items are to be read)
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get1ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByteArray(address, 1, res, size, e);
}

/**
 * Get integer (2B) array located at provided address using the specified array size and endian (or default file endian)
 *
 * @param address Address to get integer array from
 * @param res Result integer array
 * @param size Integer array size (how many items are to be read)
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get2ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByteArray(address, 2, res, size, e);
}

/**
 * Get integer (4B) array located at provided address using the specified array size and endian (or default file endian)
 *
 * @param address Address to get integer array from
 * @param res Result integer array
 * @param size Integer array size (how many items are to be read)
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get4ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByteArray(address, 4, res, size, e);
}

/**
 * Get integer (8B) array located at provided address using the specified array size and endian (or default file endian)
 *
 * @param address Address to get integer array from
 * @param res Result integer array
 * @param size Integer array size (how many items are to be read)
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get8ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByteArray(address, 8, res, size, e);
}

/**
 * Get long double (10B) array located at provided address using the specified array size
 *
 * @param address Address to get long double from
 * @param res Result long double array
 * @param size Array size (how many items are to be read)
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::get10ByteArray(std::uint64_t address, std::vector<long double>& res, std::size_t size) const
{
	long double r = 0;

	for (std::size_t i = 0; i < size; ++i)
	{
		if (get10Byte(address, r))
		{
			res.push_back(r);
			address += 10;
		}
		else
		{
			return false;
		}
	}

	return true;
}

/**
 * Get word array located at provided address using the specified size and endian (or default file endian)
 *
 * @param address Address to get integer from
 * @param res Result integer
 * @param size Word array size (how many items are to be read)
 * @param e Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getWordArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e/* = Endianness::UNKNOWN*/) const
{
	return getXByteArray(address, getBytesPerWord(), res, size, e);
}

/**
 * Get float array located at provided address using the specified array size
 *
 * @param address Address to get float from
 * @param res Result float array
 * @param size Array size (how many items are to be read)
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getFloatArray(std::uint64_t address, std::vector<float>& res, std::size_t size) const
{
	float r = 0;

	for (std::size_t i = 0; i < size; ++i)
	{
		if (getFloat(address, r))
		{
			res.push_back(r);
			address += sizeof(float);
		}
		else
		{
			return false;
		}
	}

	return true;
}

/**
 * Get double array located at provided address using the specified array size
 *
 * @param address Address to get double from
 * @param res Result double array
 * @param size Array size (how many items are to be read)
 *
 * @return Status of operation (@c true if all is OK, @c false otherwise)
 */
bool ByteValueStorage::getDoubleArray(std::uint64_t address, std::vector<double>& res, std::size_t size) const
{
	double r = 0;

	for (std::size_t i = 0; i < size; ++i)
	{
		if (getDouble(address, r))
		{
			res.push_back(r);
			address += sizeof(float);
		}
		else
		{
			return false;
		}
	}

	return true;
}

/**
 * Create integer from vector of bytes
 *
 * @param data Vector of bytes
 * @param value Resulted value
 * @param endian Endian - if specified it is forced, otherwise file's endian is used
 * @param offset Offset of first byte from @a data which will be converted
 *    (0 means first offset from @a data)
 * @param size Number of bytes for conversion (0 means all bytes from @a offset
 *    to end of @a data)
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::createValueFromBytes(const std::vector<std::uint8_t>& data, std::uint64_t& value, Endianness endian, std::uint64_t offset/* = 0*/, std::uint64_t size/* = 0*/) const
{
	const std::uint64_t realSize = (!size || offset + size > data.size()) ? data.size() - offset : size;
	if (offset >= data.size() || (size && realSize != size))
	{
		return false;
	}

	if (endian == Endianness::UNKNOWN && isLittleEndian())
	{
		endian = Endianness::LITTLE;
	}
	else if (endian == Endianness::UNKNOWN && isBigEndian())
	{
		endian = Endianness::BIG;
	}
	else if (endian == Endianness::UNKNOWN)
	{
		return false;
	}

	value = 0;

	for (std::uint64_t i = 0; i < realSize; ++i)
	{
		value += static_cast<std::uint64_t>(data[offset + i]) << (getByteLength() * (endian == Endianness::LITTLE ? i : realSize - i - 1));
	}

	return true;
}

/**
 * Create vector of bytes from integer
 *
 * @param data Integer
 * @param x Width of integer
 * @param value Resulted vector of bytes
 * @param endian Endian - if specified it is forced, otherwise file's endian is used
 *
 * @return @c true if conversion went OK, @c false otherwise
 */
bool ByteValueStorage::createBytesFromValue(std::uint64_t data, std::uint64_t x, std::vector<std::uint8_t>& value, Endianness endian) const
{
	if (endian == Endianness::UNKNOWN && isLittleEndian())
	{
		endian = Endianness::LITTLE;
	}
	else if (endian == Endianness::UNKNOWN && isBigEndian())
	{
		endian = Endianness::BIG;
	}
	else if (endian == Endianness::UNKNOWN)
	{
		return false;
	}

	value.clear();
	value.resize(x);

	for (std::uint8_t i = 0; i < x; ++i)
	{
		if (endian == Endianness::LITTLE)
			value[i] = (data >> (getByteLength() * i)) & 0xFF;
		else
			value[i] = (data >> (getByteLength() * (x - i - 1))) & 0xFF;
	}

	return true;
}

bool ByteValueStorage::get10ByteImpl(const std::vector<std::uint8_t>& data, long double& res) const
{
	if (systemHasLongDouble())
	{
		memcpy(&res, data.data(), data.size());
	}
	else
	{
		std::vector<std::uint8_t> d8;
		double10ToDouble8(d8, data);
		memcpy(&res, d8.data(), d8.size());
	}

	return true;
}

bool ByteValueStorage::getFloatImpl(const std::vector<std::uint8_t>& data, float& res) const
{
	if (data.size() != sizeof(float))
	{
		return false;
	}

	memcpy(&res, data.data(), data.size());
	return true;
}

bool ByteValueStorage::getDoubleImpl(const std::vector<std::uint8_t>& data, double& res) const
{
	if (data.size() != sizeof(double))
	{
		return false;
	}

	memcpy(&res, data.data(), data.size());
	return true;
}

bool ByteValueStorage::getNTBSImpl(const GetNByteFn& get1ByteFn, std::uint64_t address, std::string& res, std::size_t size) const
{
	std::uint64_t c = 0;
	auto suc = get1ByteFn(address, c, getEndianness());
	res.clear();

	while (suc && (c || size))
	{
		res += c;
		if (size && res.length() == size)
		{
			break;
		}
		suc = get1ByteFn(++address, c, getEndianness());
	}

	return !res.empty();
}

bool ByteValueStorage::getNTWSImpl(const GetXByteFn& getXByteFn, std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const
{
	std::vector<std::uint64_t> tmp;
	std::uint64_t item = 0;
	res.clear();

	bool ret = false;
	while (getXByteFn(address, width, item, getEndianness()))
	{
		tmp.push_back(item);
		if (!item)
		{
			ret = true;
			break;
		}
		else
		{
			address += width;
		}
	}

	if (!tmp.empty())
	{
		res = tmp;
	}

	return ret;
}

bool ByteValueStorage::getNTWSNiceImpl(const GetXByteFn& getXByteFn, std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const
{
	std::vector<std::uint64_t> tmp;
	std::uint64_t item = 0;
	res.clear();

	while (getXByteFn(address, width, item, getEndianness()))
	{
		tmp.push_back(item);
		if (!item)
		{
			break;
		}
		else if (isNiceAsciiWideCharacter(item))
		{
			address += width;
		}
		else
		{
			return false;
		}
	}

	if (!tmp.empty())
	{
		res = tmp;
	}

	// one char (trailing '0') is not enough
	return tmp.size() > 1;
}

} // namespace utils
} // namespace retdec
