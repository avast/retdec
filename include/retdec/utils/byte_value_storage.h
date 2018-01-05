/**
 * @file include/retdec/utils/byte_value_storage.h
 * @brief Declaration of @c ByteValueStorage.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */
#ifndef RETDEC_UTILS_BYTE_VALUE_STORAGE_H
#define RETDEC_UTILS_BYTE_VALUE_STORAGE_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace retdec {
namespace utils {

/**
 * Endianness.
 */
enum class Endianness
{
	UNKNOWN,
	LITTLE,
	BIG
};

class ByteValueStorage
{
public:
	ByteValueStorage() = default;
	virtual ~ByteValueStorage() = default;

	virtual Endianness getEndianness() const = 0;
	virtual std::size_t getNibbleLength() const = 0;
	virtual std::size_t getByteLength() const = 0;
	virtual std::size_t getWordLength() const = 0;
	virtual std::size_t getBytesPerWord() const = 0;
	virtual std::size_t getNumberOfNibblesInByte() const = 0;
	virtual bool hasMixedEndianForDouble() const = 0;

	virtual bool getXByte(std::uint64_t address, std::uint64_t x, std::uint64_t& res, Endianness e = Endianness::UNKNOWN) const = 0;
	virtual bool getXBytes(std::uint64_t address, std::uint64_t x, std::vector<std::uint8_t>& res) const = 0;

	virtual bool setXByte(std::uint64_t address, std::uint64_t x, std::uint64_t val, Endianness e = Endianness::UNKNOWN) = 0;
	virtual bool setXBytes(std::uint64_t address, const std::vector<std::uint8_t>& val) = 0;

	Endianness getInverseEndianness() const;
	bool isLittleEndian() const;
	bool isBigEndian() const;
	bool isUnknownEndian() const;

	bool hexToBig(std::string& str) const;
	bool hexToLittle(std::string& str) const;
	bool bitsToBig(std::string& str) const;
	bool bitsToLittle(std::string& str) const;
	bool bitsToBig(std::vector<unsigned char>& values) const;
	bool bitsToLittle(std::vector<unsigned char>& values) const;

	bool get1Byte(std::uint64_t address, std::uint64_t& res, Endianness e = Endianness::UNKNOWN) const;
	bool get2Byte(std::uint64_t address, std::uint64_t& res, Endianness e = Endianness::UNKNOWN) const;
	bool get4Byte(std::uint64_t address, std::uint64_t& res, Endianness e = Endianness::UNKNOWN) const;
	bool get8Byte(std::uint64_t address, std::uint64_t& res, Endianness e = Endianness::UNKNOWN) const;
	bool get10Byte(std::uint64_t address, long double& res) const;
	bool getWord(std::uint64_t address, std::uint64_t& res, Endianness e = Endianness::UNKNOWN) const;
	bool getFloat(std::uint64_t address, float& res) const;
	bool getDouble(std::uint64_t address, double& res) const;

	bool set1Byte(std::uint64_t address, std::uint64_t val, Endianness e = Endianness::UNKNOWN);
	bool set2Byte(std::uint64_t address, std::uint64_t val, Endianness e = Endianness::UNKNOWN);
	bool set4Byte(std::uint64_t address, std::uint64_t val, Endianness e = Endianness::UNKNOWN);
	bool set8Byte(std::uint64_t address, std::uint64_t val, Endianness e = Endianness::UNKNOWN);
	bool set10Byte(std::uint64_t address, long double val);
	bool setWord(std::uint64_t address, std::uint64_t val, Endianness e = Endianness::UNKNOWN);
	bool setFloat(std::uint64_t address, float val);
	bool setDouble(std::uint64_t address, double val);

	bool getXByteArray(std::uint64_t address, std::uint64_t x, std::vector<std::uint64_t>& res, std::size_t size, Endianness e = Endianness::UNKNOWN) const;
	bool get1ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e = Endianness::UNKNOWN) const;
	bool get2ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e = Endianness::UNKNOWN) const;
	bool get4ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e = Endianness::UNKNOWN) const;
	bool get8ByteArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t size, Endianness e = Endianness::UNKNOWN) const;
	bool get10ByteArray(std::uint64_t address, std::vector<long double>& res, std::size_t size) const;
	bool getWordArray(std::uint64_t address, std::vector<std::uint64_t>& res, std::size_t, Endianness e = Endianness::UNKNOWN) const;
	bool getFloatArray(std::uint64_t address, std::vector<float>& res, std::size_t size) const;
	bool getDoubleArray(std::uint64_t address, std::vector<double>& res, std::size_t size) const;

	bool getNTBS(std::uint64_t address, std::string& res, std::size_t size = 0) const;
	bool getNTWS(std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const;
	bool getNTWSNice(std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const;

protected:
	bool createValueFromBytes(const std::vector<std::uint8_t>& data, std::uint64_t& value, Endianness endian, std::uint64_t offset = 0, std::uint64_t size = 0) const;
	bool createBytesFromValue(std::uint64_t data, std::uint64_t x, std::vector<std::uint8_t>& value, Endianness endian) const;

	bool get10ByteImpl(const std::vector<std::uint8_t>& data, long double& res) const;
	bool getFloatImpl(const std::vector<std::uint8_t>& data, float& res) const;
	bool getDoubleImpl(const std::vector<std::uint8_t>& data, double& res) const;

	using GetNByteFn = std::function<bool(std::uint64_t, std::uint64_t&, Endianness)>;
	using GetXByteFn = std::function<bool(std::uint64_t, std::uint64_t, std::uint64_t&, Endianness)>;
	bool getNTBSImpl(const GetNByteFn& get1ByteFn, std::uint64_t address, std::string& res, std::size_t size) const;
	bool getNTWSImpl(const GetXByteFn& getXByteFn, std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const;
	bool getNTWSNiceImpl(const GetXByteFn& getXByteFn, std::uint64_t address, std::size_t width, std::vector<std::uint64_t>& res) const;
};

} // namespace utils
} // namespace retdec

#endif
