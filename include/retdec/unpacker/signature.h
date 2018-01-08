/**
 * @file include/retdec/unpacker/signature.h
 * @brief Declaration of class for matching signatures in executable files or buffers.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_SIGNATURE_H
#define RETDEC_UNPACKER_SIGNATURE_H

#include <cstdint>
#include <initializer_list>
#include <vector>

#include "retdec/loader/loader.h"
#include "retdec/unpacker/dynamic_buffer.h"

namespace retdec {
namespace unpacker {

/**
 * Creates wildcard byte.
 */
#define ANY             Signature::Byte(Signature::Byte::Type::WILDCARD, 0x0, 0xFF)

/**
 * Creates wildcard capture byte.
 */
#define CAP             Signature::Byte(Signature::Byte::Type::CAPTURE, 0x0, 0xFF)

/**
 * Creates per-bit wildcard byte with specified expected value and wildcard mask.
 */
#define ANYB(exp, mask) Signature::Byte(Signature::Byte::Type::WILDCARD, exp, mask)

/**
 * Creates per-bit wildcard capture byte with specified expected value and wildcard mask.
 */
#define CAPB(exp, mask) Signature::Byte(Signature::Byte::Type::CAPTURE, exp, mask)

/**
 * Class for storing the signatures that can be matched against another file or another DynamicBuffer.
 * Signature can contains three type of bytes
 *      1. Exact byte values
 *      2. Wildcard
 *      3. Capture
 *
 *  Exact byte values are equal to the expected byte value that should be at the specific position in the matched data.
 *  Wildcard can specify the bytes that can have any value but are still matched as equal.
 *  Capture bytes are same as wildcard bytes but they are also put into the capture buffer and can be later obtained from the caller.
 *
 *  Signatures can also be specified for per-bit-matching, not only per-byte-matching. The expected value and wildcard bits are distinguished
 *  using wildcard mask in Signature::Byte class.
 *
 *  Signature matching on files is being done only on section or segment that contains entry point.
 */
class Signature
{
public:
	/**
	 * Class that represents the settings for matching a signature. The settings contains the offset of where to
	 * start matching.and also the the maximum searching distance if the signature is not on static position.
	 */
	class MatchSettings
	{
	public:
		MatchSettings(uint64_t offset = 0, uint64_t searchDistance = 0);
		MatchSettings(const MatchSettings& settings);
		~MatchSettings();

		uint64_t getOffset() const;
		void setOffset(uint64_t offset);

		uint32_t getSectionOrSegmentIndex() const;
		void setSectionOrSegmentIndex(uint32_t secSegIndex);

		bool isSearch() const;
		uint64_t getSearchDistance() const;
		void setSearchDistance(uint64_t distance);

	private:
		MatchSettings& operator =(const MatchSettings&);

		uint64_t _offset; ///< Offset where to start matching.
		uint64_t _searchDistance; ///< Maximum searching distance. No searching if this is set 0.
	};

	/**
	 * Represents single byte in signature that is used by Signature class. Bits that are set in wildcardMask to 1 are wildcarded and are matched as always equal.
	 * expectedValue contains the exact value of the bits that is expected. If there is collision between wildcard mask
	 * and expected value, the bits that are set in expected value and wildcard mask simultaneously are set back to 0
	 * in expected value.
	 *
	 * Examples:
	 * - EXACT BYTE - matches only 0xA3
	 *     - Expected value = 10100011b (0xA3)
	 *     - Wildcard mask  = 00000000b (0x00)
	 *
	 * - PURE WILCARD BYTE - matches any byte
	 *     - Expected value = 00000000b (0x00)
	 *     - Wildcard mask  = 11111111b (0xFF)
	 *
	 * - BIT-BASED WILDCARD BYTE - matches any bytes that has lowest 4 bits equal to 0x5 (0x05, 0x15, 0x25 ...)
	 *     - Expected value = 00000101b (0x05)
	 *     - Wildcard mask  = 11110000b (0xF0)
	 *
	 * There are macros which allow shorter initialization of Signature::Byte - these are @ref ANY, @ref CAP, @ref ANYB and @ref CAPB.
	 */
	class Byte
	{
	public:
		/**
		 * Type of the signature byte.
		 */
		enum class Type
		{
			NORMAL, ///< Exact byte.
			WILDCARD, ///< Wildcard byte.
			CAPTURE ///< Wildcard with capture.
		};

		Byte();
		Byte(uint8_t byte);
		Byte(Type type, uint8_t expectedValue, uint8_t wildcardMask);
		Byte(const Byte& byte);

		~Byte();

		Type getType() const;
		uint8_t getExpectedValue() const;
		uint8_t getWildcardMask() const;

		Byte& operator =(uint8_t rhs);
		Byte& operator =(Byte rhs);
		bool operator ==(uint8_t rhs) const;
		friend bool operator ==(uint8_t lhs, const Byte& rhs);
		bool operator !=(uint8_t rhs) const;
		friend bool operator !=(uint8_t lhs, const Byte& rhs);

	private:

		Type _type; ///< Type of the byte.
		uint8_t _expectedValue; ///< Expected value of the byte.
		uint8_t _wildcardMask; ///< Wildcard mask specifying the bits that are wildcard and that are exact.
	};

	Signature() = delete;
	Signature(const std::initializer_list<Signature::Byte>& initList);
	Signature(const Signature& signature);

	virtual ~Signature();

	uint64_t getSize() const;
	uint64_t getCaptureSize() const;

	bool match(const MatchSettings& settings, retdec::loader::Image* file) const;
	bool match(const MatchSettings& settings, const DynamicBuffer& data) const;
	bool match(const MatchSettings& settings, retdec::loader::Image* file, DynamicBuffer& captures) const;
	bool match(const MatchSettings& settings, const DynamicBuffer& data, DynamicBuffer& captures) const;

	Signature& operator =(const std::initializer_list<Signature::Byte>& initList);

private:
	Signature& operator =(const Signature&);

	bool searchMatchImpl(const std::vector<uint8_t>& bytesToMatch, uint64_t offset, uint64_t maxSearchDist, DynamicBuffer* captureBuffer) const;
	int64_t matchImpl(const std::vector<uint8_t>& bytesToMatch, uint64_t offset, DynamicBuffer* captureBuffer) const;

	std::vector<Signature::Byte> _buffer; ///< Signature bytes buffer.
};

} // namespace unpacker
} // namespace retdec

#endif
