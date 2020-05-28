/**
 * @file include/retdec/yaracpp/yara_match.h
 * @brief Library representation of one YARA match.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_YARACPP_YARA_MATCH_H
#define RETDEC_YARACPP_YARA_MATCH_H

#include <cstdint>
#include <vector>

namespace retdec {
namespace yaracpp {

/**
 * Representation of one match
 */
class YaraMatch
{
	private:
		std::size_t offset;
		std::vector<std::uint8_t> data;
	public:
		/// @name Getters
		/// @{
		std::size_t getOffset() const;
		std::size_t getDataSize() const;
		const std::vector<std::uint8_t>& getData() const;
		/// @}

		/// @name Setters
		/// @{
		void setOffset(std::size_t offsetValue);
		void setData(const std::uint8_t* dataBuffer, std::size_t dataLength);
		/// @}

		/// @name Other methods
		/// @{
		void addByte(std::uint8_t byte);
		/// @}
};

} // namespace yaracpp
} // namespace retdec

#endif
