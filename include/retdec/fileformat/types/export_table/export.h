/**
 * @file include/retdec/fileformat/types/export_table/export.h
 * @brief Class for one export.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_EXPORT_TABLE_EXPORT_H
#define RETDEC_FILEFORMAT_TYPES_EXPORT_TABLE_EXPORT_H

#include <string>

namespace retdec {
namespace fileformat {

/**
 * One export
 */
class Export
{
	private:
		std::string name;
		std::uint64_t address = 0;
		std::uint64_t ordinalNumber = 0;
		bool ordinalNumberIsValid = false;
	public:
		virtual ~Export() = default;

		/// @name Getters
		/// @{
		std::string getName() const;
		std::uint64_t getAddress() const;
		bool getOrdinalNumber(std::uint64_t &exportOrdinalNumber) const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string exportName);
		void setAddress(std::uint64_t exportAddress);
		void setOrdinalNumber(std::uint64_t exportOrdinalNumber);
		/// @}

		/// @name Other methods
		/// @{
		virtual bool isUsedForExphash() const;
		void invalidateOrdinalNumber();
		bool hasEmptyName() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
