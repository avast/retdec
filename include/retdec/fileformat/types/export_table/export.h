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
		std::string name;                 ///< export name
		unsigned long long address;       ///< address of export
		unsigned long long ordinalNumber; ///< ordinal number
		bool ordinalNumberIsValid;        ///< @c true if ordinal number is valid
	public:
		Export();
		~Export();

		/// @name Getters
		/// @{
		std::string getName() const;
		unsigned long long getAddress() const;
		bool getOrdinalNumber(unsigned long long &exportOrdinalNumber) const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string exportName);
		void setAddress(unsigned long long exportAddress);
		void setOrdinalNumber(unsigned long long exportOrdinalNumber);
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
