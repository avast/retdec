/**
 * @file include/retdec/fileformat/types/dynamic_table/dynamic_entry.h
 * @brief Class for dynamic entry.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DYNAMIC_TABLE_DYNAMIC_ENTRY_H
#define RETDEC_FILEFORMAT_TYPES_DYNAMIC_TABLE_DYNAMIC_ENTRY_H

#include <string>

namespace retdec {
namespace fileformat {

/**
 * Information about dynamic entry
 */
class DynamicEntry
{
	private:
		unsigned long long type;  ///< type of the dynamic record
		unsigned long long value; ///< stored value
		std::string description;  ///< description
	public:
		DynamicEntry();
		~DynamicEntry();

		/// @name Getters
		/// @{
		unsigned long long getType() const;
		unsigned long long getValue() const;
		std::string getDescription() const;
		/// @}

		/// @name Setters
		/// @{
		void setType(unsigned long long entryType);
		void setValue(unsigned long long entryValue);
		void setDescription(std::string entryDescription);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
