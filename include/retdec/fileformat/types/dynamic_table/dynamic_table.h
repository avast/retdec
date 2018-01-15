/**
 * @file include/retdec/fileformat/types/dynamic_table/dynamic_table.h
 * @brief Class for dynamic table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_DYNAMIC_TABLE_DYNAMIC_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_DYNAMIC_TABLE_DYNAMIC_TABLE_H

#include <vector>

#include "retdec/fileformat/types/dynamic_table/dynamic_entry.h"

namespace retdec {
namespace fileformat {

/**
 * Dynamic table
 */
class DynamicTable
{
	private:
		using dynamicTableIterator = std::vector<DynamicEntry>::const_iterator;
		std::vector<DynamicEntry> table; ///< all records in table
	public:
		DynamicTable();
		~DynamicTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfRecords() const;
		const DynamicEntry* getRecord(std::size_t recordIndex) const;
		const DynamicEntry* getRecordOfType(unsigned long long recordType) const;
		/// @}

		/// @name Iterators
		/// @{
		dynamicTableIterator begin() const;
		dynamicTableIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		void clear();
		void addRecord(DynamicEntry &record);
		bool hasRecords() const;
		bool hasRecordOfType(unsigned long long recordType) const;
		void dump(std::string &dumpTable) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
