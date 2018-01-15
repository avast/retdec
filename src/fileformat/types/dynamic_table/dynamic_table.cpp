/**
 * @file src/fileformat/types/dynamic_table/dynamic_table.cpp
 * @brief Class for dynamic table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/fileformat/types/dynamic_table/dynamic_table.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
DynamicTable::DynamicTable()
{

}

/**
 * Destructor
 */
DynamicTable::~DynamicTable()
{

}

/**
 * Get number of records in table
 * @return Number of records in table
 */
std::size_t DynamicTable::getNumberOfRecords() const
{
	return table.size();
}

/**
 * Get record from table
 * @param recordIndex Index of record in table (indexed from 0)
 * @return Pointer to selected record or @c nullptr if index of record is incorrect
 */
const DynamicEntry* DynamicTable::getRecord(std::size_t recordIndex) const
{
	return (recordIndex < getNumberOfRecords()) ? &table[recordIndex] : nullptr;
}

/**
 * Get record of specified type from table
 * @param recordType Required type of record
 * @return Pointer to first record from table which have type equal to @a recordType,
 *    or @c nullptr if such record does not exist
 */
const DynamicEntry* DynamicTable::getRecordOfType(unsigned long long recordType) const
{
	for(const auto &item : table)
	{
		if(item.getType() == recordType)
		{
			return &item;
		}
	}

	return nullptr;
}

/**
 * Get begin of records
 * @return Begin of dynamic table records
 */
DynamicTable::dynamicTableIterator DynamicTable::begin() const
{
	return table.begin();
}

/**
 * Get end of records
 * @return End of dynamic table records
 */
DynamicTable::dynamicTableIterator DynamicTable::end() const
{
	return table.end();
}

/**
 * Delete all records from table
 */
void DynamicTable::clear()
{
	table.clear();
}

/**
 * Add new record
 * @param record Record which will be added
 */
void DynamicTable::addRecord(DynamicEntry &record)
{
	table.push_back(record);
}

/**
 * Find out if there are any records
 * @return @c true if there are some records, @c false otherwise
 */
bool DynamicTable::hasRecords() const
{
	return !table.empty();
}

/**
 * Check if record with type @a recordType is present in table
 * @param recordType Type of record
 * @return @c true if has record with type @a recordType, @c false otherwise
 */
bool DynamicTable::hasRecordOfType(unsigned long long recordType) const
{
	return getRecordOfType(recordType);
}

/**
 * Dump information about dynamic table
 * @param dumpTable Into this parameter is stored dump of dynamic table in an LLVM style
 */
void DynamicTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Dynamic table ------------\n";
	ret << "; Number of records: " << getNumberOfRecords() << "\n";

	if(hasRecords())
	{
		ret << ";\n";
		for(const auto &item : table)
		{
			ret << "; " << item.getDescription() << " (type: " << item.getType() << ", value: " << item.getValue() << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
