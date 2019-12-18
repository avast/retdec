/**
 * @file include/retdec/fileformat/types/import_table/import.h
 * @brief Class for one import.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_IMPORT_TABLE_IMPORT_H
#define RETDEC_FILEFORMAT_TYPES_IMPORT_TABLE_IMPORT_H

#include <string>

namespace retdec {
namespace fileformat {

/**
 * One import
 */
class Import
{
	public:
		enum class UsageType
		{
			UNKNOWN,
			FUNCTION,
			OBJECT,
			FILE
		};

	private:
		std::string name;
		unsigned long long libraryIndex = 0;
		unsigned long long address = 0;
		unsigned long long ordinalNumber = 0;
		bool ordinalNumberIsValid = false;
		UsageType usageType = UsageType::UNKNOWN;
	public:
		virtual ~Import() = default;

		/// @name Getters
		/// @{
		std::string getName() const;
		unsigned long long getLibraryIndex() const;
		unsigned long long getAddress() const;
		bool getOrdinalNumber(unsigned long long &importOrdinalNumber) const;
		Import::UsageType getUsageType() const;
		/// @}

		/// @name Usage type queries
		/// @{
		bool isUnknown() const;
		bool isFunction() const;
		bool isObject() const;
		bool isFile() const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string importName);
		void setLibraryIndex(unsigned long long importLibraryIndex);
		void setAddress(unsigned long long importAddress);
		void setOrdinalNumber(unsigned long long importOrdinalNumber);
		void setUsageType(Import::UsageType importUsageType);
		/// @}

		/// @name Other methods
		/// @{
		virtual bool isUsedForImphash() const;
		void invalidateOrdinalNumber();
		bool hasEmptyName() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
