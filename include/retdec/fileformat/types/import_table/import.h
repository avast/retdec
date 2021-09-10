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
		std::uint64_t libraryIndex = 0;
		std::uint64_t address = 0;
		std::uint64_t ordinalNumber = 0;
		bool ordinalNumberIsValid = false;
		UsageType usageType = UsageType::UNKNOWN;
	public:
		virtual ~Import() = default;

		/// @name Getters
		/// @{
		std::string getName() const;
		std::uint64_t getLibraryIndex() const;
		std::uint64_t getAddress() const;
		bool getOrdinalNumber(std::uint64_t &importOrdinalNumber) const;
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
		void setLibraryIndex(std::uint64_t importLibraryIndex);
		void setAddress(std::uint64_t importAddress);
		void setOrdinalNumber(std::uint64_t importOrdinalNumber);
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
