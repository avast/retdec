/**
 * @file src/fileinfo/file_information/file_information_types/relocation_table/relocation_table.h
 * @brief Class for relocation table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RELOCATION_TABLE_RELOCATION_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RELOCATION_TABLE_RELOCATION_TABLE_H

#include <vector>

#include "fileinfo/file_information/file_information_types/relocation_table/relocation.h"

namespace fileinfo {

/**
 * Class for relocation table
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for numeric types.
 * Methods with index parameters does not perform control of indexes.
 */
class RelocationTable
{
	private:
		std::string name;                              ///< name of relocation table
		std::string associatedSymbolTableName;         ///< name of symbol table associated with relocation table
		std::string appliesSectionName;                ///< name of section to which the relocation applies
		unsigned long long associatedSymbolTableIndex; ///< index of symbol table associated with relocation table
		unsigned long long appliesSectionIndex;        ///< index of section to which the relocation applies
		unsigned long long declaredRelocations;        ///< declared number of relocations in table
		std::vector<Relocation> table;                 ///< relocation entries
	public:
		RelocationTable();
		~RelocationTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfStoredRelocations() const;
		std::string getNumberOfStoredRelocationsStr() const;
		std::string getNumberOfDeclaredRelocationsStr() const;
		std::string getTableName() const;
		std::string getAssociatedSymbolTableName() const;
		std::string getAppliesSectionName() const;
		std::string getAssociatedSymbolTableIndex() const;
		std::string getAppliesSectionIndex() const;
		std::string getRelocationSymbolName(std::size_t position) const;
		std::string getRelocationOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getRelocationSymbolValueStr(std::size_t position) const;
		std::string getRelocationTypeStr(std::size_t position) const;
		std::string getRelocationAddendStr(std::size_t position) const;
		std::string getRelocationCalculatedValueStr(std::size_t position) const;
		/// @}

		/// @name Setters
		/// @{
		void setTableName(std::string tableName);
		void setAssociatedSymbolTableName(std::string symbolTableName);
		void setAppliesSectionName(std::string sectionName);
		void setAssociatedSymbolTableIndex(unsigned long long index);
		void setAppliesSectionIndex(unsigned long long index);
		void setNumberOfDeclaredRelocations(unsigned long long relocations);
		/// @}

		/// @name Other methods
		/// @{
		void addRelocation(Relocation &relocation);
		void clearRelocations();
		/// @}
};

} // namespace fileinfo

#endif
