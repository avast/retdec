/**
 * @file src/fileinfo/file_information/file_information_types/symbol_table/symbol_table.h
 * @brief Class for symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_SYMBOL_TABLE_SYMBOL_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_SYMBOL_TABLE_SYMBOL_TABLE_H

#include "fileinfo/file_information/file_information_types/special_information.h"
#include "fileinfo/file_information/file_information_types/symbol_table/symbol.h"

namespace fileinfo {

/**
 * Class for symbol table
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for numeric types.
 * Methods with index parameters does not perform control of indexes.
 *
 * If @a extraInfo contains non-zero number of items, each item in @a extraInfo must contains
 * as many records as member @a table.
 */
class SymbolTable
{
	private:
		std::string name;                          ///< name of symbol table
		unsigned long long offset;                 ///< offset of symbol table in file
		unsigned long long declaredSymbols;        ///< declared number of symbols in table
		std::vector<Symbol> table;                 ///< vector of symbols in table
		std::vector<SpecialInformation> extraInfo; ///< vector of special information (e.g. processor-specific information)
	public:
		SymbolTable();
		~SymbolTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfStoredSymbols() const;
		std::string getNumberOfDeclaredSymbolsStr() const;
		std::string getTableName() const;
		std::string getTableOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSymbolName(std::size_t position) const;
		std::string getSymbolType(std::size_t position) const;
		std::string getSymbolBind(std::size_t position) const;
		std::string getSymbolOther(std::size_t position) const;
		std::string getSymbolLinkToSection(std::size_t position) const;
		std::string getSymbolIndexStr(std::size_t position) const;
		std::string getSymbolValueStr(std::size_t position) const;
		std::string getSymbolAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSymbolSizeStr(std::size_t position) const;
		std::size_t getNumberOfStoredSpecialInformation() const;
		std::size_t getNumberOfSpecialInformationValues(std::size_t position) const;
		std::string getSpecialInformationDescription(std::size_t position) const;
		std::string getSpecialInformationAbbreviation(std::size_t position) const;
		std::string getSpecialInformationValue(std::size_t infoIndex, std::size_t recordIndex) const;
		/// @}

		/// @name Setters
		/// @{
		void setTableName(std::string tableName);
		void setNumberOfDeclaredSymbols(unsigned long long symbols);
		void setTableOffset(unsigned long long tableOffset);
		/// @}

		/// @name Other methods
		/// @{
		void addSymbol(Symbol &symbol);
		void clearSymbols();
		void addSpecialInformation(SpecialInformation &information);
		void clearSpecialInformation();
		/// @}
};

} // namespace fileinfo

#endif
