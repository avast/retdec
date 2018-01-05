/**
 * @file include/retdec/fileformat/types/symbol_table/symbol_table.h
 * @brief Class for symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SYMBOL_TABLE_SYMBOL_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_SYMBOL_TABLE_SYMBOL_TABLE_H

#include <memory>
#include <vector>

#include "retdec/fileformat/types/symbol_table/symbol.h"

namespace retdec {
namespace fileformat {

/**
 * Class for symbol table
 */
class SymbolTable
{
	private:
		using symbolsConstIterator = std::vector<std::shared_ptr<Symbol>>::const_iterator;
		using symbolsIterator = std::vector<std::shared_ptr<Symbol>>::iterator;
		std::vector<std::shared_ptr<Symbol>> table; ///< stored symbols
		std::string name;                           ///< name of symbol table
	public:
		SymbolTable();
		~SymbolTable();

		/// @name Const getters
		/// @{
		std::size_t getNumberOfSymbols() const;
		const Symbol* getSymbol(std::size_t symbolIndex) const;
		const Symbol* getSymbol(const std::string &name) const;
		const Symbol* getSymbolOnAddress(unsigned long long addr) const;
		const Symbol* getSymbolWithIndex(std::size_t symbolIndex) const;
		const std::string& getName() const;
		/// @}

		/// @name Getters
		/// @{
		Symbol* getSymbol(std::size_t symbolIndex);
		Symbol* getSymbol(const std::string &name);
		Symbol* getSymbolOnAddress(unsigned long long addr);
		Symbol* getSymbolWithIndex(std::size_t symbolIndex);
		/// @}

		/// @name Iterators
		/// @{
		symbolsConstIterator begin() const;
		symbolsIterator begin();
		symbolsConstIterator end() const;
		symbolsIterator end();
		/// @}

		/// @name Other methods
		/// @{
		void clear();
		void addSymbol(const std::shared_ptr<Symbol> &symbol);
		void addSymbol(std::shared_ptr<Symbol> &&symbol);
		bool hasSymbols() const;
		bool hasSymbol(const std::string &name) const;
		bool hasSymbol(unsigned long long addr) const;
		void dump(std::string &dumpTable) const;
		void setName(const std::string& symbolTableName);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
