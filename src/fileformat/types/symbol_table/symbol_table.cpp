/**
 * @file src/fileformat/types/symbol_table/symbol_table.cpp
 * @brief Class for symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/symbol_table/symbol_table.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
SymbolTable::SymbolTable() : table(), name()
{

}

/**
 * Destructor
 */
SymbolTable::~SymbolTable()
{

}

/**
 * Get number of symbols in table
 * @return Number of symbols in table
 */
std::size_t SymbolTable::getNumberOfSymbols() const
{
	return table.size();
}

/**
 * Get pointer to symbol from table
 * @param symbolIndex Index of selected symbol (indexed from 0)
 * @return Pointer to symbol or @c nullptr if symbol index is invalid
 */
const Symbol* SymbolTable::getSymbol(std::size_t symbolIndex) const
{
	return (symbolIndex < getNumberOfSymbols()) ? table[symbolIndex].get() : nullptr;
}

/**
 * Get symbol by name
 * @param name Name of the symbol to get
 * @return Pointer to symbol with the specified name or @c nullptr if such item not found
 */
const Symbol* SymbolTable::getSymbol(const std::string &name) const
{
	for(const auto &s : table)
	{
		if(s->getName() == name)
		{
			return s.get();
		}
	}

	return nullptr;
}

/**
 * Get pointer to symbol from table
 * @param addr Address of selected symbol
 * @return Pointer to symbol or @c nullptr if symbol address is invalid
 */
const Symbol* SymbolTable::getSymbolOnAddress(unsigned long long addr) const
{
	for(const auto &s : table)
	{
		unsigned long long a;
		if(s->getAddress(a) && a == addr)
		{
			return s.get();
		}
	}

	return nullptr;
}

/**
 * Get pointer to symbol from table with specified index
 * @param symbolIndex Index stored in symbol
 * @return Pointer to symbol or @c nullptr if symbol with index is not found
 */
const Symbol* SymbolTable::getSymbolWithIndex(std::size_t symbolIndex) const
{
	for(const auto &s : table)
	{
		if(s->getIndex() == symbolIndex)
		{
			return s.get();
		}
	}

	return nullptr;
}

/**
 * Get name of the symbol table.
 * @return Name of the symbol table.
 */
const std::string& SymbolTable::getName() const
{
	return name;
}

/**
 * Get pointer to symbol from table
 * @param symbolIndex Index of selected symbol (indexed from 0)
 * @return Pointer to symbol or @c nullptr if symbol index is invalid
 */
Symbol* SymbolTable::getSymbol(std::size_t symbolIndex)
{
	return (symbolIndex < getNumberOfSymbols()) ? table[symbolIndex].get() : nullptr;
}

/**
 * Get symbol by name
 * @param name Name of the symbol to get
 * @return Pointer to symbol with the specified name or @c nullptr if such item not found
 */
Symbol* SymbolTable::getSymbol(const std::string &name)
{
	for(auto &s : table)
	{
		if(s->getName() == name)
		{
			return s.get();
		}
	}

	return nullptr;
}

/**
 * Get pointer to symbol from table
 * @param addr Address of selected symbol
 * @return Pointer to symbol or @c nullptr if symbol address is invalid
 */
Symbol* SymbolTable::getSymbolOnAddress(unsigned long long addr)
{
	for(auto &s : table)
	{
		unsigned long long a;
		if(s->getAddress(a) && a == addr)
		{
			return s.get();
		}
	}

	return nullptr;
}

/**
 * Get pointer to symbol from table with specified index
 * @param symbolIndex Index stored in symbol
 * @return Pointer to symbol or @c nullptr if symbol with index is not found
 */
Symbol* SymbolTable::getSymbolWithIndex(std::size_t symbolIndex)
{
	for(auto &s : table)
	{
		if(s->getIndex() == symbolIndex)
		{
			return s.get();
		}
	}

	return nullptr;
}

/**
 * Get begin constant iterator
 * @return Begin constant iterator
 */
SymbolTable::symbolsConstIterator SymbolTable::begin() const
{
	return table.begin();
}

/**
 * Get begin iterator
 * @return Begin iterator
 */
SymbolTable::symbolsIterator SymbolTable::begin()
{
	return table.begin();
}

/**
 * Get end constant iterator
 * @return End constant iterator
 */
SymbolTable::symbolsConstIterator SymbolTable::end() const
{
	return table.end();
}

/**
 * Get end iterator
 * @return End iterator
 */
SymbolTable::symbolsIterator SymbolTable::end()
{
	return table.end();
}

/**
 * Delete all records from table
 */
void SymbolTable::clear()
{
	table.clear();
}

/**
 * Add new symbol to table
 * @param symbol New symbol
 */
void SymbolTable::addSymbol(const std::shared_ptr<Symbol> &symbol)
{
	table.push_back(symbol);
}

/**
 * Add new symbol to table
 * @param symbol New symbol
 */
void SymbolTable::addSymbol(std::shared_ptr<Symbol> &&symbol)
{
	table.push_back(std::move(symbol));
}

/**
 * Find out if there are any symbols.
 * @return @c true if there are some symbols, @c false otherwise
 */
bool SymbolTable::hasSymbols() const
{
	return !table.empty();
}

/**
 * Check if symbol with name @a name exists
 * @param name Name of symbol
 * @return @c true if has symbol with name @a name, @c false otherwise
 */
bool SymbolTable::hasSymbol(const std::string &name) const
{
	return getSymbol(name);
}

/**
 * Check if symbol on address exists
 * @param addr Adress of symbol
 * @return @c true if has symbol on @a address, @c false otherwise
 */
bool SymbolTable::hasSymbol(unsigned long long addr) const
{
	return getSymbolOnAddress(addr);
}

/**
 * Dump information about all symbols in table
 * @param dumpTable Into this parameter is stored dump of symbol table in an LLVM style
 */
void SymbolTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Symbol table ------------\n";
	ret << "; Number of symbols: " << getNumberOfSymbols() << "\n";

	if(hasSymbols())
	{
		unsigned long long aux;
		std::string type, usageType;
		ret << ";\n";

		for(const auto &item : table)
		{
			switch(item->getType())
			{
				case Symbol::Type::PRIVATE:
					type = "PRIVATE";
					break;
				case Symbol::Type::PUBLIC:
					type = "PUBLIC";
					break;
				case Symbol::Type::WEAK:
					type = "WEAK";
					break;
				case Symbol::Type::EXTERN:
					type = "EXTERN";
					break;
				case Symbol::Type::ABSOLUTE_SYM:
					type = "ABS_SYM";
					break;
				case Symbol::Type::COMMON:
					type = "COMMON";
					break;
				default:
					type = "UNDEF";
			}

			switch(item->getUsageType())
			{
				case Symbol::UsageType::FUNCTION:
					usageType = "FUNC";
					break;
				case Symbol::UsageType::OBJECT:
					usageType = "OBJECT";
					break;
				case Symbol::UsageType::FILE:
					usageType = "FILE";
					break;
				default:
					usageType = "UNKN";
			}

			ret << "; " << item->getName() << " (addr: " << (item->getAddress(aux) ? numToStr(aux, std::hex) : "-") <<
				", index: " << item->getIndex() << ", type: " << type << ", usageType: " << usageType <<
				", section: " << (item->getLinkToSection(aux) ? numToStr(aux) : "-") <<
				", size: " << (item->getSize(aux) ? numToStr(aux) : "-") << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

/**
 * Sets the name of the symbol table.
 * @param symbolTableName Name of the symbol table.
 */
void SymbolTable::setName(const std::string& symbolTableName)
{
	name = symbolTableName;
}

} // namespace fileformat
} // namespace retdec
