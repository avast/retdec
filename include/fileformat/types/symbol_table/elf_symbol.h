/**
 * @file include/fileformat/types/symbol_table/elf_symbol.h
 * @brief Class for one ELF symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_SYMBOL_TABLE_ELF_SYMBOL_H
#define FILEFORMAT_TYPES_SYMBOL_TABLE_ELF_SYMBOL_H

#include "fileformat/types/symbol_table/symbol.h"

namespace fileformat {

/**
 * Class for one ELF symbol
 */
class ElfSymbol : public Symbol
{
	private:
		unsigned long long elfType;    ///< ELF symbol type
		unsigned long long elfBind;    ///< ELF symbol bind type
		unsigned long long elfOther;   ///< ELF symbol other data
	public:
		ElfSymbol();
		~ElfSymbol();

		/// @name Getters
		/// @{
		unsigned long long getElfType() const;
		unsigned long long getElfBind() const;
		unsigned long long getElfOther() const;
		/// @]

		/// @name Setters
		/// @{
		void setElfType(unsigned long long symbolElfType);
		void setElfBind(unsigned long long symbolElfBind);
		void setElfOther(unsigned long long symbolElfOther);
		/// @}
};

} // namespace fileformat

#endif
