/**
 * @file src/fileformat/types/symbol_table/elf_symbol.cpp
 * @brief Class for one ELF symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/symbol_table/elf_symbol.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ElfSymbol::ElfSymbol() : elfType(0), elfBind(0), elfOther(0)
{

}

/**
 * Destructor
 */
ElfSymbol::~ElfSymbol()
{

}

/**
 * Returns the ELF symbol type.
 * @return ELF symbol type.
 */
unsigned long long ElfSymbol::getElfType() const
{
	return elfType;
}

/**
 * Returns the ELF symbol bind type.
 * @return ELF symbol bind type.
 */
unsigned long long ElfSymbol::getElfBind() const
{
	return elfBind;
}

/**
 * Returns the ELF symbol other data.
 * @return ELF symbol other data.
 */
unsigned long long ElfSymbol::getElfOther() const
{
	return elfOther;
}

/**
 * Sets the ELF symbol type.
 * @param symbolElfType ELF symbol type.
 */
void ElfSymbol::setElfType(unsigned long long symbolElfType)
{
	elfType = symbolElfType;
}

/**
 * Sets the ELF symbol bind type.
 * @param symbolElfBind ELF symbol bind type.
 */
void ElfSymbol::setElfBind(unsigned long long symbolElfBind)
{
	elfBind = symbolElfBind;
}

/**
 * Sets the ELF symbol other data.
 * @param symbolElfOther ELF symbol other data.
 */
void ElfSymbol::setElfOther(unsigned long long symbolElfOther)
{
	elfOther = symbolElfOther;
}

} // namespace fileformat
} // namespace retdec
