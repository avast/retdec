/**
 * @file include/retdec/fileformat/types/symbol_table/macho_symbol.h
 * @brief Class for one Mach-O symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SYMBOL_TABLE_MACHO_SYMBOL_H
#define RETDEC_FILEFORMAT_TYPES_SYMBOL_TABLE_MACHO_SYMBOL_H

#include <string>

#include <llvm/Object/MachO.h>
#include <llvm/Support/MachO.h>

#include "retdec/fileformat/types/export_table/export.h"
#include "retdec/fileformat/types/import_table/import.h"
#include "retdec/fileformat/types/symbol_table/symbol.h"

namespace retdec {
namespace fileformat {

/**
 * Class for one MachO symbol
 */
class MachOSymbol
{
	private:
		// Converted
		std::string name;         ///< Symbol name
		std::string altName;      ///< Alternative name for weak symbols
		unsigned long long value; ///< Symbol value - various interpetation
		// Raw values
		std::int16_t description; ///< Symbol description and library ordinal
		std::uint8_t section;     ///< Section index
		std::uint8_t type;        ///< Type of symbol
		// Additional values
		unsigned index;           ///< Index of symbol
		bool isFunction = false;  ///< @c true if symbol is function @c false otherwise

		/// @name Auxiliary methods
		/// @{
		Symbol::Type getSymbolType() const;
		Symbol::UsageType getSymbolUsageType() const;
		template<typename T> void setValues(const T &nList, const llvm::StringRef &strTable, unsigned index);
		/// @}
	public:
		MachOSymbol();
		~MachOSymbol();

		/// @name Setters
		/// @{
		void makeFunction(FileFormat *fileParser);
		void setAllValues(const llvm::MachO::nlist &nList, const llvm::StringRef &strTable, unsigned index);
		void setAllValues(const llvm::MachO::nlist_64 &nList, const llvm::StringRef &strTable, unsigned index);
		/// @}

		/// @name Interpretation methods
		/// @{
		std::unique_ptr<Import> getAsImport() const;
		Export getAsExport() const;
		std::shared_ptr<Symbol> getAsSymbol() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
