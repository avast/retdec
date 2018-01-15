/**
 * @file include/retdec/fileformat/types/relocation_table/relocation_table.h
 * @brief Class for relocation table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RELOCATION_TABLE_RELOCATION_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_RELOCATION_TABLE_RELOCATION_TABLE_H

#include <vector>

#include "retdec/fileformat/types/relocation_table/relocation.h"

namespace retdec {
namespace fileformat {

/**
 * Class for relocation table
 */
class RelocationTable
{
	private:
		using relocationsIterator = std::vector<Relocation>::const_iterator;
		std::vector<Relocation> table; ///< stored relocations
		unsigned long long linkToSymbolTable; ///< link to associated symbol table
	public:
		RelocationTable();
		~RelocationTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfRelocations() const;
		const Relocation* getRelocation(std::size_t relocationIndex) const;
		const Relocation* getRelocation(const std::string &name) const;
		const Relocation* getRelocationOnAddress(unsigned long long addr) const;
		unsigned long long getLinkToSymbolTable() const;
		/// @}

		/// @name Setters
		void setLinkToSymbolTable(std::uint64_t symbolTableIndex);
		/// @}

		/// @name Iterators
		/// @{
		relocationsIterator begin() const;
		relocationsIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		void clear();
		void addRelocation(Relocation &relocation);
		bool hasRelocations() const;
		bool hasRelocation(const std::string &name) const;
		bool hasRelocation(unsigned long long addr) const;
		void dump(std::string &dumpTable) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
