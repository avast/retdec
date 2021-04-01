/**
 * @file include/retdec/fileformat/types/import_table/elf_import_table.h
 * @brief Class for ELF import table.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "import_table.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_tables.h"

namespace retdec {
namespace fileformat {

class ElfImportTable : public ImportTable
{
public:
	// so we can prefere .dynsym over .symtab
	// https://github.com/trendmicro/telfhash/blob/b5e398e59dc25a56a28861751c1fccc74ef71617/telfhash/telfhash.py#L279
	bool isDynsym = false;
	std::vector<std::string> symbolNames; // used for telfhash calculation
	void computeHashes() override;
};
} // namespace fileformat
} // namespace retdec
