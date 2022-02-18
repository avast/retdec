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
	void computeHashes() override;
};

} // namespace fileformat
} // namespace retdec
