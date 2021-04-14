/**
 * @file include/retdec/fileformat/types/import_table/elf_import_table.h
 * @brief Class for ELF import table.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/crypto.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/types/import_table/elf_import_table.h"
#include <tlsh/tlsh.h>

#include <algorithm>
#include <unordered_set>>
#include <regex>


using namespace retdec::utils;

namespace retdec {
namespace fileformat {

void ElfImportTable::computeHashes()
{
	std::vector<std::string> imported_symbols;
	imported_symbols.reserve(imports.size());

	for (const auto& import : imports) {
		auto name = import->getName();
		imported_symbols.emplace_back(toLower(name));
	}

	/* sort them lexicographically */
	std::sort(imported_symbols.begin(), imported_symbols.end());

	std::string impHashString;
	for (const auto& symbol : imported_symbols) {
		if (!impHashString.empty())
			impHashString.append(1, ',');

		impHashString.append(symbol);
	}

	if (impHashString.size()) {
		auto data = reinterpret_cast<const uint8_t*>(impHashString.data());

		Tlsh tlsh;
		tlsh.update(data, impHashString.size());

		tlsh.final();
		/* this prepends the hash with 'T' + number of the version */
		const int show_version = 1;
		impHashTlsh = toLower(tlsh.getHash(show_version));

		impHashCrc32 = getCrc32(data, impHashString.size());
		impHashMd5 = getMd5(data, impHashString.size());
		impHashSha256 = getSha256(data, impHashString.size());
	}
}

} // namespace fileformat
} // namespace retdec
