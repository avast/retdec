/**
 * @file include/retdec/fileformat/types/import_table/elf_import_table.h
 * @brief Class for ELF import table.
 * @copyright (c) 2021 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/crypto.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/tlsh/tlsh.h"
#include "retdec/fileformat/types/import_table/elf_import_table.h"
#include <algorithm>
#include <regex>

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

static const std::set<std::string> exclusion_set = {
	"__libc_start_main", // main function
	"main", // main function
	"abort", // ARM default
	"cachectl", // MIPS default
	"cacheflush", // MIPS default
	"puts", // Compiler optimization (function replacement)
	"atol", // Compiler optimization (function replacement)
	"malloc_trim" // GNU extensions
};

bool isSymbolExcluded(std::string symbol)
{
	if (symbol.empty()) {
		return true;
	}
	/* ignore:
		symbols starting with . or _
		x86-64 specific functions
		string functions (str.* and mem.*), gcc changes them depending on architecture
		symbols starting with . or _
	*/
	std::regex exclusion_regex("(^[_\.].*$)|(^.*64$)|(^str.*$)|(^mem.*$)");

	if (std::regex_match(symbol, exclusion_regex)) {
		return true;
	}

	if (exclusion_set.count(symbol)) {
		return true;
	}

	return false;
}

/**
 * Compute import telfhash
 */
void ElfImportTable::computeHashes()
{
	std::vector<std::string> imported_symbols;

	for (const auto& import : imports) {
		auto funcName = toLower(import->getName());

		// filter the symbols just as telfhash does for the same result
		if (isSymbolExcluded(funcName)) {
			continue;
		}

		imported_symbols.push_back(funcName);
	}

	std::sort(imported_symbols.begin(), imported_symbols.end());

	std::string impHashString;
	for (const auto& symbol : imported_symbols) {
		if (!impHashString.empty())
			impHashString.append(1, ',');

		impHashString.append(symbol);
	}

	if (impHashString.size()) {
		Tlsh tlsh;
		tlsh.update(reinterpret_cast<const uint8_t*>(impHashString.data()), impHashString.size());
		tlsh.final();
		const int show_version = 1; /* this prepends the hash with 'T' + number of the version */
		impHashTlsh = toLower(tlsh.getHash(show_version));

		impHashCrc32 = getCrc32(reinterpret_cast<const uint8_t*>(impHashString.data()), impHashString.size());
		impHashMd5 = getMd5(reinterpret_cast<const uint8_t*>(impHashString.data()), impHashString.size());
		impHashSha256 = getSha256(reinterpret_cast<const uint8_t*>(impHashString.data()), impHashString.size());
	}
}

} // namespace fileformat
} // namespace retdec