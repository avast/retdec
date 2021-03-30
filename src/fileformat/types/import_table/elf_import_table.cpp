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
#include <unordered_set>>
#include <regex>

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/* exclusions are based on the original implementation 
   https://github.com/trendmicro/telfhash/blob/master/telfhash/telfhash.py */
static const std::unordered_set<std::string> exclusion_set = {
	"__libc_start_main", // main function
	"main", // main function
	"abort", // ARM default
	"cachectl", // MIPS default
	"cacheflush", // MIPS default
	"puts", // Compiler optimization (function replacement)
	"atol", // Compiler optimization (function replacement)
	"malloc_trim" // GNU extensions
};

/*
ignore
	symbols starting with . or 
	x86-64 specific functions
	string functions (str.* and mem.*), gcc changes them depending on architecture
	symbols starting with . or _
*/
static std::regex exclusion_regex("(^[_\.].*$)|(^.*64$)|(^str.*$)|(^mem.*$)");

static bool isSymbolExcluded(const std::string& symbol)
{
	return symbol.empty() 
		|| std::regex_match(symbol, exclusion_regex) 
		|| exclusion_set.count(symbol);
}

void ElfImportTable::computeHashes()
{
	std::vector<std::string> imported_symbols(imports.size());

	for (const auto& import : imports) {
		auto funcName = toLower(import->getName());

		// filter the symbols just as telfhash does for the same result
		if (isSymbolExcluded(funcName)) {
			continue;
		}

		imported_symbols.push_back(funcName);
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
		Tlsh tlsh;
		tlsh.update(
				reinterpret_cast<const uint8_t*>(impHashString.data()),
				impHashString.size());

		tlsh.final();
		const int show_version = 1; /* this prepends the hash with 'T' + number of the version */
		impHashTlsh = toLower(tlsh.getHash(show_version));

		impHashCrc32 = getCrc32(
				reinterpret_cast<const uint8_t*>(impHashString.data()),
				impHashString.size());
		impHashMd5 = getMd5(
				reinterpret_cast<const uint8_t*>(impHashString.data()),
				impHashString.size());
		impHashSha256 = getSha256(
				reinterpret_cast<const uint8_t*>(impHashString.data()),
				impHashString.size());
	}
}

} // namespace fileformat
} // namespace retdec
