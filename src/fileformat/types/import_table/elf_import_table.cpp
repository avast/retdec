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
	std::vector<std::string> imported_symbols;
	imported_symbols.reserve(symbolNames.size());

	for (const auto& symbol : symbolNames) {
		/* It is important to first exclude, then lowercase
		   as "Str_Aprintf" is valid, but would become
		   filtered when lower case */
		if (isSymbolExcluded(symbol)) {
			continue;
		}

		auto name = toLower(symbol);

		imported_symbols.emplace_back(name);
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
		const int show_version = 1; /* this prepends the hash with 'T' + number of the version */
		impHashTlsh = toLower(tlsh.getHash(show_version));

		impHashCrc32 = getCrc32(data, impHashString.size());
		impHashMd5 = getMd5(data, impHashString.size());
		impHashSha256 = getSha256(data, impHashString.size());
	}
}

} // namespace fileformat
} // namespace retdec
