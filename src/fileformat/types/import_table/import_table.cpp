/**
 * @file src/fileformat/types/import_table/import_table.cpp
 * @brief Class for import table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/utils/ord_lookup.h"
#include "retdec/fileformat/utils/crypto.h"
#include "retdec/pelib/PeLibAux.h"
#include "retdec/fileformat/types/import_table/import_table.h"
#include <tlsh/tlsh.h>

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Get number of libraries which are imported
 * @return Number of libraries which are imported
 */
std::size_t ImportTable::getNumberOfLibraries() const
{
	return libraries.size();
}

/**
 * Get number of imports in import table
 * @return Number of imports in import table
 */
std::size_t ImportTable::getNumberOfImports() const
{
	return imports.size();
}

/**
 * Get number of imports from selected library
 * @param libraryIndex Index of selected library (indexed from 0)
 * @return Number of imports from selected library or 0 if library index is invalid
 */
std::size_t ImportTable::getNumberOfImportsInLibrary(std::size_t libraryIndex) const
{
	std::size_t result = 0;
	if(libraryIndex < libraries.size())
	{
		for(const auto &imp : imports)
		{
			if(imp->getLibraryIndex() == libraryIndex)
			{
				++result;
			}
		}
	}

	return result;
}

/**
 * Get number of imports from selected library
 * @param name Name of selected library
 * @return Number of imports from selected library or 0 if library was not found
 */
std::size_t ImportTable::getNumberOfImportsInLibrary(const std::string &name) const
{
	std::size_t result = 0;

	for(std::size_t i = 0, e = getNumberOfLibraries(); i < e; ++i)
	{
		if(libraries[i] == name)
		{
			result += getNumberOfImportsInLibrary(i);
		}
	}

	return result;
}

/**
 * Get number of imports from selected library
 * @param name Name of selected library (cse-insensitive)
 * @return Number of imports from selected library or 0 if library was not found
 */
std::size_t ImportTable::getNumberOfImportsInLibraryCaseInsensitive(const std::string &name) const
{
	std::size_t result = 0;

	for(std::size_t i = 0, e = getNumberOfLibraries(); i < e; ++i)
	{
		if(areEqualCaseInsensitive(libraries[i], name))
		{
			result += getNumberOfImportsInLibrary(i);
		}
	}

	return result;
}

/**
 * Get imphash as CRC32
 * @return Imphash as CRC32
 */
const std::string& ImportTable::getImphashCrc32() const
{
	return impHashCrc32;
}

/**
 * Get imphash as MD5
 * @return Imphash as MD5
 */
const std::string& ImportTable::getImphashMd5() const
{
	return impHashMd5;
}

/**
 * Get imphash as SHA256
 * @return Imphash as SHA256
 */
const std::string& ImportTable::getImphashSha256() const
{
	return impHashSha256;
}

const std::string& ImportTable::getImpHashTlsh() const {
	return impHashTlsh;
}

/**
 * Get list of missing dependencies
 * @return Vector of missing dependencies
 */
const std::vector<std::string> & ImportTable::getMissingDependencies() const
{
	return missingDeps;
}

/**
 * Get name of imported library
 * @param libraryIndex Index of selected library (indexed from 0)
 * @return Name of selected library or empty string if library index is invalid
 */
std::string ImportTable::getLibrary(std::size_t libraryIndex) const
{
	return (libraryIndex < getNumberOfLibraries()) ? libraries[libraryIndex] : "";
}

/**
 * Get selected import
 * @param importIndex Index of selected import (indexed from 0)
 * @return Pointer to selected import or @c nullptr if import index is invalid
 */
const Import* ImportTable::getImport(std::size_t importIndex) const
{
	return (importIndex < getNumberOfImports()) ? imports[importIndex].get() : nullptr;
}

/**
 * Get import by name
 * @param name Name of the import to get
 * @return Pointer to import with the specified name or @c nullptr if such import not found
 */
const Import* ImportTable::getImport(const std::string &name) const
{
	for(const auto &i : imports)
	{
		if(i->getName() == name)
		{
			return i.get();
		}
	}

	return nullptr;
}

/**
 * Get selected import
 * @param address Adress of selected import
 * @return Pointer to selected import or @c nullptr if import address is invalid
 */
const Import* ImportTable::getImportOnAddress(unsigned long long address) const
{
	for(const auto &i : imports)
	{
		if(i->getAddress() == address)
		{
			return i.get();
		}
	}

	return nullptr;
}

/**
 * Get begin imports iterator
 * @return Begin imports iterator
 */
ImportTable::importsIterator ImportTable::begin() const
{
	return imports.begin();
}

/**
 * Get end imports iterator
 * @return End imports iterator
 */
ImportTable::importsIterator ImportTable::end() const
{
	return imports.end();
}

/**
 * Compute import hashes - CRC32, MD5, SHA256, TLSH.
 */
void ImportTable::computeHashes()
{
	std::string impHashBytes;

	// Prevent endless reallocations by reserving space in the import data blob
	// The blob format is DllName1.SymbolName1[,DllName2.SymbolName2[,DllName3.SymbolName3]]
	impHashBytes.reserve(imports.size() * (PeLib::IMPORT_LIBRARY_MAX_LENGTH + PeLib::IMPORT_LIBRARY_MAX_LENGTH + 2));

	// Enumerate imports and append them to the import data blob
	for (const auto& import : imports)
	{
		if(!import->isUsedForImphash())
		{
			continue;
		}

		// Get library name and import name
		auto libName = toLower(getLibrary(import->getLibraryIndex()));
		auto funcName = toLower(import->getName());

		// YARA compatible name lookup
		if(funcName.empty())
		{
			std::uint64_t ord;
			if(import->getOrdinalNumber(ord))
			{
				funcName = toLower(retdec::utils::ordLookUp(libName, ord, true));
			}
		}

		// Cut common suffixes
		if(endsWith(libName, ".ocx")
				|| endsWith(libName, ".sys")
				|| endsWith(libName, ".dll"))
		{
			libName.erase(libName.length() - 4, 4);
		}

		// Issue 460: Do not generate import name hash if there is an imported name that is either empty or invalid
		// https://github.com/avast/retdec/issues/460
		if(libName.empty() || funcName.empty())
		{
			break;
		}

		// Yara adds comma if there are multiple imports
		if(!impHashBytes.empty())
			impHashBytes.append(1, ',');

		// Append the bytes of the import name to the hash bytes vector
		// Note that this is faster than the previous char-to-char concatenating
		impHashBytes.append(libName);
		impHashBytes.append(1, '.');
		impHashBytes.append(funcName);

		//for(const auto c : std::string())
		//{
		//	impHashBytes.push_back(static_cast<std::uint8_t>(c));
		//}
	}

	if (impHashBytes.size()) {
		auto data = reinterpret_cast<const uint8_t*>(impHashBytes.data());

		Tlsh tlsh;
		tlsh.update(data, impHashBytes.size());
		tlsh.final();
		/* this prepends the hash with 'T' + number of the version */
		const int show_version = 1;
		impHashTlsh = tlsh.getHash(show_version);

		impHashCrc32 = getCrc32(data, impHashBytes.size());
		impHashMd5 = getMd5(data, impHashBytes.size());
		impHashSha256 = getSha256(data, impHashBytes.size());
	}
}

/**
 * Reset table and delete all records from it
 */
void ImportTable::clear()
{
	libraries.clear();
	imports.clear();
	impHashCrc32.clear();
	impHashMd5.clear();
	impHashSha256.clear();
}

/**
 * Add name of imported library
 * @param name Name of imported library
 * @param isMissingDependency If true, then it means that the library name might be a missing dependency (aka not normally present on the OS)
 *
 * Order in which are libraries added must be same as order of libraries import in input file
 */
void ImportTable::addLibrary(std::string name, bool isMissingDependency)
{
	if(isMissingDependency)
		missingDeps.push_back(name);
	libraries.push_back(name);
}

/**
 * Add import
 * @param import Import which will be added
 */
const Import* ImportTable::addImport(std::unique_ptr<Import>&& import)
{
	imports.push_back(std::move(import));
	return imports.back().get();
}

/**
 * Find out if there are any libraries.
 * @return @c true if there are some libraries, @c false otherwise.
 */
bool ImportTable::hasLibraries() const
{
	return !libraries.empty();
}

/**
 * Find out if there is library with name @a name
 * @param name Name of selected library
 * @return @c true if there is library with name @a name, @c false otherwise
 */
bool ImportTable::hasLibrary(const std::string &name) const
{
	return hasItem(libraries, name);
}

/**
 * Find out if there is library with name @a name (case-insensitive)
 * @param name Name of selected library
 * @return @c true if there is library with name @a name, @c false otherwise
 */
bool ImportTable::hasLibraryCaseInsensitive(const std::string &name) const
{
	for(const auto &item : libraries)
	{
		if(areEqualCaseInsensitive(item, name))
		{
			return true;
		}
	}

	return false;
}

/**
 * Find out if there are any imports.
 * @return @c true if there are some imports, @c false otherwise
 */
bool ImportTable::hasImports() const
{
	return !imports.empty();
}

/**
 * Check if import with name @a name exists
 * @param name Name of import
 * @return @c true if import with name @a name exists, @c false otherwise
 */
bool ImportTable::hasImport(const std::string &name) const
{
	return getImport(name);
}

/**
 * Check if import on address exists
 * @param address Adress of import
 * @return @c true if has import on @a address, @c false otherwise
 */
bool ImportTable::hasImport(unsigned long long address) const
{
	return getImportOnAddress(address);
}

/**
 * @return @c True if import hashes are invalid, @c False otherwise.
 */
bool ImportTable::invalidImpHash() const
{
	return getImphashCrc32().empty()
			|| getImphashMd5().empty()
			|| getImphashSha256().empty();
}

/**
 * Check if import table is empty
 * @return @c true if table does not contain any library name or import, @c false otherwise
 */
bool ImportTable::empty() const
{
	return !hasLibraries() && !hasImports();
}

/**
 * Dump information about all imports in table
 * @param dumpTable Into this parameter is stored dump of import table in an LLVM style
 */
void ImportTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Imported functions ------------\n";
	ret << "; Number of libraries: " << getNumberOfLibraries() << "\n";
	ret << "; Number of imports: " << getNumberOfImports() << "\n";
	const auto crc32 = getImphashCrc32();
	const auto md5 = getImphashMd5();
	const auto sha256 = getImphashSha256();
	if(!crc32.empty())
	{
		ret << "; CRC32: " << crc32 << "\n";
	}
	if(!md5.empty())
	{
		ret << "; MD5: " << md5 << "\n";
	}
	if(!sha256.empty())
	{
		ret << "; SHA256: " << sha256 << "\n";
	}

	if(hasLibraries())
	{
		ret << ";\n";
		for(const auto &lib : libraries)
		{
			ret << "; " << lib << "\n";
		}
	}

	if(hasImports())
	{
		std::uint64_t aux;
		ret << ";\n";

		for(const auto &imp : imports)
		{
			ret << "; " << std::hex << imp->getName() << " (addr: " << imp->getAddress() <<
				", ord: " << std::dec << (imp->getOrdinalNumber(aux) ? std::to_string(aux) : "-") <<
				", libId: " << (imp->getLibraryIndex() < getNumberOfLibraries() ?
				std::to_string(imp->getLibraryIndex()) : "-") << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

/**
 * Dump information about selected library
 * @param libraryIndex Index of selected library (indexed from 0)
 * @param libraryDump Into this parameter is stored dump of selected library
 */
void ImportTable::dumpLibrary(std::size_t libraryIndex, std::string &libraryDump) const
{
	libraryDump.clear();
	if(libraryIndex >= getNumberOfLibraries())
	{
		return;
	}

	std::stringstream ret;
	std::vector<std::size_t> indexes;

	for(std::size_t i = 0, e = imports.size(); i < e; ++i)
	{
		if(imports[i]->getLibraryIndex() == libraryIndex)
		{
			indexes.push_back(i);
		}
	}

	ret << "; ------------ Import library ------------\n";
	ret << "; Name: " << getLibrary(libraryIndex) << "\n";
	ret << "; Number of imports: " << indexes.size() << "\n";

	if(!indexes.empty())
	{
		std::uint64_t aux;
		ret << ";\n";

		for(const auto &i : indexes)
		{
			ret << "; " << std::hex << imports[i]->getName() << " (addr: " << imports[i]->getAddress() <<
				", ord: " << std::dec << (imports[i]->getOrdinalNumber(aux) ? std::to_string(aux) : "-") <<
				", libId: " << imports[i]->getLibraryIndex() << ")\n";
		}
	}

	libraryDump = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
