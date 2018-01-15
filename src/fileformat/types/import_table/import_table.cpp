/**
 * @file src/fileformat/types/import_table/import_table.cpp
 * @brief Class for import table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/crypto/crypto.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/types/import_table/import_table.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ImportTable::ImportTable()
{

}

/**
 * Destructor
 */
ImportTable::~ImportTable()
{

}

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
			if(imp.getLibraryIndex() == libraryIndex)
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
std::string ImportTable::getImphashCrc32() const
{
	return impHashCrc32;
}

/**
 * Get imphash as MD5
 * @return Imphash as MD5
 */
std::string ImportTable::getImphashMd5() const
{
	return impHashMd5;
}

/**
 * Get imphash as SHA256
 * @return Imphash as SHA256
 */
std::string ImportTable::getImphashSha256() const
{
	return impHashSha256;
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
	return (importIndex < getNumberOfImports()) ? &imports[importIndex] : nullptr;
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
		if(i.getName() == name)
		{
			return &i;
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
		if(i.getAddress() == address)
		{
			return &i;
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
 * Compute import hashes - CRC32, MD5, SHA256.
 */
void ImportTable::computeHashes()
{
	if (impHashBytes.empty())
		return;

	impHashCrc32 = retdec::crypto::getCrc32(impHashBytes.data(), impHashBytes.size());
	impHashMd5 = retdec::crypto::getMd5(impHashBytes.data(), impHashBytes.size());
	impHashSha256 = retdec::crypto::getSha256(impHashBytes.data(), impHashBytes.size());
}

/**
 * Reset table and delete all records from it
 */
void ImportTable::clear()
{
	impHashBytes.clear();
	libraries.clear();
	imports.clear();
	impHashCrc32.clear();
	impHashMd5.clear();
	impHashSha256.clear();
}

/**
 * Add name of imported library
 * @param name Name of imported library
 *
 * Order in which are libraries added must be same as order of libraries import in input file
 */
void ImportTable::addLibrary(std::string name)
{
	libraries.push_back(name);
}

/**
 * Add import
 * @param import Import which will be added
 */
void ImportTable::addImport(const Import &import)
{
	imports.push_back(import);
	auto libName = toLower(getLibrary(import.getLibraryIndex()));
	if(endsWith(libName, ".ocx") || endsWith(libName, ".sys") || endsWith(libName, ".dll"))
	{
		libName.erase(libName.length() - 4, 4);
	}
	auto funcName = toLower(import.getName());
	if(funcName.empty())
	{
		unsigned long long ord;
		if(import.getOrdinalNumber(ord))
		{
			funcName = numToStr(ord);
		}
	}
	if(libName.empty() || funcName.empty())
	{
		return;
	}

	for(const auto c : std::string(libName + "." + funcName))
	{
		impHashBytes.push_back(static_cast<unsigned char>(c));
	}
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
		unsigned long long aux;
		ret << ";\n";

		for(const auto &imp : imports)
		{
			ret << "; " << std::hex << imp.getName() << " (addr: " << imp.getAddress() <<
				", ord: " << std::dec << (imp.getOrdinalNumber(aux) ? numToStr(aux, std::dec) : "-") <<
				", libId: " << (imp.getLibraryIndex() < getNumberOfLibraries() ?
				numToStr(imp.getLibraryIndex(), std::dec) : "-") << ")\n";
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
		if(imports[i].getLibraryIndex() == libraryIndex)
		{
			indexes.push_back(i);
		}
	}

	ret << "; ------------ Import library ------------\n";
	ret << "; Name: " << getLibrary(libraryIndex) << "\n";
	ret << "; Number of imports: " << indexes.size() << "\n";

	if(!indexes.empty())
	{
		unsigned long long aux;
		ret << ";\n";

		for(const auto &i : indexes)
		{
			ret << "; " << std::hex << imports[i].getName() << " (addr: " << imports[i].getAddress() <<
				", ord: " << std::dec << (imports[i].getOrdinalNumber(aux) ? numToStr(aux, std::dec) : "-") <<
				", libId: " << imports[i].getLibraryIndex() << ")\n";
		}
	}

	libraryDump = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
