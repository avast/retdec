/**
 * @file src/fileformat/types/import_table/pe_import.cpp
 * @brief Class for one PE import.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/import_table/pe_import.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
PeImport::PeImport(std::uint32_t importFlags) : flags(importFlags)
{

}

/**
 * Destructor
 */
PeImport::~PeImport()
{

}

/**
 * Is import delayed.
 * @return `true` if delayed, otherwise `false`.
 */
bool PeImport::isDelayed() const
{
	return flags & PeImportFlag::Delayed;
}

/**
 * Set/unset delayed import.
 * @param importDelayed `true` if delayed, otherwise `false`.
 */
void PeImport::setDelayed(bool importDelayed)
{
	flags = importDelayed ? (flags | PeImportFlag::Delayed) : (flags & ~PeImportFlag::Delayed);
}

/**
 * Virtual method which indicates whether import should be used
 * for calculating imphash.
 * @return `true` if should be used, otherwise `false`.
 */
bool PeImport::isUsedForImphash() const
{
	return !isDelayed();
}

} // namespace fileformat
} // namespace retdec
