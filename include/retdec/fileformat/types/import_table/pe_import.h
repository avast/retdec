/**
 * @file include/retdec/fileformat/types/import_table/pe_import.h
 * @brief Class for one PE import.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_IMPORT_TABLE_PE_IMPORT_H
#define RETDEC_FILEFORMAT_TYPES_IMPORT_TABLE_PE_IMPORT_H

#include "retdec/fileformat/types/import_table/import.h"

namespace retdec {
namespace fileformat {

enum PeImportFlag : std::uint32_t
{
	None = 0,
	Delayed = 1,
};

/**
 * One import
 */
class PeImport : public Import
{
	private:
		std::uint32_t flags;
	public:
		PeImport(std::uint32_t flags);
		~PeImport();

		/// @name Getters
		/// @{
		bool isDelayed() const;
		/// @}

		/// @name Setters
		/// @{
		void setDelayed(bool importDelayed);
		/// @}

		/// @name Other methods
		/// @{
		virtual bool isUsedForImphash() const override;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
