/**
 * @file include/retdec/fileformat/types/resource_table/resource_version.h
 * @brief Class for one version resource.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_VERSION_H
#define RETDEC_FILEFORMAT_TYPES_RESOURCE_TABLE_RESOURCE_VERSION_H

#include "retdec/fileformat/types/resource_table/resource.h"

namespace retdec {
namespace fileformat {

/**
 * One version resource
 */
class ResourceVersion : public Resource
{
	private:
		// TODO
		size_t iconGroupID;                 ///< icon group id

		/// @name Auxiliary methods
		/// @{
		
		/// @}

	public:
		ResourceVersion();
		~ResourceVersion();

		/// @name Getters
		/// @{
		
		/// @}

		/// @name Getters of icon group content
		/// @{
		
		/// @}

		/// @name Setters
		/// @{
		
		/// @}

		/// @name Other methods
		/// @{
		
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
