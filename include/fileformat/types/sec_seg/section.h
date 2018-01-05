/**
 * @file include/fileformat/types/sec_seg/section.h
 * @brief Class for file section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_SEC_SEG_SECTION_H
#define FILEFORMAT_TYPES_SEC_SEG_SECTION_H

#include "fileformat/types/sec_seg/sec_seg.h"

namespace fileformat {

/**
 * Section in file
 */
class Section : public SecSeg
{
	public:
		Section();
};

} // namespace fileformat

#endif
