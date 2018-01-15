/**
 * @file include/retdec/fileformat/types/sec_seg/section.h
 * @brief Class for file section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SEC_SEG_SECTION_H
#define RETDEC_FILEFORMAT_TYPES_SEC_SEG_SECTION_H

#include "retdec/fileformat/types/sec_seg/sec_seg.h"

namespace retdec {
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
} // namespace retdec

#endif
