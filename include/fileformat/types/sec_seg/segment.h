/**
 * @file include/fileformat/types/sec_seg/segment.h
 * @brief Class for file segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_TYPES_SEC_SEG_SEGMENT_H
#define FILEFORMAT_TYPES_SEC_SEG_SEGMENT_H

#include "fileformat/types/sec_seg/sec_seg.h"

namespace fileformat {

/**
 * Segment in file
 */
class Segment : public SecSeg
{
	public:
		Segment();
};

} // namespace fileformat

#endif
