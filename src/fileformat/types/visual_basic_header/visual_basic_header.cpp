/**
 * @file src/fileformat/types/visual_basic_header/visual_basic_header.cpp
 * @brief Class for visual basic header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>

#include "retdec/fileformat/types/visual_basic_header/visual_basic_header.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
VisualBasicHeader::VisualBasicHeader()
{

}

/**
 * Destructor
 */
VisualBasicHeader::~VisualBasicHeader()
{

}

/**
 * Set header address
 * @param address Header address to be set
 */
void VisualBasicHeader::setHeaderAddress(std::size_t address)
{
	headerAddress = address;
}

} // namespace fileformat
} // namespace retdec
