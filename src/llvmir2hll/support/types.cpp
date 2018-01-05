/**
* @file src/llvmir2hll/support/types.cpp
* @brief Implementation of the types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

// Definitions of global constants.
const AddressRange NO_ADDRESS_RANGE = AddressRange(0, 0);
const LineRange NO_LINE_RANGE = LineRange(0, 0);

} // namespace llvmir2hll
} // namespace retdec
