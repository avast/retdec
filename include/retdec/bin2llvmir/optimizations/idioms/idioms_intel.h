/**
* @file include/retdec/bin2llvmir/optimizations/idioms/idioms_intel.h
* @brief Intel compiler instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_INTEL_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_INTEL_H

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
namespace bin2llvmir {

/**
 * @brief Intel compiler instruction idioms
 */
class IdiomsIntel: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;
	// Add idioms here, if you have found idioms specific for Borland compiler.
};

} // namespace bin2llvmir
} // namespace retdec

#endif
