/**
* @file include/retdec/bin2llvmir/optimizations/idioms/idioms_owatcom.h
* @brief Open Watcom instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_OWATCOM_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_OWATCOM_H

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
namespace bin2llvmir {

/**
 * @brief Open Watcom instruction idioms
 */
class IdiomsOWatcom: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;
	// Add idioms here, if you have found idioms specific for Open Watcom compiler.
};

} // namespace bin2llvmir
} // namespace retdec

#endif
