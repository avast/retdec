/**
* @file include/retdec/bin2llvmir/optimizations/idioms/idioms_borland.h
* @brief Borland C/C++ instruction idioms
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_BORLAND_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_IDIOMS_IDIOMS_BORLAND_H

#include "retdec/bin2llvmir/optimizations/idioms/idioms_abstract.h"

namespace retdec {
namespace bin2llvmir {

/**
 * @brief Borland C/C++ instruction idioms
 */
class IdiomsBorland: virtual public IdiomsAbstract {
	friend class IdiomsAnalysis;
	// Add idioms here, if you have found idioms specific for Borland compiler.
};

} // namespace bin2llvmir
} // namespace retdec

#endif
