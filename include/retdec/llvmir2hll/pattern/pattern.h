/**
* @file include/retdec/llvmir2hll/pattern/pattern.h
* @brief A base class for representing code patterns.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_H

#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class for representing code patterns.
*
* This class is a base class for all representations of code patterns.
*
* Instances of this class and subclasses have reference object semantics.
*/
class Pattern: private retdec::utils::NonCopyable {
public:
	/**
	* @brief Prints the pattern to stream @a os, each line indented with @a
	*        indentation.
	*
	* The pattern may span over multiple lines. When the pattern is empty,
	* nothing should be printed. If the pattern is non-empty, the output is
	* ended with a new line.
	*/
	virtual void print(llvm::raw_ostream &os,
		const std::string &indentation = "") const = 0;

protected:
	Pattern();
	virtual ~Pattern();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
