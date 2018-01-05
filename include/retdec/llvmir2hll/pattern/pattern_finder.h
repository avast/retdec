/**
* @file include/retdec/llvmir2hll/pattern/pattern_finder.h
* @brief A base class for all pattern finders.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_H
#define RETDEC_LLVMIR2HLL_PATTERN_PATTERN_FINDER_H

#include <string>
#include <vector>

#include "retdec/llvmir2hll/pattern/pattern.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;
class ValueAnalysis;
class CallInfoObtainer;

/**
* @brief A base class for all pattern finders.
*
* A concrete finder should
*  - implement all the pure virtual functions
*  - define a static <tt>ShPtr<PatternFinder> create()</tt> function
*  - register itself at PatternFinderFactory by passing the static @c create
*    function and the finder's ID
*
* Note: Do NOT set the ID of your concrete finder to "all" as this ID is
*       reserved.
*
* Instances of this class have reference object semantics.
*/
class PatternFinder: private retdec::utils::NonCopyable {
public:
	/// A list of patterns.
	using Patterns = std::vector<ShPtr<Pattern>>;

public:
	virtual ~PatternFinder();

	/**
	* @brief Returns the ID of the finder.
	*/
	virtual const std::string getId() const = 0;

	/**
	* @brief Finds patterns in the given module and returns them.
	*/
	virtual Patterns findPatterns(ShPtr<Module> module) = 0;

protected:
	PatternFinder(ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio);

protected:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// The used call info obtainer.
	ShPtr<CallInfoObtainer> cio;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
