/**
* @file include/retdec/bin2llvmir/optimizations/globals/global_to_local.h
* @brief Converts global variables to local variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_GLOBALS_GLOBAL_TO_LOCAL_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_GLOBALS_GLOBAL_TO_LOCAL_H

#include "retdec/bin2llvmir/optimizations/globals/global_to_local_and_dead_global_assign.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Optimization that converts global variables to local variables. Also
*        replaces uses of global variable with new created local variables.
*
* Optimization optimizes these situations:
* @par I.
* Converts global variables to local variables and replaces uses everywhere
* where is it possible.
* @code
* func() {
*   g = 2; <- can be replaced with local variable.
*   v = g; <- can be replaced with local variable.
* }
* @endcode
* can be optimized to
* @code
* func() {
*   int gLoc;
*   gLoc = 2;
*   v = gLoc;
* }
* @endcode
*
* @par II.
* We can call this situation as pattern. This pattern contains assign from
* global variable to temporary variable and at the end in all exits of function
* is temporary variable assigned to global variable. When all body inside this
* pattern can be optimized and we have no use of temporary variable then we can
*  remove instructions that creates pattern and optimize body of this pattern.
* @code
* func() {
*   tmp = g; <- can be removed.
*   g = 2; <- can be replaced with local variable.
*   v = g; <- can be replaced with local variable.
*   g = tmp; <- can be removed.
* }
* @endcode
* can be optimized to
* @code
* func() {
*   int gLoc;
*   gLoc = 2;
*   v = gLoc;
* }
* @endcode
*
* @par III.
* If uses of global variable is only in one function then we can move global
* variable to local in this function and is it need to assign global variable
* initializer to this new created local variable.
* int g = 2;
* @code
* func() {
*   v = g; <- can be replaced with local variable.
* }
* @endcode
* can be optimized to
* @code
* func() {
*   int gLoc;
*   gLoc = 2;
*   v = gLoc;
* }
* @endcode
* @par IV.
* Removes all definitions of global variables that don't have use.
*
* This optimization can run in two variants. Aggressive and not aggressive.
* Not aggressive is run by:
* @code
* -global-to-local -not-aggressive
* @endcode
* Aggressive variant is default. Aggressive variant does not count that there
* is some use in functions that are defined out of the module.
*
* This optimization can be run with statistics about how many global
* declaration or how many dead global assigns were deleted. This is possible
* with:
* @code
* --stats -global-to-local
* @endcode
*/
class GlobalToLocal: public GlobalToLocalAndDeadGlobalAssign {
public:
	GlobalToLocal();
	virtual ~GlobalToLocal() override;

	static const char *getPassArg();
	virtual const char *getPassName() const override;

public:
	static char ID;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
