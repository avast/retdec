/**
* @file include/retdec/bin2llvmir/optimizations/globals/dead_global_assign.h
* @brief Removes dead assignments to global variables.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_GLOBALS_DEAD_GLOBAL_ASSIGN_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_GLOBALS_DEAD_GLOBAL_ASSIGN_H

#include "retdec/bin2llvmir/optimizations/globals/global_to_local_and_dead_global_assign.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Optimization that removes dead global assigns.
*
* This optimization optimizes for example (@c g and @c v are global variables):
* @code
* g = 1; -- remove, not use this value.
* g = 2;
* v = 2; -- remove, only if v is not used anywhere from this place (also not
*           used in called functions).
* x = g;
* @endcode
*
* Also removes all definitions of global variables that don't have use.
*
* This optimization can run in two variants. Aggressive and not aggressive.
* Not aggressive is run by:
* @code
* -dead-global-assign -not-aggressive
* @endcode
* Aggressive variant is default. Aggressive variant does not count that there
* is some use in functions that are defined out of the module.
*
* This optimization can be run with statistics about how many global
* declaration or how many dead global assigns were deleted. This is possible
* with:
* @code
* --stats -dead-global-assign
* @endcode
*/
class DeadGlobalAssign: public GlobalToLocalAndDeadGlobalAssign {
public:
	DeadGlobalAssign();
	virtual ~DeadGlobalAssign() override;

	static const char *getPassArg();
	virtual const char *getPassName() const override;

public:
	static char ID;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
