/**
* @file include/retdec/llvmir2hll/support/funcs_with_prefix_remover.h
* @brief Removes functions whose name starts with a prefix from the given set.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_FUNCS_WITH_PREFIX_REMOVER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_FUNCS_WITH_PREFIX_REMOVER_H

#include <string>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Module;

/**
* @brief Removes functions whose name starts with a prefix from the given set.
*
* For more information, see the description of removeFuncs().
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class FuncsWithPrefixRemover: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~FuncsWithPrefixRemover() override;

	static void removeFuncs(ShPtr<Module> module,
		const StringSet &prefixes);
	static void removeFuncs(ShPtr<Module> module,
		const std::string &prefix);

private:
	FuncsWithPrefixRemover(ShPtr<Module> module,
		const StringSet &prefixes);

	void performRemoval();
	void removeCallsOfFuncsWithPrefixes();
	void removeDeclarationsOfFuncsWithPrefixes();
	bool isCallOfFuncToBeRemoved(ShPtr<Expression> expr) const;
	bool shouldBeRemoved(ShPtr<Function> func) const;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	/// @}

private:
	/// Module in which the functions are removed.
	ShPtr<Module> module;

	/// Prefixes of functions that should be removed.
	StringSet prefixes;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
