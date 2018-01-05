/**
* @file src/llvmir2hll/support/global_vars_sorter.cpp
* @brief Implementation of GlobalVarsSorter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <map>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/global_vars_sorter.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/container.h"
#include "retdec/utils/non_copyable.h"

using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Sorter of global variables according to their interdependencies.
*/
class InterdependencySorter: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
	friend class LessThanKey;

private:
	/**
	* @brief Key to be used to sort sequences of ShPtr<GlobalVarDefVector>.
	*/
	struct LessThanKey {
		explicit LessThanKey(ShPtr<InterdependencySorter> sorter): sorter(sorter) {}

		/**
		* @brief Returns @c true iff <tt>p1 < p2</tt>.
		*/
		bool operator() (const ShPtr<GlobalVarDef> &p1,
				const ShPtr<GlobalVarDef> &p2) {
			// p1: int a;
			// p2: int b = /* a appears here */;
			//
			// p1 < p2
			if (hasItem(sorter->varToUsedVarsMap[p2->getVar()], p1->getVar())) {
				return true;
			}

			// p1: int b = /* a appears here */;
			// p2: int a;
			//
			// !(p1 < p2)
			if (hasItem(sorter->varToUsedVarsMap[p1->getVar()], p2->getVar())) {
				return false;
			}

			// p1: int a;
			// p2: int b = /* some variables other than a */;
			//
			// p1 < p2
			if (sorter->varToUsedVarsMap[p1->getVar()].empty() &&
				!sorter->varToUsedVarsMap[p2->getVar()].empty() &&
					!hasItem(sorter->varToUsedVarsMap[p2->getVar()], p1->getVar())) {
				return true;
			}

			// p1: int b = /* some variables other than a */;
			// p2: int a;
			//
			// !(p1 < p2)
			if (sorter->varToUsedVarsMap[p2->getVar()].empty() &&
				!sorter->varToUsedVarsMap[p1->getVar()].empty() &&
					!hasItem(sorter->varToUsedVarsMap[p1->getVar()], p2->getVar())) {
				return false;
			}

			// p1: int a;
			// p2: int b;
			//
			// The '<' relation is decided by using the original names of the
			// variables. We use the original names instead of the current
			// names to make the variables and their comments (address,
			// original name) appear in a sorted order. That is, instead of
			//
			//   int32_t abaca = 0; // gpr2
			//   int32_t * apple; // 0x804cf40
			//   int32_t apricot = 0; // gpr0
			//
			// we want
			//
			//   int32_t * apple; // 0x804cf40
			//   int32_t apricot = 0; // gpr0
			//   int32_t abaca = 0; // gpr2
			//
			// We use the fact that frontend generates global variables grouped
			// by their type. For example, global variables corresponding to
			// registers are emitted in one group, other variables into other
			// groups.
			//
			// The reason why we need to sort the variables by using the
			// initial names is that variables are renamed before HLL emission,
			// and during such renaming, the original groups may be lost. This
			// would result into a mixed order, as shown above.
			return p1->getVar()->getInitialName() < p2->getVar()->getInitialName();
		}

		ShPtr<InterdependencySorter> sorter;
	};

public:
	/**
	* @brief Implementation of GlobalVarsSorter::sortByInterdependencies().
	*/
	static GlobalVarDefVector sort(const GlobalVarDefVector &globalVars) {
		ShPtr<InterdependencySorter> sorter(new InterdependencySorter(globalVars));

		GlobalVarDefVector sorted(globalVars);
		std::sort(sorted.begin(), sorted.end(), LessThanKey(sorter));
		return sorted;
	}

	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~InterdependencySorter() override {}

private:
	explicit InterdependencySorter(const GlobalVarDefVector &globalVars) {
		// Compute used variables in the initializers of all global variables.
		for (const auto &varInitPair : globalVars) {
			usedVarsInLastInit.clear();
			if (ShPtr<Expression> init = varInitPair->getInitializer()) {
				init->accept(this);
			}
			varToUsedVarsMap[varInitPair->getVar()] = usedVarsInLastInit;
		}
	}

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<Variable> var) override {
		usedVarsInLastInit.insert(var);
	}
	/// @}

private:
	/// Used variables in the last initializer.
	VarSet usedVarsInLastInit;

	/// Mapping of a variable into the set of variables used in in its
	/// initializer.
	std::map<ShPtr<Variable>, VarSet> varToUsedVarsMap;
};

} // anonymous namespace

/**
* @brief Sorts the given vector of global variables by their interdependencies.
*
* For example, if it contains the following two global variables
* @code
* int g = 5;
* @endcode
* and
* @code
* int *p = &g;
* @endcode
* then they are ordered in this way because of their interdependencies.
*
* @par Preconditions
*  - the variables can be sorted in this way, i.e. there are no dependency
*    loops that would prevent the variables from being sorted
*/
GlobalVarDefVector GlobalVarsSorter::sortByInterdependencies(
		const GlobalVarDefVector &globalVars) {
	return InterdependencySorter::sort(globalVars);
}

} // namespace llvmir2hll
} // namespace retdec
