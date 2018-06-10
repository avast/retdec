/**
* @file src/llvmir2hll/analysis/value_analysis.cpp
* @brief Implementation of ValueAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/alias_analysis/alias_analysis.h"
#include "retdec/llvmir2hll/analysis/value_analysis.h"
#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/comma_op_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;
using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new ValueData object.
*/
ValueData::ValueData(): dirReadVars(), dirWrittenVars(), dirAllVars(),
	dirNumOfVarUses(), mayBeReadVars(), mayBeWrittenVars(),
	mayBeAccessedVars(), mustBeReadVars(), mustBeWrittenVars(),
	mustBeAccessedVars(), calls(), addressTakenVars(), containsDerefs(false),
	containsArrayAccesses(false), containsStructAccesses(false) {}

/**
* @brief Constructs a new ValueData object from @a other.
*/
ValueData::ValueData(const ValueData &other) = default;

/**
* @brief Destructs the object.
*/
ValueData::~ValueData() {}

/**
* @brief Assigns @a other to the current object.
*/
ValueData &ValueData::operator=(const ValueData &other) = default;

/**
* @brief Returns @c true if the current object is equal to @a other, @c false
*        otherwise.
*/
bool ValueData::operator==(const ValueData &other) const {
	return (dirReadVars == other.dirReadVars &&
		dirWrittenVars == other.dirWrittenVars &&
		dirAllVars == other.dirAllVars &&
		dirNumOfVarUses == other.dirNumOfVarUses &&
		mayBeReadVars == other.mayBeReadVars &&
		mayBeWrittenVars == other.mayBeWrittenVars &&
		mayBeAccessedVars == other.mayBeAccessedVars &&
		mustBeReadVars == other.mustBeReadVars &&
		mustBeWrittenVars == other.mustBeWrittenVars &&
		mustBeAccessedVars == other.mustBeAccessedVars &&
		calls == other.calls &&
		addressTakenVars == other.addressTakenVars &&
		containsDerefs == other.containsDerefs &&
		containsArrayAccesses == other.containsArrayAccesses &&
		containsStructAccesses == other.containsStructAccesses);
}

/**
* @brief Returns @c true if the current object is not equal to @a other, @c
*        false otherwise.
*/
bool ValueData::operator!=(const ValueData &other) const {
	return !(*this == other);
}

/**
* @brief Returns the variables that are directly read.
*/
const VarSet &ValueData::getDirReadVars() const {
	return dirReadVars;
}

/**
* @brief Returns the variables that are directly written into.
*/
const VarSet &ValueData::getDirWrittenVars() const {
	return dirWrittenVars;
}

/**
* @brief Returns the set of all directly accessed variables.
*/
const VarSet &ValueData::getDirAccessedVars() const {
	return dirAllVars;
}

/**
* @brief Returns the number of directly read variables.
*/
std::size_t ValueData::getNumOfDirReadVars() const {
	return dirReadVars.size();
}

/**
* @brief Returns the number of directly written variables.
*/
std::size_t ValueData::getNumOfDirWrittenVars() const {
	return dirWrittenVars.size();
}

/**
* @brief Returns the number of directly accessed variables.
*/
std::size_t ValueData::getNumOfDirAccessedVars() const {
	return dirAllVars.size();
}

/**
* @brief Returns the number of direct uses of @a var.
*
* @par Preconditions
*  - @a var is non-null
*/
std::size_t ValueData::getDirNumOfUses(ShPtr<Variable> var) const {
	PRECONDITION_NON_NULL(var);

	auto i = dirNumOfVarUses.find(var);
	if (i != dirNumOfVarUses.end()) {
		return i->second;
	}
	// The given variable doesn't exist, so it doesn't have any use.
	return 0;
}

/**
* @brief Returns an iterator to the first directly read variable.
*/
ValueData::var_iterator ValueData::dir_read_begin() const {
	return dirReadVars.begin();
}

/**
* @brief Returns an iterator past the last directly read variable.
*/
ValueData::var_iterator ValueData::dir_read_end() const {
	return dirReadVars.end();
}

/**
* @brief Returns an iterator to the first directly written variable.
*/
ValueData::var_iterator ValueData::dir_written_begin() const {
	return dirWrittenVars.begin();
}

/**
* @brief Returns an iterator past the last directly written variable.
*/
ValueData::var_iterator ValueData::dir_written_end() const {
	return dirWrittenVars.end();
}

/**
* @brief Returns an iterator to the first directly accessed variable.
*/
ValueData::var_iterator ValueData::dir_all_begin() const {
	return dirAllVars.begin();
}

/**
* @brief Returns an iterator past the last directly accessed variable.
*/
ValueData::var_iterator ValueData::dir_all_end() const {
	return dirAllVars.end();
}

/**
* @brief Returns @c true if @a var is directly read, @c false otherwise.
*/
bool ValueData::isDirRead(ShPtr<Variable> var) const {
	return hasItem(dirReadVars, var);
}

/**
* @brief Returns @c true if @a var is directly written, @c false otherwise.
*/
bool ValueData::isDirWritten(ShPtr<Variable> var) const {
	return hasItem(dirWrittenVars, var);
}

/**
* @brief Returns @c true if @a var is directly accessed, @c false otherwise.
*/
bool ValueData::isDirAccessed(ShPtr<Variable> var) const {
	return hasItem(dirAllVars, var);
}

/**
* @brief Returns the set of variables that may be indirectly read.
*
* Variables which must be read (i.e. are always read) are not included into the
* result.
*/
const VarSet &ValueData::getMayBeReadVars() const {
	return mayBeReadVars;
}

/**
* @brief Returns the set of variables into which may be indirectly written.
*
* Variables which must be written (i.e. are always written) are not included
* into the result.
*/
const VarSet &ValueData::getMayBeWrittenVars() const {
	return mayBeWrittenVars;
}

/**
* @brief Returns the set of variables that may be indirectly accessed.
*
* Variables which must be accessed (i.e. are always accessed) are not included
* into the result.
*/
const VarSet &ValueData::getMayBeAccessedVars() const {
	return mayBeAccessedVars;
}

/**
* @brief Returns @c true if @a var may be indirectly read, @c false otherwise.
*/
bool ValueData::mayBeIndirRead(ShPtr<Variable> var) const {
	return hasItem(mayBeReadVars, var);
}

/**
* @brief Returns @c true if @a var may be indirectly written-into, @c false
*        otherwise.
*/
bool ValueData::mayBeIndirWritten(ShPtr<Variable> var) const {
	return hasItem(mayBeWrittenVars, var);
}

/**
* @brief Returns @c true if @a var may be indirectly accessed, @c false
*        otherwise.
*/
bool ValueData::mayBeIndirAccessed(ShPtr<Variable> var) const {
	return hasItem(mayBeAccessedVars, var);
}

/**
* @brief Returns an iterator to the first variable that may be
*        indirectly read.
*
* Variables which must be read (i.e. are always read) are not included into the
* result.
*/
ValueData::var_iterator ValueData::may_be_read_begin() const {
	return mayBeReadVars.begin();
}

/**
* @brief Returns an iterator past the last variable that may be
*        indirectly read.
*
* Variables which must be read (i.e. are always read) are not included into the
* result.
*/
ValueData::var_iterator ValueData::may_be_read_end() const {
	return mayBeReadVars.end();
}

/**
* @brief Returns an iterator to the first variable into which may be
*        written.
*
* Variables which must be written (i.e. are always written) are not included
* into the result.
*/
ValueData::var_iterator ValueData::may_be_written_begin() const {
	return mayBeWrittenVars.begin();
}

/**
* @brief Returns an iterator past the last variable into which may be
*        written.
*
* Variables which must be written (i.e. are always written) are not included
* into the result.
*/
ValueData::var_iterator ValueData::may_be_written_end() const {
	return mayBeWrittenVars.end();
}

/**
* @brief Returns an iterator to the first variable that may be
*        accessed.
*
* Variables which must be accessed (i.e. are always accessed) are not included
* into the result.
*/
ValueData::var_iterator ValueData::may_be_accessed_begin() const {
	return mayBeAccessedVars.begin();
}

/**
* @brief Returns an iterator past the last variable that may be
*
* Variables which must be accessed (i.e. are always accessed) are not included
* into the result.
*/
ValueData::var_iterator ValueData::may_be_accessed_end() const {
	return mayBeAccessedVars.end();
}

/**
* @brief Returns the set of variables that must be indirectly read.
*/
const VarSet &ValueData::getMustBeReadVars() const {
	return mustBeReadVars;
}

/**
* @brief Returns the set of variables into which must be indirectly written.
*/
const VarSet &ValueData::getMustBeWrittenVars() const {
	return mustBeWrittenVars;
}

/**
* @brief Returns the set of variables that must be indirectly accessed.
*/
const VarSet &ValueData::getMustBeAccessedVars() const {
	return mustBeAccessedVars;
}

/**
* @brief Returns @c true if @a var must be indirectly read, @c false otherwise.
*/
bool ValueData::mustBeIndirRead(ShPtr<Variable> var) const {
	return hasItem(mustBeReadVars, var);
}

/**
* @brief Returns @c true if @a var must be indirectly written-into, @c false
*        otherwise.
*/
bool ValueData::mustBeIndirWritten(ShPtr<Variable> var) const {
	return hasItem(mustBeWrittenVars, var);
}

/**
* @brief Returns @c true if @a var must be indirectly accessed, @c false
*        otherwise.
*/
bool ValueData::mustBeIndirAccessed(ShPtr<Variable> var) const {
	return hasItem(mustBeAccessedVars, var);
}

/**
* @brief Returns an iterator to the first variable that must be
*        indirectly read.
*/
ValueData::var_iterator ValueData::must_be_read_begin() const {
	return mustBeReadVars.begin();
}

/**
* @brief Returns an iterator past the last variable that must be
*        indirectly read.
*/
ValueData::var_iterator ValueData::must_be_read_end() const {
	return mustBeReadVars.end();
}

/**
* @brief Returns an iterator to the first variable into which must be
*        written.
*/
ValueData::var_iterator ValueData::must_be_written_begin() const {
	return mustBeWrittenVars.begin();
}

/**
* @brief Returns an iterator past the last variable into which must be
*        written.
*/
ValueData::var_iterator ValueData::must_be_written_end() const {
	return mustBeWrittenVars.end();
}

/**
* @brief Returns an iterator to the first variable that must be
*        accessed.
*/
ValueData::var_iterator ValueData::must_be_accessed_begin() const {
	return mustBeAccessedVars.begin();
}

/**
* @brief Returns an iterator past the last variable that must be
*        accessed.
*/
ValueData::var_iterator ValueData::must_be_accessed_end() const {
	return mustBeAccessedVars.end();
}

/**
* @brief Returns all function calls.
*/
const CallVector &ValueData::getCalls() const {
	return calls;
}

/**
* @brief Returns @c true if there are function calls, @c false otherwise.
*/
bool ValueData::hasCalls() const {
	return !calls.empty();
}

/**
* @brief Returns the number of calls.
*/
std::size_t ValueData::getNumOfCalls() const {
	return calls.size();
}

/**
* @brief Returns an iterator to the first call.
*/
ValueData::call_iterator ValueData::call_begin() const {
	return calls.begin();
}

/**
* @brief Returns an iterator past the last call.
*/
ValueData::call_iterator ValueData::call_end() const {
	return calls.end();
}

/**
* @brief Returns @c true if there are any address operators, @c false otherwise.
*/
bool ValueData::hasAddressOps() const {
	return !addressTakenVars.empty();
}

/**
* @brief Returns @c true if @a var has its address taken, @c false otherwise.
*
* @par Preconditions
*  - @a var is non-null
*/
bool ValueData::hasAddressTaken(ShPtr<Variable> var) const {
	PRECONDITION_NON_NULL(var);

	return hasItem(addressTakenVars, var);
}

/**
* @brief Returns @c true if there are any dereferences, @c false otherwise.
*/
bool ValueData::hasDerefs() const {
	return containsDerefs;
}

/**
* @brief Returns @c true if there are any array accesses, @c false otherwise.
*/
bool ValueData::hasArrayAccesses() const {
	return containsArrayAccesses;
}

/**
* @brief Returns @c true if there are any struct accesses, @c false otherwise.
*/
bool ValueData::hasStructAccesses() const {
	return containsStructAccesses;
}

/**
* @brief Clears all private containers and variables.
*/
void ValueData::clear() {
	dirReadVars.clear();
	dirWrittenVars.clear();
	dirAllVars.clear();
	dirNumOfVarUses.clear();
	mayBeReadVars.clear();
	mayBeWrittenVars.clear();
	mayBeAccessedVars.clear();
	mustBeReadVars.clear();
	mustBeWrittenVars.clear();
	mustBeAccessedVars.clear();
	calls.clear();
	addressTakenVars.clear();
	containsDerefs = false;
	containsArrayAccesses = false;
	containsStructAccesses = false;
}

/**
* @brief Constructs a new visitor.
*
* See the description of create() for more information.
*/
ValueAnalysis::ValueAnalysis(ShPtr<AliasAnalysis> aliasAnalysis,
		bool enableCaching):
	OrderedAllVisitor(false, false), Caching(enableCaching),
	aliasAnalysis(aliasAnalysis), valueData(), writing(false),
	removingFromCache(false) {}

/**
* @brief Destructs the visitor.
*/
ValueAnalysis::~ValueAnalysis() {}

/**
* @brief Returns information about the given value.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<ValueData> ValueAnalysis::getValueData(ShPtr<Value> value) {
	PRECONDITION_NON_NULL(value);

	// Caching.
	if (isCachingEnabled() && getCachedResult(value, valueData)) {
		return valueData;
	}

	// Initialization.
	restart(false, false);
	valueData = ShPtr<ValueData>(new ValueData());
	writing = false;

	// Obtain read and written-into variables.
	value->accept(this);

	// Merge them into the set of all variables.
	addToSet(valueData->dirReadVars, valueData->dirAllVars);
	addToSet(valueData->dirWrittenVars, valueData->dirAllVars);

	// Caching.
	addToCache(value, valueData);

	return valueData;
}

/**
* @brief Clears the cache of the already cached results.
*
* It also puts the analysis into a valid state.
*/
void ValueAnalysis::clearCache() {
	Caching::clearCache();
	validateState();
}

/**
* @brief Removes the selected value from the cache.
*
* @param[in] value Value to be removed from the cache.
* @param[in] recursive If @c true, also removes all sub-values of @a value
*                      (e.g. operands) from the cache.
*
* @par Preconditions
*  - @a value is non-null
*/
void ValueAnalysis::removeFromCache(ShPtr<Value> value, bool recursive) {
	if (!isCachingEnabled()) {
		return;
	}

	// First, remove the value alone.
	Caching::removeFromCache(value);

	// If requested, remove also all sub-values, like operands.
	if (recursive) {
		removingFromCache = true;
		value->accept(this);
		removingFromCache = false;
	}
}

/**
* @brief Re-initializes the underlying alias analysis.
*
* This function is a delegation to AliasAnalysis::init(). See it for more
* information.
*/
void ValueAnalysis::initAliasAnalysis(ShPtr<Module> module) {
	aliasAnalysis->init(module);
}

/**
* @brief Returns the set of variables to which @a var may point to.
*
* This function is a delegation to AliasAnalysis::mayPointTo(). See it for more
* information.
*/
const VarSet &ValueAnalysis::mayPointTo(ShPtr<Variable> var) const {
	return aliasAnalysis->mayPointTo(var);
}

/**
* @brief Returns the variable to which @a var always points.
*
* This function is a delegation to AliasAnalysis::pointsTo(). See it for more
* information.
*/
ShPtr<Variable> ValueAnalysis::pointsTo(ShPtr<Variable> var) const {
	return aliasAnalysis->pointsTo(var);
}

/**
* @brief Returns @c true if a pointer may point to @a var, @c false
*        otherwise.
*
* This function is a delegation to AliasAnalysis::mayBePointed(). See it for
* more information.
*/
bool ValueAnalysis::mayBePointed(ShPtr<Variable> var) const {
	return aliasAnalysis->mayBePointed(var);
}

/**
* @brief Creates a new analysis.
*
* @param[in] aliasAnalysis The used alias analysis.
* @param[in] enableCaching If @c true, it caches the results returned by
*                          getValueData() until restartCache() or
*                          disableCaching() is called. This may speed up
*                          subsequent calls to getValueData() if the same
*                          values are passed to getValueData().
*
* @par Preconditions
*  - @a aliasAnalysis has been initialized
*/
ShPtr<ValueAnalysis> ValueAnalysis::create(ShPtr<AliasAnalysis> aliasAnalysis,
		bool enableCaching) {
	PRECONDITION(aliasAnalysis->isInitialized(), "it is not initialized");

	return ShPtr<ValueAnalysis>(new ValueAnalysis(aliasAnalysis, enableCaching));
}

/**
* @brief Computes indirectly used variables in the given dereferencing
*        expression and stores them in appropriate sets of @c valueData.
*/
void ValueAnalysis::computeAndStoreIndirectlyUsedVars(ShPtr<DerefOpExpr> expr) {
	// Traverse through the (possibly nested) dereferences until we find
	// something different than a dereference. Also, keep the number of
	// traversed dereferences. This will be useful later.
	unsigned numOfDerefs = 1;
	ShPtr<Expression> firstNonDerefExpr(expr->getOperand());
	while (isa<DerefOpExpr>(firstNonDerefExpr)) {
		firstNonDerefExpr = ucast<DerefOpExpr>(firstNonDerefExpr)->getOperand();
		numOfDerefs++;
	}

	// Currently, we can compute indirectly read/written variables only if the
	// first non-dereference operand is a variable.
	ShPtr<Variable> var = cast<Variable>(firstNonDerefExpr);
	if (!var) {
		return;
	}

	// Now, consider the following piece of code:
	//
	//     int *p = &a;
	//     int *pp = &p;
	//     return **pp;
	//
	// Then, in `return **p`, we include both `p` and `a` into
	// appropriate sets.
	//
	// More generally, if there are n stars before the variable, n-1 of them
	// read a variable while the last star may write into a variable if
	// `writing == true`. For example, in the code above, `*pp` reads the value
	// of `p` and `*pp` reads the value of `a`. In `**pp = 1`, `*p` would again
	// read `p`, but `**p` would write into `a`.
	//
	// If a dereference may point to several variables, we consider all of
	// them.

	// We create two vectors: one for storing accessed variables in every
	// dereference, and the second one for storing the info whether the
	// variables accessed in every dereference are `must be accessed`
	// variables.
	//
	// The indexing of these two vectors is done in the following way:
	//
	//     *  *  *  *  p
	//     3  2  1  0
	//
	// That is, the innermost start has index 0.
	//
	std::vector<VarSet> accessedVarsInDeref(numOfDerefs);
	std::vector<bool> mustInDeref(numOfDerefs);

	// Compute the index [0] (the innermost star).
	// Does var point to a single, unique variable?
	if (ShPtr<Variable> pointsToVar = aliasAnalysis->pointsTo(var)) {
		// Yes, it does, so include just it.
		accessedVarsInDeref[0].insert(pointsToVar);
		mustInDeref[0] = true;
	} else {
		// It may point to several variables, so include all of them.
		const VarSet &mayPointTo(aliasAnalysis->mayPointTo(var));
		addToSet(mayPointTo, accessedVarsInDeref[0]);
		mustInDeref[0] = false;
	}

	// Compute the index [i] for i = 1, ..., numOfDerefs (not the innermost star).
	for (unsigned i = 1; i < numOfDerefs; ++i) {
		// For every variable accessed in the previous dereference...
		for (const auto &varFromPrevDeref : accessedVarsInDeref[i - 1]) {
			// Does this variable point to a single, unique variable?
			if (ShPtr<Variable> pointsToVar = cast<Variable>(
					aliasAnalysis->pointsTo(varFromPrevDeref))) {
				// Yes, it does, so include just it.
				accessedVarsInDeref[i].insert(pointsToVar);
				mustInDeref[i] = true;
			} else {
				// It may point to several variables, so include all of them.
				const VarSet &mayPointTo(aliasAnalysis->mayPointTo(varFromPrevDeref));
				addToSet(mayPointTo, accessedVarsInDeref[i]);
				mustInDeref[i] = false;
			}
		}
	}

	// Include the variables computed above into appropriate sets of may/must
	// be read/written variables.
	// For the index [numOfDerefs - 1] (the outermost star).
	const VarSet &varsFromInnmostDeref(accessedVarsInDeref[numOfDerefs - 1]);
	if (mustInDeref[numOfDerefs - 1]) {
		// must
		valueData->mustBeAccessedVars.insert(*varsFromInnmostDeref.begin());
		if (writing) {
			valueData->mustBeWrittenVars.insert(*varsFromInnmostDeref.begin());
		} else {
			valueData->mustBeReadVars.insert(*varsFromInnmostDeref.begin());
		}
	} else {
		// may
		addToSet(varsFromInnmostDeref, valueData->mayBeAccessedVars);
		if (writing) {
			addToSet(varsFromInnmostDeref, valueData->mayBeWrittenVars);
		} else {
			addToSet(varsFromInnmostDeref, valueData->mayBeReadVars);
		}
	}
	// For the index [i], where i = 0, ..., numOfDerefs - 1 (not the outermost
	// star).
	for (unsigned i = 0; i < numOfDerefs - 1; ++i) {
		const VarSet &varsFromCurrDeref(accessedVarsInDeref[i]);
		if (mustInDeref[i]) {
			// must
			valueData->mustBeAccessedVars.insert(*varsFromCurrDeref.begin());
			valueData->mustBeReadVars.insert(*varsFromCurrDeref.begin());
		} else {
			// may
			addToSet(varsFromCurrDeref, valueData->mayBeAccessedVars);
			addToSet(varsFromCurrDeref, valueData->mayBeReadVars);
		}
	}
}

void ValueAnalysis::visit(ShPtr<Function> func) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(func);
	}

	if (func->isDefinition()) {
		visitStmt(func->getBody());
	}
}

void ValueAnalysis::visit(ShPtr<AssignStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
		OrderedAllVisitor::visit(stmt);
		return;
	}

	//
	// Directly used variables
	//
	writing = true;
	stmt->getLhs()->accept(this);
	writing = false;
	stmt->getRhs()->accept(this);
}

void ValueAnalysis::visit(ShPtr<BreakStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<CallStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<ContinueStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<EmptyStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<ForLoopStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
		OrderedAllVisitor::visit(stmt);
		return;
	}

	//
	// Directly used variables
	//
	writing = true;
	stmt->getIndVar()->accept(this);
	writing = false;
	stmt->getStartValue()->accept(this);
	stmt->getEndCond()->accept(this);
	stmt->getStep()->accept(this);
}

void ValueAnalysis::visit(ShPtr<UForLoopStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
		OrderedAllVisitor::visit(stmt);
		return;
	}

	//
	// Directly used variables
	//
	if (auto init = stmt->getInit()) {
		init->accept(this);
	}
	if (auto cond = stmt->getCond()) {
		cond->accept(this);
	}
	if (auto step = stmt->getStep()) {
		step->accept(this);
	}
}

void ValueAnalysis::visit(ShPtr<GotoStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<IfStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<ReturnStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<SwitchStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<UnreachableStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<VarDefStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
		OrderedAllVisitor::visit(stmt);
		return;
	}

	//
	// Directly used variables
	//
	writing = true;
	stmt->getVar()->accept(this);
	writing = false;
	if (ShPtr<Expression> init = stmt->getInitializer()) {
		init->accept(this);
	}
}

void ValueAnalysis::visit(ShPtr<WhileLoopStmt> stmt) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(stmt);
	}

	OrderedAllVisitor::visit(stmt);
}

void ValueAnalysis::visit(ShPtr<AddOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<AddressOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
		OrderedAllVisitor::visit(expr);
		return;
	}

	//
	// Address operators
	//
	if (ShPtr<Variable> var = cast<Variable>(expr->getOperand())) {
		valueData->addressTakenVars.insert(var);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<AndOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<ArrayIndexOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
		OrderedAllVisitor::visit(expr);
		return;
	}

	//
	// Array accesses
	//
	valueData->containsArrayAccesses = true;

	//
	// Directly used variables
	//
	// We consider a in a[1] = 5 to be just read (not written).
	bool oldWriting = writing;
	writing = false;
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
	writing = oldWriting;
}

void ValueAnalysis::visit(ShPtr<AssignOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
		OrderedAllVisitor::visit(expr);
		return;
	}

	//
	// Directly used variables
	//
	writing = true;
	expr->getFirstOperand()->accept(this);
	writing = false;
	expr->getSecondOperand()->accept(this);
}

void ValueAnalysis::visit(ShPtr<StructIndexOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
		OrderedAllVisitor::visit(expr);
		return;
	}

	//
	// Struct accesses
	//
	valueData->containsStructAccesses = true;

	//
	// Directly used variables
	//
	// We consider a in a['1'] = 5 to be just read (not written).
	bool oldWriting = writing;
	writing = false;
	expr->getFirstOperand()->accept(this);
	expr->getSecondOperand()->accept(this);
	writing = oldWriting;
}

void ValueAnalysis::visit(ShPtr<BitAndOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<BitOrOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<BitShlOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<BitShrOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<BitXorOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<CallExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
		OrderedAllVisitor::visit(expr);
		return;
	}

	//
	// Calls
	//
	valueData->calls.push_back(expr);

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<CommaOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<DerefOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
		OrderedAllVisitor::visit(expr);
		return;
	}

	//
	// Dereferences
	//
	valueData->containsDerefs = true;

	//
	// Indirectly used variables
	//
	computeAndStoreIndirectlyUsedVars(expr);

	//
	// Directly used variables
	//

	// Traverse through the (possibly nested, like in `***p`) dereferences
	// until we find something different than a dereference. The reason why we
	// do this instead of just calling expr->getOperand()->accept(this) is that
	// if we did this, we would also compute indirectly used variables for all
	// sub-dereferences, which might give us invalid results. Indeed, recall
	// that in every call to <tt>visit(ShPtr<DerefOpExpr> expr)</tt>, we
	// compute indirectly used variables.
	ShPtr<Expression> firstNonDerefExpr(expr->getOperand());
	while (isa<DerefOpExpr>(firstNonDerefExpr)) {
		firstNonDerefExpr = ucast<DerefOpExpr>(firstNonDerefExpr)->getOperand();
	}

	// We consider a in *a = 5 to be just read (not written).
	bool oldWriting = writing;
	writing = false;
	firstNonDerefExpr->accept(this);
	writing = oldWriting;
}

void ValueAnalysis::visit(ShPtr<DivOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<EqOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<GtEqOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<GtOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<LtEqOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<LtOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<ModOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<MulOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<NegOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<NeqOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<NotOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<OrOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<SubOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<TernaryOpExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<Variable> var) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(var);
		OrderedAllVisitor::visit(var);
		return;
	}

	//
	// Directly used variables
	//
	if (writing) {
		valueData->dirWrittenVars.insert(var);
	} else {
		valueData->dirReadVars.insert(var);
	}

	valueData->dirNumOfVarUses[var]++;
}

void ValueAnalysis::visit(ShPtr<BitCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<ExtCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<FPToIntCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<IntToFPCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<IntToPtrCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<PtrToIntCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<TruncCastExpr> expr) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(expr);
	}

	OrderedAllVisitor::visit(expr);
}

void ValueAnalysis::visit(ShPtr<ConstArray> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

void ValueAnalysis::visit(ShPtr<ConstBool> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

void ValueAnalysis::visit(ShPtr<ConstFloat> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

void ValueAnalysis::visit(ShPtr<ConstInt> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

void ValueAnalysis::visit(ShPtr<ConstNullPointer> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

void ValueAnalysis::visit(ShPtr<ConstString> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

void ValueAnalysis::visit(ShPtr<ConstStruct> constant) {
	//
	// Caching
	//
	if (removingFromCache) {
		Caching::removeFromCache(constant);
	}

	OrderedAllVisitor::visit(constant);
}

} // namespace llvmir2hll
} // namespace retdec
