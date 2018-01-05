/**
* @file src/llvmir2hll/analysis/used_types_visitor.cpp
* @brief A visitor for obtaining the used types in the IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/used_types_visitor.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/utils/container.h"

using retdec::utils::addToSet;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new UsedTypes object.
*/
UsedTypes::UsedTypes(): intTypes(), floatTypes(), structTypes(),
	otherTypes(), allTypes(), usedBool(false) {}

/**
* @brief Constructs a new UsedTypes object from @a other.
*/
UsedTypes::UsedTypes(const UsedTypes &other) = default;

/**
* @brief Destructs the object.
*/
UsedTypes::~UsedTypes() {}

/**
* @brief Assigns @a other to the current object.
*/
UsedTypes &UsedTypes::operator=(const UsedTypes &other) = default;

/**
* @brief Returns @c true if the current object is equal to @a other, @c false
*        otherwise.
*/
bool UsedTypes::operator==(const UsedTypes &other) const {
	return (intTypes == other.intTypes &&
		floatTypes == other.floatTypes &&
		structTypes == other.structTypes &&
		otherTypes == other.otherTypes &&
		allTypes == other.allTypes &&
		usedBool == other.usedBool);
}

/**
* @brief Returns @c true if the current object is not equal to @a other, @c
*        false otherwise.
*/
bool UsedTypes::operator!=(const UsedTypes &other) const {
	return !(*this == other);
}

/**
* @brief Returns the integer types.
*/
TypeSet UsedTypes::getIntTypes() const {
	return intTypes;
}

/**
* @brief Returns the signed integer types.
*/
TypeSet UsedTypes::getSignedIntTypes() const {
	return signedIntTypes;
}

/**
* @brief Returns the unsigned integer types.
*/
TypeSet UsedTypes::getUnsignedIntTypes() const {
	return unsignedIntTypes;
}

/**
* @brief Returns the float types.
*/
TypeSet UsedTypes::getFloatTypes() const {
	return floatTypes;
}

/**
* @brief Returns the structure types.
*/
StructTypeSet UsedTypes::getStructTypes() const {
	return structTypes;
}

/**
* @brief Returns the other types (int, float, struct not included).
*/
TypeSet UsedTypes::getOtherTypes() const {
	return otherTypes;
}

/**
* @brief Returns the all types (int, float, struct included).
*/
TypeSet UsedTypes::getAllTypes() const {
	return allTypes;
}

/**
* @brief Returns the number of used types.
*
* @param[in] intTy Include the number of integer types.
* @param[in] floatTy Include the number of float types.
* @param[in] structTy Include the number of struct types.
* @param[in] otherTy Include the number of other types
*                    (int, float, struct not included).
*
* If all params are @c true, returns the number of all used types.
*/
std::size_t UsedTypes::getCount(bool intTy, bool floatTy,
		bool structTy, bool otherTy) const {
	std::size_t count = 0;
	if (intTy) {
		count += intTypes.size();
	}
	if (floatTy) {
		count += floatTypes.size();
	}
	if (structTy) {
		count += structTypes.size();
	}
	if (otherTy) {
		// Other types are all types without int, float and struct types.
		count += otherTypes.size();
	}
	return count;
}

/**
* @brief Returns @c true if the bool type was detected, @c false otherwise.
*/
bool UsedTypes::isUsedBool() const {
	return usedBool;
}

/**
* @brief Returns an iterator to the first signed int type.
*/
UsedTypes::type_iterator UsedTypes::signed_int_begin() const {
	return signedIntTypes.begin();
}

/**
* @brief Returns an iterator past the last signed int type.
*/
UsedTypes::type_iterator UsedTypes::signed_int_end() const {
	return signedIntTypes.end();
}

/**
* @brief Returns an iterator to the first unsigned int type.
*/
UsedTypes::type_iterator UsedTypes::unsigned_int_begin() const {
	return unsignedIntTypes.begin();
}

/**
* @brief Returns an iterator past the last unsigned int type.
*/
UsedTypes::type_iterator UsedTypes::unsigned_int_end() const {
	return unsignedIntTypes.end();
}

/**
* @brief Returns an iterator to the first int type.
*/
UsedTypes::type_iterator UsedTypes::int_begin() const {
	return intTypes.begin();
}

/**
* @brief Returns an iterator past the last int type.
*/
UsedTypes::type_iterator UsedTypes::int_end() const {
	return intTypes.end();
}

/**
* @brief Returns an iterator to the first float type.
*/
UsedTypes::type_iterator UsedTypes::float_begin() const {
	return floatTypes.begin();
}

/**
* @brief Returns an iterator past the last float type.
*/
UsedTypes::type_iterator UsedTypes::float_end() const {
	return floatTypes.end();
}

/**
* @brief Returns an iterator to the first struct type.
*/
UsedTypes::struct_type_iterator UsedTypes::struct_begin() const {
	return structTypes.begin();
}

/**
* @brief Returns an iterator past the last struct type.
*/
UsedTypes::struct_type_iterator UsedTypes::struct_end() const {
	return structTypes.end();
}

/**
* @brief Returns an iterator to the first other type.
*/
UsedTypes::type_iterator UsedTypes::other_begin() const {
	return otherTypes.begin();
}

/**
* @brief Returns an iterator past the last other type.
*/
UsedTypes::type_iterator UsedTypes::other_end() const {
	return otherTypes.end();
}

/**
* @brief Returns an iterator to the first type.
*/
UsedTypes::type_iterator UsedTypes::all_begin() const {
	return allTypes.begin();
}

/**
* @brief Returns an iterator past the last type.
*/
UsedTypes::type_iterator UsedTypes::all_end() const {
	return allTypes.end();
}

/**
* @brief Constructs a new visitor.
*/
UsedTypesVisitor::UsedTypesVisitor():
	OrderedAllVisitor(), usedTypes(new UsedTypes()) {}

/**
* @brief Destructs the visitor.
*/
UsedTypesVisitor::~UsedTypesVisitor() {}

/**
* @brief Returns the set of used types in the given module.
*
* @param[in] module Searched module.
*/
ShPtr<UsedTypes> UsedTypesVisitor::getUsedTypes(ShPtr<Module> module) {
	ShPtr<UsedTypesVisitor> visitor(new UsedTypesVisitor());

	// Obtain types from module.
	// Global vars.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		(*i)->accept(visitor.get());
	}

	// Functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(visitor.get());
	}

	ShPtr<UsedTypes> usedTypes(visitor->usedTypes);
	// Merge signed and unsigned integer sets into the set of integer types.
	addToSet(usedTypes->signedIntTypes, usedTypes->intTypes);
	addToSet(usedTypes->unsignedIntTypes, usedTypes->intTypes);
	// Merge sets of types into the set of all types.
	addToSet(usedTypes->intTypes, usedTypes->allTypes);
	addToSet(usedTypes->floatTypes, usedTypes->allTypes);
	for (auto i = usedTypes->struct_begin(), e = usedTypes->struct_end();
			i != e; ++i) {
		usedTypes->allTypes.insert(*i);
	}

	return usedTypes;
}

//
// Visits
//

void UsedTypesVisitor::visit(ShPtr<Function> func) {
	// Return type.
	func->getRetType()->accept(this);

	// Parameters and body.
	OrderedAllVisitor::visit(func);
}

void UsedTypesVisitor::visit(ShPtr<Variable> var) {
	var->getType()->accept(this);
}

void UsedTypesVisitor::visit(ShPtr<ConstBool> constant) {
	usedTypes->usedBool = true;
}

//
// Casts
//

void UsedTypesVisitor::visit(ShPtr<BitCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

void UsedTypesVisitor::visit(ShPtr<ExtCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

void UsedTypesVisitor::visit(ShPtr<TruncCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

void UsedTypesVisitor::visit(ShPtr<FPToIntCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

void UsedTypesVisitor::visit(ShPtr<IntToFPCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

void UsedTypesVisitor::visit(ShPtr<IntToPtrCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

void UsedTypesVisitor::visit(ShPtr<PtrToIntCastExpr> expr) {
	expr->getType()->accept(this);
	OrderedAllVisitor::visit(expr);
}

//
// Types
//

void UsedTypesVisitor::visit(ShPtr<FloatType> type) {
	usedTypes->floatTypes.insert(type);
}

void UsedTypesVisitor::visit(ShPtr<IntType> type) {
	// If int type is has size 1, it is bool.
	if (type->isBool()) {
		usedTypes->usedBool = true;
	}
	if (type->isSigned()) {
		usedTypes->signedIntTypes.insert(type);
	} else {
		usedTypes->unsignedIntTypes.insert(type);
	}
}

void UsedTypesVisitor::visit(ShPtr<PointerType> type) {
	usedTypes->otherTypes.insert(type);
	OrderedAllVisitor::visit(type);
}

void UsedTypesVisitor::visit(ShPtr<StringType> type) {
	usedTypes->otherTypes.insert(type);
}

void UsedTypesVisitor::visit(ShPtr<ArrayType> type) {
	usedTypes->otherTypes.insert(type);
	OrderedAllVisitor::visit(type);
}

void UsedTypesVisitor::visit(ShPtr<StructType> type) {
	usedTypes->structTypes.insert(type);
	OrderedAllVisitor::visit(type);
}

void UsedTypesVisitor::visit(ShPtr<FunctionType> type) {
	usedTypes->otherTypes.insert(type);
	OrderedAllVisitor::visit(type);
}

void UsedTypesVisitor::visit(ShPtr<VoidType> type) {
	usedTypes->otherTypes.insert(type);
}

void UsedTypesVisitor::visit(ShPtr<UnknownType> type) {
	usedTypes->otherTypes.insert(type);
}

} // namespace llvmir2hll
} // namespace retdec
