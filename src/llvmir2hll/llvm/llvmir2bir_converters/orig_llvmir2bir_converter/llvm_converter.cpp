/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_converter.cpp
* @brief Implementation LLVMConverter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <string>

#include <llvm/IR/CallSite.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/ErrorHandling.h>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/binary_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
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
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/vars_handler.h"
#include "retdec/llvmir2hll/llvm/string_conversions.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"

using namespace retdec::llvm_support;

using retdec::utils::mapHasKey;

namespace retdec {
namespace llvmir2hll {
namespace {

/**
* @brief Returns @c true if the specified LLVM value's name needs to have its
*        address taken in order to get a value of the correct type.
*
* @par Preconditions
*  - @a v is non-null
*/
bool isAddressExposed(const llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	return LLVMSupport::isDirectAlloca(v) || llvm::isa<llvm::GlobalVariable>(v);
}

/**
* @brief Creates a constant array from the given initializer.
*/
ShPtr<ConstArray> createInitializedConstArray(const ExprVector &values) {
	// Do not use llvmTypeToType() because it considers all string types as
	// char * (a pointer). We want to have StringType in such cases.
	ArrayType::Dimensions dims{values.size()};
	ShPtr<ArrayType> arrayType = ArrayType::create(values.front()->getType(), dims);
	return ConstArray::create(values, arrayType);
}

} // anonymous namespace

/**
* @brief Constructs a new converter.
*
* See create() for more information.
*/
LLVMConverter::LLVMConverter(llvm::Module *module, ShPtr<Module> resModule,
	ShPtr<VarsHandler> varsHandler):
		module(module), resModule(resModule), varsHandler(varsHandler),
		llvmTypeToTypeMap(), optionStrictFPUSemantics(false) {}

/**
* @brief Destructs the converter.
*/
LLVMConverter::~LLVMConverter() {}

/**
* @brief Converts the given LLVM constant @a c into an expression in the
*        backend IR.
*
* @par Preconditions
*  - @a c is non-null and corresponds to an expression
*/
ShPtr<Expression> LLVMConverter::llvmConstantToExpression(llvm::Constant *c) {
	PRECONDITION_NON_NULL(c);

	// Expression
	if (llvm::ConstantExpr *ce = llvm::dyn_cast<llvm::ConstantExpr>(c)) {
		ShPtr<Expression> op(llvmValueToExpression(ce->getOperand(0)));
		switch (ce->getOpcode()) {
			// Casts
			case llvm::Instruction::Trunc:
				return TruncCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::ZExt:
				return ExtCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::SExt:
				return ExtCastExpr::create(op, llvmTypeToType(ce->getType(), true),
						ExtCastExpr::Variant::SExt);

			case llvm::Instruction::FPTrunc:
				return TruncCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::FPExt:
				return ExtCastExpr::create(op, llvmTypeToType(ce->getType()),
						ExtCastExpr::Variant::FPExt);

			case llvm::Instruction::UIToFP:
				return IntToFPCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::SIToFP:
				return IntToFPCastExpr::create(op, llvmTypeToType(ce->getType()),
					IntToFPCastExpr::Variant::SIToFP);

			case llvm::Instruction::FPToUI:
				return FPToIntCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::FPToSI:
				return FPToIntCastExpr::create(op, llvmTypeToType(ce->getType(), true));

			case llvm::Instruction::PtrToInt:
				return PtrToIntCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::IntToPtr:
				return IntToPtrCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::BitCast:
				return BitCastExpr::create(op, llvmTypeToType(ce->getType()));

			case llvm::Instruction::GetElementPtr:
				return llvmGEPExpressionToExpressionInternal(ce->getOperand(0),
					gep_type_begin(c), gep_type_end(c));

			// Select
			case llvm::Instruction::Select: {
				ShPtr<Expression> cond(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> trueValue(llvmValueToExpression(ce->getOperand(1)));
				ShPtr<Expression> falseValue(llvmValueToExpression(ce->getOperand(2)));
				return TernaryOpExpr::create(cond, trueValue, falseValue);
			}

			// Add
			case llvm::Instruction::Add:
			case llvm::Instruction::FAdd: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return AddOpExpr::create(op1, op2);
			}

			// Sub
			case llvm::Instruction::Sub:
			case llvm::Instruction::FSub: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return SubOpExpr::create(op1, op2);
			}

			// Mul
			case llvm::Instruction::Mul:
			case llvm::Instruction::FMul: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return MulOpExpr::create(op1, op2);
			}

			// Div
			case llvm::Instruction::UDiv:
			case llvm::Instruction::SDiv:
			case llvm::Instruction::FDiv: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return DivOpExpr::create(op1, op2);
			}

			// Mod
			case llvm::Instruction::URem:
			case llvm::Instruction::SRem:
			case llvm::Instruction::FRem: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return ModOpExpr::create(op1, op2);
			}

			// Cmp
			case llvm::Instruction::ICmp:
			case llvm::Instruction::FCmp: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return EqOpExpr::create(op1, op2);
			}

			// And
			case llvm::Instruction::And: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return BitAndOpExpr::create(op1, op2);
			}

			// Or
			case llvm::Instruction::Or: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return BitOrOpExpr::create(op1, op2);
			}

			// Xor
			case llvm::Instruction::Xor: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return BitXorOpExpr::create(op1, op2);
			}

			// Shl
			case llvm::Instruction::Shl: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return BitShlOpExpr::create(op1, op2);
			}

			// Shr
			case llvm::Instruction::LShr:
			case llvm::Instruction::AShr: {
				ShPtr<Expression> op1(llvmValueToExpression(ce->getOperand(0)));
				ShPtr<Expression> op2(llvmValueToExpression(ce->getOperand(1)));
				return BitShrOpExpr::create(op1, op2,
					ce->getOpcode() == llvm::Instruction::LShr ?
						BitShrOpExpr::Variant::Logical :
						BitShrOpExpr::Variant::Arithmetical
				);
			}

			default:
				printErrorMessage("Unknown constant expression type: ", *ce);
				llvm_unreachable(0);
				break;
		}
	} else if (llvm::isa<llvm::UndefValue>(c) && c->getType()->isSingleValueType()) {
		return getDefaultInitializer(c->getType());
	}

	// Int
	if (llvm::ConstantInt *cInt = llvm::dyn_cast<llvm::ConstantInt>(c)) {
		// If the constant is only on a single bit (i.e. it is of the i1 type),
		// make it a boolean constant instead of an integer constant.
		if (cInt->getBitWidth() == 1) {
			return ConstBool::create(!cInt->isZero());
		}
		return ConstInt::create(cInt->getValue());
	}

	// Float
	if (llvm::ConstantFP *cFP = llvm::dyn_cast<llvm::ConstantFP>(c)) {
		return ConstFloat::create(cFP->getValueAPF());
	}

	// Array
	if (llvm::ConstantArray *ca = llvm::dyn_cast<llvm::ConstantArray>(c)) {
		return llvmConstantArrayToExpression(ca);
	}

	// Constant aggregate zero
	if (llvm::ConstantAggregateZero *caz = llvm::dyn_cast<llvm::ConstantAggregateZero>(c)) {
		return getDefaultInitializer(caz->getType());
	}

	// Undefined value
	if (llvm::UndefValue *uv = llvm::dyn_cast<llvm::UndefValue>(c)) {
		return getDefaultInitializer(uv->getType());
	}

	// Constant data array
	if (llvm::ConstantDataArray *cda = llvm::dyn_cast<llvm::ConstantDataArray>(c)) {
		if (cda->isString()) {
			return toConstString(cda);
		}
		return llvmConstantDataSequentialToConstArray(cda);
	}

	// Constant data sequential
	if (llvm::ConstantDataSequential *cds = llvm::dyn_cast<llvm::ConstantDataSequential>(c)) {
		return llvmConstantDataSequentialToConstArray(cds);
	}

	// Address of a block.
	if (llvm::isa<llvm::BlockAddress>(c)) {
		// TODO Add support for this type of a constant.
		printErrorMessage("Unsupported constant ", *c, " of type llvm::BlockAddress*.");
		llvm_unreachable(0);
	}

	// Other
	switch (c->getType()->getTypeID()) {
		case llvm::Type::FloatTyID:
		case llvm::Type::DoubleTyID:
		case llvm::Type::X86_FP80TyID:
		case llvm::Type::PPC_FP128TyID:
		case llvm::Type::FP128TyID: {
			llvm::ConstantFP *cFP = llvm::cast<llvm::ConstantFP>(c);
			return ConstFloat::create(cFP->getValueAPF());
		}

		case llvm::Type::PointerTyID: {
			if (llvm::ConstantPointerNull *cpn = llvm::dyn_cast<llvm::ConstantPointerNull>(c)) {
				ShPtr<PointerType> pointerType(cast<PointerType>(llvmTypeToType(cpn->getType())));
				ASSERT_MSG(pointerType, "got a pointer which is of a non-pointer type");
				return ConstNullPointer::create(pointerType);
			}

			llvm::GlobalVariable *gvar = llvm::dyn_cast<llvm::GlobalVariable>(c);
			if (gvar && gvar->hasInitializer()) {
				if (llvm::ConstantArray *ca = llvm::dyn_cast<llvm::ConstantArray>(
						gvar->getInitializer())) {
					return llvmConstantArrayToExpression(ca);
				}
			}

			return llvmValueToExpression(c);
		}

		case llvm::Type::StructTyID:
			if (llvm::isa<llvm::ConstantAggregateZero>(c) || llvm::isa<llvm::UndefValue>(c)) {
				llvm::StructType *st = llvm::cast<llvm::StructType>(c->getType());
				if (st->getNumElements()) {
					ConstStruct::Type constValue;
					for (unsigned i = 0, e = st->getNumElements(); i != e; ++i) {
						// TODO Is the used number of bits (32) correct?
						constValue.push_back(ConstStruct::Item(
							ConstInt::create(i, 32), llvmConstantToExpression(
							llvm::Constant::getNullValue(st->getElementType(i)))));
					}
					return ConstStruct::create(constValue,
						cast<StructType>(llvmTypeToType(st)));
				}
			} else {
				ConstStruct::Type constValue;
				for (unsigned i = 0, e = c->getNumOperands(); i != e; ++i) {
					// TODO Is the used number of bits (32) correct?
					constValue.push_back(ConstStruct::Item(
						ConstInt::create(i, 32), llvmConstantToExpression(
						llvm::cast<llvm::Constant>(c->getOperand(i)))));
				}
				return ConstStruct::create(constValue,
					cast<StructType>(llvmTypeToType(c->getType())));
			}
			break;

		default:
			printErrorMessage("Unknown constant type: ", *c, " (ID: ",
				c->getType()->getTypeID(), ")");
			llvm_unreachable(0);
			break;
	}

	FAIL("the constant `" << *c <<
		"` does not correspond to an expression; this should never happen");
	return ShPtr<Expression>();
}

/**
* @brief Converts the given LLVM value @a v into an expression in the backend IR.
*
* @par Preconditions
*  - @a v is non-null and corresponds to an expression
*/
ShPtr<Expression> LLVMConverter::llvmValueToExpression(llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	ShPtr<Expression> expr = llvmValueToExpressionInternal(v);
	if (!isAddressExposed(v)) {
		return expr;
	}

	// If the expression is a string literal, then instead of &"string", return
	// just "string".
	if (isa<ConstString>(expr)) {
		return expr;
	}

	return ShPtr<Expression>(AddressOpExpr::create(expr));
}

/**
* @brief Converts the given LLVM value @a v into an expression in the backend
*        IR.
*
* @par Preconditions
*  - @a v is non-null and corresponds to an expression
*
* TODO Highlight the difference between this function and
*      llvmValueToExpression().
*/
ShPtr<Expression> LLVMConverter::llvmValueToExpressionInternal(llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	if (llvm::Instruction *i = llvm::dyn_cast<llvm::Instruction>(v)) {
		// Should we inline this instruction?
		if (LLVMSupport::isInlinableInst(i) && !LLVMSupport::isDirectAlloca(i)) {
			return cast<Expression>(visit(*i));
		}
	}

	if (llvm::Constant *c = llvm::dyn_cast<llvm::Constant>(v)) {
		// The conversion depends on whether the constant is a global value or
		// not.
		if (llvm::isa<llvm::GlobalValue>(c)) {
			// Check if the value is a string literal. If so, return it.
			if (llvm::GlobalVariable *gv = llvm::dyn_cast<llvm::GlobalVariable>(c)) {
				if (resModule->isGlobalVarStoringStringLiteral(gv->getName()) ||
						stores8BitStringLiteral(gv)) {
					return getInitializerAsConstString(gv);
				}
			}
		} else {
			return llvmConstantToExpression(c);
		}
	}

	// It is nothing from above, return a variable.
	std::string operandName = varsHandler->getValueName(v);
	ShPtr<Variable> var = varsHandler->getVariableByName(operandName);
	if (isa<UnknownType>(var->getType())) {
		llvm::Type *fixedType = v->getType();
		if (llvm::Type *allocatedType = varsHandler->getAllocatedVarType(v)) {
			fixedType = allocatedType;
		}
		var->setType(llvmTypeToType(fixedType));
	}
	return var;
}

/**
* @brief Returns the result of dereferencing the specified operand with '*'.
*
* This is equivalent to generating a dereference operator and then using
* llvmValueToExpression(), but avoids excess syntax in some cases.
*
* @par Preconditions
*  - @a v is non-null and has a default initializer
*/
ShPtr<Expression> LLVMConverter::llvmValueToExpressionDeref(llvm::Value *v) {
	PRECONDITION_NON_NULL(v);

	if (isAddressExposed(v)) {
		// Already something with its address exposed.
		return llvmValueToExpressionInternal(v);
	}
	return DerefOpExpr::create(llvmValueToExpression(v));
}

/**
* @brief Converts the given LLVM GetElementPtr expression into an expression in
*        the backend IR.
*
* @param[in] ptr GetElementPtr expression.
* @param[in] i Iterator to the first index.
* @param[in] e Iterator one past the last index.
*
* @par Preconditions
*  - @a ptr is non-null and is a GetElementPtr expression
*/
ShPtr<Expression> LLVMConverter::llvmGEPExpressionToExpressionInternal(
		llvm::Value *ptr, llvm::gep_type_iterator i, llvm::gep_type_iterator e) {
	PRECONDITION_NON_NULL(ptr);

	// If there are no indices, just return the pointer.
	if (i == e) {
		return llvmValueToExpression(ptr);
	}

	// If the expression is a global constant storing a string literal, return
	// directly it, not an access to a variable that stores it (this makes e.g.
	// printf() calls more readable).
	llvm::GlobalVariable *gv = llvm::dyn_cast<llvm::GlobalVariable>(ptr);
	if (gv && (resModule->isGlobalVarStoringStringLiteral(gv->getName()) ||
			stores8BitStringLiteral(gv))) {
		for (auto gi = module->global_begin(), ge = module->global_end();
				gi != ge; ++gi) {
			if (gi->getName() != gv->getName()) {
				continue;
			}

			// We have found a matching global variable.
			return getInitializerAsConstString(gv);
		}
	}

	// If the first index is 0 (very typical), we can do a number of
	// simplifications to clean up the resulting expression.
	llvm::Value *firstOp = i.getOperand();
	ShPtr<Expression> currentOperand;
	if (!llvm::isa<llvm::Constant>(firstOp) || !llvm::cast<llvm::Constant>(firstOp)->isNullValue()) {
		// The first index isn't simple, transform it the hard way.
		currentOperand = llvmValueToExpression(ptr);
	} else {
		++i; // Skip the zero index.

		currentOperand = llvmValueToExpressionInternal(ptr);
		if (i != e && (*i)->isStructTy()) {
			currentOperand = StructIndexOpExpr::create(currentOperand,
				ConstInt::create(llvm::cast<llvm::ConstantInt>(i.getOperand())->getValue()));
			++i; // Eat the struct index as well.
		}
	}

	for (; i != e; ++i) {
		if ((*i)->isStructTy()) {
			currentOperand = StructIndexOpExpr::create(currentOperand,
				ConstInt::create(llvm::cast<llvm::ConstantInt>(i.getOperand())->getValue()));
		} else {
			currentOperand = ArrayIndexOpExpr::create(currentOperand,
				llvmValueToExpression(i.getOperand()));
		}
	}

	return AddressOpExpr::create(currentOperand);
}

/**
* @brief Returns the initializer of the given LLVM global variable @a v.
*
* If @a v doesn't have an initializer, it returns the null pointer.
*
* @par Preconditions
*  - @a v is non-null
*/
ShPtr<Expression> LLVMConverter::getInitializer(llvm::GlobalVariable *v) {
	PRECONDITION_NON_NULL(v);

	if (!v->hasInitializer()) {
		// No initializer.
		return ShPtr<Expression>();
	}

	return llvmConstantToExpression(v->getInitializer());
}

/**
* @brief Returns the default initializer for the given LLVM type @a t.
*
* @par Preconditions
*  - @a t is non-null and has a default initializer
*/
ShPtr<Constant> LLVMConverter::getDefaultInitializer(llvm::Type *t) {
	PRECONDITION_NON_NULL(t);

	switch (t->getTypeID()) {
		case llvm::Type::IntegerTyID: {
			llvm::IntegerType *it = llvm::cast<llvm::IntegerType>(t);
			// If the bit width of the type is only on a single bit (i.e. i1),
			// make it a boolean instead of an integer.
			if (it->getBitWidth() == 1) {
				return ConstBool::create(false);
			}
			return ConstInt::create(0, it->getBitWidth());
			}

		case llvm::Type::FloatTyID:
		case llvm::Type::DoubleTyID:
		case llvm::Type::X86_FP80TyID:
		case llvm::Type::PPC_FP128TyID:
		case llvm::Type::FP128TyID:
			return ConstFloat::create(llvm::APFloat(0.0));

		case llvm::Type::PointerTyID: {
			ShPtr<PointerType> type(cast<PointerType>(llvmTypeToType(t)));
			ASSERT_MSG(type, "got a pointer which is of a non-pointer type");
			return ConstNullPointer::create(type);
			}

		case llvm::Type::StructTyID: {
			// Recursively generate an initializer for a structure of the given
			// type.
			ConstStruct::Type constValue;
			for (unsigned i = 0, n = t->getNumContainedTypes(); i < n; ++i) {
				// TODO Is the used number of bits (32) correct?
				constValue.push_back(ConstStruct::Item(
					ConstInt::create(i, 32),
					getDefaultInitializer(t->getContainedType(i))));
			}
			return ConstStruct::create(constValue,
				cast<StructType>(llvmTypeToType(t)));
			}

		case llvm::Type::ArrayTyID: {
			llvm::ArrayType *arrayType = llvm::dyn_cast<llvm::ArrayType>(t);
			ShPtr<ArrayType> birArrayType = ucast<ArrayType>(llvmTypeToType(arrayType));
			return ConstArray::createUninitialized(birArrayType);
			}

		case llvm::Type::VectorTyID:
			// TODO Add support for this type.
			printErrorMessage("The vector type is not supported");
			llvm_unreachable(0);
			break;

		default:
			printErrorMessage("Unknown initializer for a type with ID ",
				t->getTypeID());
			llvm_unreachable(0);
			break;
	}
}

/**
* @brief Converts the given LLVM constant array @a ca into a constant array in
*        the backend IR.
*
* If @a ca is a null value (@c ca->isNullValue()), the empty array is returned.
*/
ShPtr<ConstArray> LLVMConverter::llvmConstantArrayToConstArray(llvm::ConstantArray *ca) {
	PRECONDITION_NON_NULL(ca);

	// If the array has no initializer, return the empty array.
	if (ca->isNullValue()) {
		return ucast<ConstArray>(getDefaultInitializer(ca->getType()));
	}

	// It has an initializer.
	ExprVector array;
	for (unsigned i = 0, e = ca->getNumOperands(); i != e; ++i) {
		array.push_back(llvmConstantToExpression(ca->getOperand(i)));
	}
	return createInitializedConstArray(array);
}

/**
* @brief Converts the given LLVM constant array @a ca into an expression in the
*        backend IR.
*/
ShPtr<Expression> LLVMConverter::llvmConstantArrayToExpression(llvm::ConstantArray *ca) {
	PRECONDITION_NON_NULL(ca);

	if (is8BitStringLiteral(ca)) {
		return toConstString(ca);
	}
	return llvmConstantArrayToConstArray(ca);
}

/**
* @brief Converts the given LLVM constant data sequential @a cds into a constant
*        array in the backend IR.
*
* If @a cds is a null value (@c cds->isNullValue()), the empty array is
* returned.
*/
ShPtr<ConstArray> LLVMConverter::llvmConstantDataSequentialToConstArray(
		llvm::ConstantDataSequential *cds) {
	PRECONDITION_NON_NULL(cds);

	// If cds has no initializer, return the empty array.
	if (cds->isNullValue()) {
		return ucast<ConstArray>(getDefaultInitializer(cds->getType()));
	}

	// It has an initializer.
	ExprVector array;
	for (unsigned i = 0, e = cds->getNumElements(); i != e; ++i) {
		array.push_back(llvmConstantToExpression(cds->getElementAsConstant(i)));
	}
	return createInitializedConstArray(array);
}

/**
* @brief Converts the given LLVM type @a llvmType into a type in the backend
*        IR.
*
* If @a llvmType cannot be converted into a type, the @c UnknownType is
* returned. If @a llvmSigned is @c true, the created type will be signed,
* otherwise unsigned.
*
* @par Preconditions
*  - @a llvmType is non-null
*/
ShPtr<Type> LLVMConverter::llvmTypeToType(llvm::Type *llvmType, bool llvmSigned) {
	PRECONDITION_NON_NULL(llvmType);

	// Since there may be recursive types (e.g. a structure contains a pointer
	// to itself), before calling this function recursively, we:
	//  - check if llvmTypeToTypeMap[llvmType] already exists; if this is
	//    so, it is used instead of converting llvmType by recursively
	//    calling this function
	//  - if it doesn't exist, we create a type in our IR
	//  - we add a mapping of llvmType into it
	//  - we convert the type and return the result
	//  In this way, we avoid infinite recursion occurring when converting
	//  recursive data types.
	//
	// Since signed types differ from unsigned types, we use two maps: one for
	// signed types, one for unsigned types.
	// Signed types should be only integers.
	if (llvmSigned && llvmType->isIntegerTy()) {
		if (mapHasKey(llvmTypeToSignedTypeMap, llvmType)) {
			return llvmTypeToSignedTypeMap[llvmType];
		}
	} else {
		if (mapHasKey(llvmTypeToTypeMap, llvmType)) {
			return llvmTypeToTypeMap[llvmType];
		}
	}

	// Function type.
	if (llvmType->isFunctionTy()) {
		return llvmTypeToTypeMap[llvmType] = llvmFunctionTypeToFunctionType(
			llvm::dyn_cast<llvm::FunctionType>(llvmType));
	}

	// Pointer.
	if (llvm::PointerType *pt = llvm::dyn_cast<llvm::PointerType>(llvmType)) {
		// First, we create a dummy pointer type.
		ShPtr<PointerType> convertedType(PointerType::create(
			IntType::create(1, false)));

		// Store a reference to it so it may be used in the nested
		// llvmTypeToType call.
		llvmTypeToTypeMap[llvmType] = convertedType;

		// Convert the nested type.
		convertedType->setContainedType(llvmTypeToType(pt->getContainedType(0)));
		return convertedType;
	}

	// Signed integer.
	if (llvmSigned && llvmType->isIntegerTy()) {
		return llvmTypeToSignedTypeMap[llvmType] = IntType::create(
			llvmType->getScalarSizeInBits(), true);
	// Unsigned integer.
	} else if (llvmType->isIntegerTy()) {
		return llvmTypeToTypeMap[llvmType] = IntType::create(
			llvmType->getScalarSizeInBits(), false);
	}

	// Float.
	if (llvmType->isFloatTy()) {
		return llvmTypeToTypeMap[llvmType] = FloatType::create(32);
	} else if (llvmType->isDoubleTy()) {
		return llvmTypeToTypeMap[llvmType] = FloatType::create(64);
	} else if (llvmType->isX86_FP80Ty()) {
		return llvmTypeToTypeMap[llvmType] = FloatType::create(80);
	} else if (llvmType->isFP128Ty() || llvmType->isPPC_FP128Ty()) {
		return llvmTypeToTypeMap[llvmType] = FloatType::create(128);
	}

	// Array.
	if (llvmType->isArrayTy()) {
		ArrayType::Dimensions arrayDims;
		llvm::ArrayType *arrayType = llvm::dyn_cast<llvm::ArrayType>(llvmType);
		llvm::ArrayType *arrayTypeTmp;
		do {
			arrayDims.push_back(arrayType->getNumElements());
			arrayTypeTmp = arrayType;
		} while ((arrayType = llvm::dyn_cast<llvm::ArrayType>(arrayType->getContainedType(0))));
		return llvmTypeToTypeMap[llvmType] = ArrayType::create(llvmTypeToType(
			arrayTypeTmp->getContainedType(0)), arrayDims);
	}

	// Structure.
	if (llvmType->isStructTy()) {
		StructType::ElementTypes elementTypes;
		llvm::StructType *structType = llvm::dyn_cast<llvm::StructType>(llvmType);
		for (unsigned i = 0; i < structType->getNumElements(); ++i) {
			elementTypes.push_back(llvmTypeToType(structType->getElementType(i)));
		}
		// Because of structures containing other structures, we have to check
		// whether we have already processed the structure also at this place
		// (above, there are calls to llvmTypeToType).
		if (mapHasKey(llvmTypeToTypeMap, llvmType)) {
			return llvmTypeToTypeMap[llvmType];
		}
		// StructType::getName() cannot be called on a literal, so we have to
		// first check that the type has a name and if so, we use it.
		return llvmTypeToTypeMap[llvmType] = StructType::create(elementTypes,
			structType->hasName() ? structType->getName() : "");
	}

	// Void.
	if (llvmType->isVoidTy())
		return llvmTypeToTypeMap[llvmType] = VoidType::create();

	// Unknown type.
	return llvmTypeToTypeMap[llvmType] = UnknownType::create();
}

/**
* @brief Converts the given LLVM function type into a type in the backend IR.
*
* @par Preconditions
*  - @a llvmType is non-null
*/
ShPtr<FunctionType> LLVMConverter::llvmFunctionTypeToFunctionType(
		llvm::FunctionType *llvmType) {
	PRECONDITION_NON_NULL(llvmType);

	ShPtr<FunctionType> funcType(FunctionType::create());

	// Return type.
	funcType->setRetType(llvmTypeToType(llvmType->getReturnType()));

	// Variable number of arguments.
	funcType->setVarArg(llvmType->isVarArg());

	// Parameters.
	for (auto i = llvmType->param_begin(), e = llvmType->param_end();
			i != e; ++i) {
		funcType->addParam(llvmTypeToType(*i));
	}

	return funcType;
}

/**
* @brief Converts the given LLVM load instruction @a i into an expression in
*        the backend IR.
*/
ShPtr<Expression> LLVMConverter::llvmLoadInstToExpression(llvm::LoadInst &i) {
	return llvmValueToExpressionDeref(i.getOperand(0));
}

/**
* @brief Converts the given LLVM store instruction @a i into an assign
*        statement in the backend IR.
*/
ShPtr<AssignStmt> LLVMConverter::llvmStoreInstToAssignStmt(llvm::StoreInst &i) {
	auto assignStmt = AssignStmt::create(
		llvmValueToExpressionDeref(i.getPointerOperand()),
		llvmValueToExpression(i.getOperand(0))
	);

	// We want to prevent optimization of variables used in volatile load/store
	// operations, so mark such variables as external.
	if (i.isVolatile()) {
		if (auto lhsVar = cast<Variable>(assignStmt->getLhs())) {
			lhsVar->markAsExternal();
		}
	}

	return assignStmt;
}

/**
* @brief Converts the given LLVM select instruction @a i into a ternary
*        operator in the backend IR.
*/
ShPtr<TernaryOpExpr> LLVMConverter::llvmSelectInstToTernaryOp(llvm::SelectInst &i) {
	ShPtr<Expression> cond(llvmValueToExpression(i.getCondition()));
	ShPtr<Expression> trueValue(llvmValueToExpression(i.getTrueValue()));
	ShPtr<Expression> falseValue(llvmValueToExpression(i.getFalseValue()));
	return TernaryOpExpr::create(cond, trueValue, falseValue);
}

/**
* @brief Converts the given LLVM call instruction @a i into a call statement in
*        the backend IR.
*/
ShPtr<CallStmt> LLVMConverter::llvmCallInstToCallStmt(llvm::CallInst &i) {
	ShPtr<Expression> calledExpr = llvmValueToExpression(i.getCalledValue());

	// Obtain arguments.
	ExprVector args;
	unsigned argNo = 0;
	llvm::CallSite cs(&i);
	for (auto ai = cs.arg_begin(), ae = cs.arg_end(); ai != ae; ++ai) {
		// Check if the argument is expected to be passed by value.
		ShPtr<Expression> arg = (i.paramHasAttr(argNo + 1, llvm::Attribute::ByVal)) ?
			llvmValueToExpressionDeref(*ai) : llvmValueToExpression(*ai);
		args.push_back(arg);
		argNo++;
	}

	ShPtr<CallExpr> callExpr(CallExpr::create(calledExpr, args));
	return CallStmt::create(callExpr);
}

/**
* @brief Converts the given LLVM GetElementPtr instruction @a i into an
*        expression in the backend IR.
*/
ShPtr<Expression> LLVMConverter::llvmGEPInstToExpression(llvm::GetElementPtrInst &i) {
	return llvmGEPExpressionToExpressionInternal(i.getPointerOperand(),
		gep_type_begin(i), gep_type_end(i));
}

/**
* @brief Converts the given LLVM alloca instruction @a i into an initializer.
*/
ShPtr<Expression> LLVMConverter::llvmAllocaInstToExpression(llvm::AllocaInst &i) {
	return getDefaultInitializer(i.getType()->getElementType());
}

/**
* @brief Converts the given LLVM instruction @a i into a value in the backend IR.
*/
ShPtr<Value> LLVMConverter::llvmInstructionToValue(llvm::Instruction &i) {
	return visit(i);
}

/**
* @brief Converts the given LLVM return instruction into a return statement in
*        the backend IR.
*/
ShPtr<Value> LLVMConverter::llvmReturnInstToReturnStmt(llvm::ReturnInst &i) {
	// NOTE: Do NOT try to eliminate the return statement here if this
	// instruction is the last in a basic block. This approach may fail if the
	// instruction is the last one prior to another case branch etc. Instead,
	// use VoidReturnOptimizer.

	ShPtr<Expression> retVal;
	if (i.getNumOperands() > 0) {
		retVal = llvmValueToExpression(i.getOperand(0));
	}
	return ReturnStmt::create(retVal);
}

/**
* @brief Converts the given LLVM binary operator @a i into an expression in
*        the backend IR.
*
* @par Preconditions
*  - @a i is a binary operation
*/
ShPtr<Expression> LLVMConverter::llvmBinaryOperatorToExpression(llvm::Instruction &i) {
	// Binary instructions, shift instructions, setCond instructions.
	PRECONDITION(!i.getType()->isPointerTy(), "it should not be a pointer");

	// If this is a negation operation, generate it out as such. For
	// floating-points, we don't want to generate "-0.0 - X".

	if (llvm::BinaryOperator::isNeg(&i)) {
		ShPtr<Expression> op(llvmValueToExpression(
			llvm::BinaryOperator::getNegArgument(llvm::cast<llvm::BinaryOperator>(&i))));
		return NegOpExpr::create(op);
	} else if (llvm::BinaryOperator::isFNeg(&i)) {
		ShPtr<Expression> op(llvmValueToExpression(
			llvm::BinaryOperator::getFNegArgument(llvm::cast<llvm::BinaryOperator>(&i))));
		return NegOpExpr::create(op);
	} else {
		ShPtr<Expression> op1(llvmValueToExpression(i.getOperand(0)));
		ShPtr<Expression> op2(llvmValueToExpression(i.getOperand(1)));

		switch (i.getOpcode()) {
			case llvm::Instruction::Add:
			case llvm::Instruction::FAdd:
				return AddOpExpr::create(op1, op2);

			case llvm::Instruction::Sub:
			case llvm::Instruction::FSub:
				return SubOpExpr::create(op1, op2);

			case llvm::Instruction::Mul:
			case llvm::Instruction::FMul:
				return MulOpExpr::create(op1, op2);

			case llvm::Instruction::URem:
				return ModOpExpr::create(op1, op2);
			case llvm::Instruction::SRem:
				return ModOpExpr::create(op1, op2, ModOpExpr::Variant::SMod);
			case llvm::Instruction::FRem:
				return ModOpExpr::create(op1, op2, ModOpExpr::Variant::FMod);

			case llvm::Instruction::UDiv:
				return DivOpExpr::create(op1, op2);
			case llvm::Instruction::SDiv:
				return DivOpExpr::create(op1, op2, DivOpExpr::Variant::SDiv);
			case llvm::Instruction::FDiv:
				return DivOpExpr::create(op1, op2, DivOpExpr::Variant::FDiv);

			case llvm::Instruction::And:
				return BitAndOpExpr::create(op1, op2);

			case llvm::Instruction::Or:
				return BitOrOpExpr::create(op1, op2);

			case llvm::Instruction::Xor:
				return BitXorOpExpr::create(op1, op2);

			case llvm::Instruction::Shl:
				return BitShlOpExpr::create(op1, op2);

			case llvm::Instruction::AShr:
				return BitShrOpExpr::create(op1, op2, BitShrOpExpr::Variant::Arithmetical);

			case llvm::Instruction::LShr:
				return BitShrOpExpr::create(op1, op2, BitShrOpExpr::Variant::Logical);

			default:
				llvm::errs() << "Invalid operator type: " << i << "\n";
				llvm_unreachable(0);
				break;
		}
	}
}

/**
* @brief Converts the given LLVM integer comparison instruction @a i into an
*        expression in the backend IR.
*/
ShPtr<Expression> LLVMConverter::llvmICmpInstToExpression(llvm::ICmpInst &i) {
	// Get both operands.
	ShPtr<Expression> op1 = llvmValueToExpression(i.getOperand(0));
	ShPtr<Expression> op2 = llvmValueToExpression(i.getOperand(1));

	// Get the operator.
	ShPtr<BinaryOpExpr> op;
	switch (i.getPredicate()) {
		case llvm::ICmpInst::ICMP_EQ:
			return EqOpExpr::create(op1, op2);
		case llvm::ICmpInst::ICMP_NE:
			return NeqOpExpr::create(op1, op2);
		case llvm::ICmpInst::ICMP_ULE:
			return LtEqOpExpr::create(op1, op2);
		case llvm::ICmpInst::ICMP_SLE:
			return LtEqOpExpr::create(op1, op2, LtEqOpExpr::Variant::SCmp);
		case llvm::ICmpInst::ICMP_UGE:
			return GtEqOpExpr::create(op1, op2);
		case llvm::ICmpInst::ICMP_SGE:
			return GtEqOpExpr::create(op1, op2, GtEqOpExpr::Variant::SCmp);
		case llvm::ICmpInst::ICMP_ULT:
			return LtOpExpr::create(op1, op2);
		case llvm::ICmpInst::ICMP_SLT:
			return LtOpExpr::create(op1, op2, LtOpExpr::Variant::SCmp);
		case llvm::ICmpInst::ICMP_UGT:
			return GtOpExpr::create(op1, op2);
		case llvm::ICmpInst::ICMP_SGT:
			return GtOpExpr::create(op1, op2, GtOpExpr::Variant::SCmp);
		default:
			printErrorMessage("Invalid ICmp predicate ", i);
			llvm_unreachable(0);
			return ShPtr<BinaryOpExpr>();
	}
}

/**
* @brief Converts the given LLVM floating-point comparison instruction @a i
*        into an expression in the backend IR.
*/
ShPtr<Expression> LLVMConverter::llvmFCmpInstToExpression(llvm::FCmpInst &i) {
	if (i.getPredicate() == llvm::FCmpInst::FCMP_FALSE) {
		return ConstBool::create(false);
	}
	if (i.getPredicate() == llvm::FCmpInst::FCMP_TRUE) {
		return ConstBool::create(true);
	}

	return optionStrictFPUSemantics ?
		llvmFCmpBinInstToExpressionStrictFPUSemantics(i) :
		llvmFCmpBinInstToExpressionNonStrictFPUSemantics(i);
}

/**
* @brief Converts the given LLVM floating-point comparison instruction (binary
*        predicate) @a i into an expression in the backend IR.
*
* Uses non-strict FPU semantics.
*/
ShPtr<Expression> LLVMConverter::llvmFCmpBinInstToExpressionNonStrictFPUSemantics(
		llvm::FCmpInst &i) {
	ASSERT_MSG(i.getNumOperands() >= 2,
		"expected a binary predicate, got a unary predicate " << i);

	// The following switch is based on the on in
	// llvmFCmpBinInstToExpressionStrictFPUSemantics() but creates a more
	// simple expression.
	ShPtr<Expression> x(llvmValueToExpression(i.getOperand(0)));
	ShPtr<Expression> y(llvmValueToExpression(i.getOperand(1)));
	switch (i.getPredicate()) {
		case llvm::FCmpInst::FCMP_UNO:
			return OrOpExpr::create(
				NeqOpExpr::create(x, x),
				NeqOpExpr::create(y, y));
		case llvm::FCmpInst::FCMP_ORD:
			return AndOpExpr::create(
				EqOpExpr::create(x, x),
				EqOpExpr::create(y, y));
		case llvm::FCmpInst::FCMP_UEQ:
		case llvm::FCmpInst::FCMP_OEQ:
			return EqOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_ULT:
		case llvm::FCmpInst::FCMP_OLT:
			return LtOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_ULE:
		case llvm::FCmpInst::FCMP_OLE:
			return LtEqOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_UGT:
		case llvm::FCmpInst::FCMP_OGT:
			return GtOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_UGE:
		case llvm::FCmpInst::FCMP_OGE:
			return GtEqOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_UNE:
		case llvm::FCmpInst::FCMP_ONE:
			return NeqOpExpr::create(x, y);
		default:
			printErrorMessage("Invalid FCmp predicate ", i);
			llvm_unreachable(0);
			break;
	}
}

/**
* @brief Converts the given LLVM floating-point comparison instruction (binary
*        predicate) @a i into an expression in the backend IR.
*
* Uses strict FPU semantics.
*/
ShPtr<Expression> LLVMConverter::llvmFCmpBinInstToExpressionStrictFPUSemantics(
		llvm::FCmpInst &i) {
	ASSERT_MSG(i.getNumOperands() >= 2,
		"expected a binary predicate, got a unary predicate " << i);

	// The following switch is created from functions introduced by CBackend.
	ShPtr<Expression> x(llvmValueToExpression(i.getOperand(0)));
	ShPtr<Expression> y(llvmValueToExpression(i.getOperand(1)));
	switch (i.getPredicate()) {
		case llvm::FCmpInst::FCMP_UNO:
			// llvm_fcmp_uno(x,y) { return x != x || y != y; }
			return OrOpExpr::create(
				NeqOpExpr::create(x, x),
				NeqOpExpr::create(y, y));
		case llvm::FCmpInst::FCMP_UEQ:
			// llvm_fcmp_ueq(x,y) { return x == y || llvm_fcmp_uno(x, y); }
			return OrOpExpr::create(
				EqOpExpr::create(x, y),
				OrOpExpr::create(
					NeqOpExpr::create(x, x),
					NeqOpExpr::create(y, y)));
		case llvm::FCmpInst::FCMP_ULT:
			// llvm_fcmp_ult(x,y) { return x <  y || llvm_fcmp_uno(x, y); }
			return OrOpExpr::create(
				LtOpExpr::create(x, y),
				OrOpExpr::create(
					NeqOpExpr::create(x, x),
					NeqOpExpr::create(y, y)));
		case llvm::FCmpInst::FCMP_ULE:
			// llvm_fcmp_ule(x,y) { return x <= y || llvm_fcmp_uno(x, y); }
			return OrOpExpr::create(
				LtEqOpExpr::create(x, y),
				OrOpExpr::create(
					NeqOpExpr::create(x, x),
					NeqOpExpr::create(y, y)));
		case llvm::FCmpInst::FCMP_UGT:
			// llvm_fcmp_ugt(x,y) { return x >  y || llvm_fcmp_uno(x, y); }
			return OrOpExpr::create(
				GtOpExpr::create(x, y),
				OrOpExpr::create(
					NeqOpExpr::create(x, x),
					NeqOpExpr::create(y, y)));
		case llvm::FCmpInst::FCMP_UGE:
			// llvm_fcmp_uge(x,y) { return x >= y || llvm_fcmp_uno(x, y); }
			return OrOpExpr::create(
				GtEqOpExpr::create(x, y),
				OrOpExpr::create(
					NeqOpExpr::create(x, x),
					NeqOpExpr::create(y, y)));
		case llvm::FCmpInst::FCMP_ORD:
			// llvm_fcmp_ord(x,y) { return x == x && y == y; }
			return AndOpExpr::create(
				EqOpExpr::create(x, x),
				EqOpExpr::create(y, y));
		case llvm::FCmpInst::FCMP_ONE:
			// llvm_fcmp_one(x,y) { return x != y && llvm_fcmp_ord(x, y); }
			return AndOpExpr::create(
				NeqOpExpr::create(x, y),
				AndOpExpr::create(
					EqOpExpr::create(x, x),
					EqOpExpr::create(y, y)));
		case llvm::FCmpInst::FCMP_UNE:
			// llvm_fcmp_une(x,y) { return x != y; }
			return NeqOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_OEQ:
			// llvm_fcmp_oeq(x,y) { return x == y ; }
			return EqOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_OLT:
			// llvm_fcmp_olt(x,y) { return x <  y ; }
			return LtOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_OLE:
			// llvm_fcmp_ole(x,y) { return x <= y ; }
			return LtEqOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_OGT:
			// llvm_fcmp_ogt(x,y) { return x >  y ; }
			return GtOpExpr::create(x, y);
		case llvm::FCmpInst::FCMP_OGE:
			// llvm_fcmp_oge(x,y) { return x >= y ; }
			return GtEqOpExpr::create(x, y);
		default:
			printErrorMessage("Invalid FCmp predicate ", i);
			llvm_unreachable(0);
			break;
	}
}

/**
* @brief Converts the given LLVM insert value instruction @a i into a
*        statement in the backend IR.
*
* The resulting statement are actually two statements.
*/
ShPtr<Statement> LLVMConverter::llvmInsertValueInstToStatement(llvm::InsertValueInst &i) {
	ShPtr<Expression> lhs, rhs;

	// Create the aggregate that is accessed by the instruction.
	lhs = llvmValueToExpression(&i);
	rhs = llvmValueToExpression(i.getOperand(0));
	ShPtr<Statement> aggregateDefStmt(AssignStmt::create(lhs, rhs));

	// Create the accesses.
	lhs = generateAccessesToCompositeType(
		llvm::dyn_cast<llvm::CompositeType>(i.getOperand(0)->getType()),
		i.getIndices(),
		varsHandler->getVariableByName(varsHandler->getValueName(&i)));
	rhs = llvmValueToExpression(i.getOperand(1));
	ShPtr<AssignStmt> aggregateAccessStmt(AssignStmt::create(lhs, rhs));

	return Statement::mergeStatements(aggregateDefStmt, aggregateAccessStmt);
}

/**
* @brief Converts the given LLVM extract value instruction @a i into an
*        expression in the backend IR.
*/
ShPtr<Expression> LLVMConverter::llvmExtractValueInstToExpression(
		llvm::ExtractValueInst &i) {
	if (llvm::isa<llvm::UndefValue>(i.getOperand(0))) {
		return getDefaultInitializer(i.getType());
	}
	return generateAccessesToCompositeType(
		llvm::dyn_cast<llvm::CompositeType>(i.getOperand(0)->getType()),
		i.getIndices(),
		varsHandler->getVariableByName(
			varsHandler->getValueName(i.getOperand(0))));
}

/**
* @brief Generates accesses to the given composite type from the given array of
*        indices, starting at the given base expression.
*/
ShPtr<Expression> LLVMConverter::generateAccessesToCompositeType(
		llvm::CompositeType *ct, llvm::ArrayRef<unsigned> indices,
		ShPtr<Expression> base) {
	ShPtr<Expression> expr(base);
	for (const auto index : indices) {
		// TODO Is the used number of bits (32) correct?
		ShPtr<ConstInt> currIndex(ConstInt::create(index, 32));

		if (llvm::isa<llvm::StructType>(ct)) {
			expr = StructIndexOpExpr::create(expr, currIndex);
		} else {
			expr = ArrayIndexOpExpr::create(expr, currIndex);
		}
		ct = llvm::dyn_cast<llvm::CompositeType>(ct->getTypeAtIndex(index));
	}
	return expr;
}

ShPtr<Value> LLVMConverter::visitBinaryOperator(llvm::Instruction &i) {
	return llvmBinaryOperatorToExpression(i);
}

ShPtr<Value> LLVMConverter::visitCastInst(llvm::CastInst &i) {
	ShPtr<Expression> op(llvmValueToExpression(i.getOperand(0)));
	switch (i.getOpcode()) {
		case llvm::Instruction::Trunc:
			return TruncCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::ZExt:
			return ExtCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::SExt:
			return ExtCastExpr::create(op, llvmTypeToType(i.getType(), true),
					ExtCastExpr::Variant::SExt);
		case llvm::Instruction::FPTrunc:
			return TruncCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::FPExt:
			return ExtCastExpr::create(op, llvmTypeToType(i.getType()),
					ExtCastExpr::Variant::FPExt);
		case llvm::Instruction::UIToFP:
			return IntToFPCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::SIToFP:
			return IntToFPCastExpr::create(op, llvmTypeToType(i.getType()),
				IntToFPCastExpr::Variant::SIToFP);
		case llvm::Instruction::FPToUI:
			return FPToIntCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::FPToSI:
			return FPToIntCastExpr::create(op, llvmTypeToType(i.getType(), true));
		case llvm::Instruction::PtrToInt:
			return PtrToIntCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::IntToPtr:
			return IntToPtrCastExpr::create(op, llvmTypeToType(i.getType()));
		case llvm::Instruction::BitCast:
			return BitCastExpr::create(op, llvmTypeToType(i.getType()));
		default:
			return llvmValueToExpression(i.getOperand(0));
	}
}

ShPtr<Value> LLVMConverter::visitCallInst(llvm::CallInst &i) {
	return llvmCallInstToCallStmt(i);
}

ShPtr<Value> LLVMConverter::visitAllocaInst(llvm::AllocaInst &i) {
	return llvmAllocaInstToExpression(i);
}

ShPtr<Value> LLVMConverter::visitInsertValueInst(llvm::InsertValueInst &i) {
	return llvmInsertValueInstToStatement(i);
}

ShPtr<Value> LLVMConverter::visitExtractValueInst(llvm::ExtractValueInst &i) {
	return llvmExtractValueInstToExpression(i);
}

ShPtr<Value> LLVMConverter::visitGetElementPtrInst(llvm::GetElementPtrInst &i) {
	return llvmGEPExpressionToExpressionInternal(i.getPointerOperand(),
		gep_type_begin(i), gep_type_end(i));
}

ShPtr<Value> LLVMConverter::visitICmpInst(llvm::ICmpInst &i) {
	return llvmICmpInstToExpression(i);
}

ShPtr<Value> LLVMConverter::visitFCmpInst(llvm::FCmpInst &i) {
	return llvmFCmpInstToExpression(i);
}

ShPtr<Value> LLVMConverter::visitLoadInst(llvm::LoadInst &i) {
	return llvmLoadInstToExpression(i);
}

ShPtr<Value> LLVMConverter::visitStoreInst(llvm::StoreInst &i) {
	return llvmStoreInstToAssignStmt(i);
}

ShPtr<Value> LLVMConverter::visitSelectInst(llvm::SelectInst &i) {
	return llvmSelectInstToTernaryOp(i);
}

ShPtr<Value> LLVMConverter::visitInstruction(llvm::Instruction &i) {
	printErrorMessage("Unknown instruction:", i); // No space after ":".
	llvm_unreachable(0);
	return ShPtr<Value>();
}

/**
* @brief Enables/disables the use of strict FPU semantics.
*
* @param[in] strict If @c true, enables the use of strict FPU semantics. If @c
*                   false, disables the use of strict FPU semantics.
*/
void LLVMConverter::setOptionStrictFPUSemantics(bool strict) {
	optionStrictFPUSemantics = strict;
}

} // namespace llvmir2hll
} // namespace retdec
