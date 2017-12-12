/**
* @file include/llvmir2hll/llvm/llvmir2bir_converters/new_llvmir2bir_converter/llvm_fcmp_converter.h
* @brief A converter from LLVM fcmp instruction to expression in BIR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_FCMP_CONVERTER_H
#define LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_NEW_LLVMIR2BIR_CONVERTER_LLVM_FCMP_CONVERTER_H

#include "llvmir2hll/support/smart_ptr.h"
#include "llvmir2hll/support/types.h"
#include "tl-cpputils/non_copyable.h"

namespace llvm {

class FCmpInst;

} // namespace llvm

namespace llvmir2hll {

class Expression;

/**
* @brief A converter from LLVM fcmp instruction to expression in BIR.
*/
class LLVMFCmpConverter final: private tl_cpputils::NonCopyable {
public:
	LLVMFCmpConverter();

	ShPtr<Expression> convertToExpression(ShPtr<Expression> op1,
		ShPtr<Expression> op2, unsigned predicate);

	/// @name Options
	/// @{
	void setOptionStrictFPUSemantics(bool strict = true);
	/// @}

private:
	ShPtr<Expression> getExprIsNotQNAN(ShPtr<Expression> op) const;
	ShPtr<Expression> getExprIsQNAN(ShPtr<Expression> op) const;

	template<class T>
	ShPtr<Expression> getOrdFCmpExpr(ShPtr<Expression> op1,
		ShPtr<Expression> op2) const;
	template<class T>
	ShPtr<Expression> getUnordFCmpExpr(ShPtr<Expression> op1,
		ShPtr<Expression> op2) const;

	/// Use strict FPU semantics?
	bool optionStrictFPUSemantics;
};

} // namespace llvmir2hll

#endif
