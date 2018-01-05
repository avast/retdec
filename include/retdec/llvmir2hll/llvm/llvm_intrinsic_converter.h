/**
* @file include/retdec/llvmir2hll/llvm/llvm_intrinsic_converter.h
* @brief Conversion of LLVM intrinsic functions into functions from the
*        standard C library.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVM_INTRINSIC_CONVERTER_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVM_INTRINSIC_CONVERTER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class CallExpr;
class Function;
class Module;

/**
* @brief Conversion of LLVM intrinsic functions into functions from the
*        standard C library.
*
* LLVM intrinsic functions are of the following format (see
* http://llvm.org/docs/LangRef.html#intrinsics):
* @code
* llvm.FUNCNAME.SPECIFICATIONS
* @endcode
* where @c FUNCNAME is the name of a function and @c SPECIFICATIONS are some
* additional specifications.
*
* For example, the following function is an LLVM's intrinsic variant of the
* standard @c memcpy() function from C:
* @code
* declare void @llvm.memcpy.p0i8.p0i8.i32(i8* nocapture,
*     i8* nocapture, i32, i32, i1) nounwind
* @endcode
* Unlike the C version, this one takes 5 parameters, where the last two specify
* alignment and volatileness. We convert this function into
* @code
* void *memcpy(void *dest, const void *src, size_t n);
* @endcode
* Hence, we drop the last two parameters.
*
* The convert() function of this class performs this conversion. The following
* LLVM intrinsics are converted:
* @code
*  - llvm.memcpy.*   (arguments/parameters are decreased from 5 to 3)
*  - llvm.memmove.*  (detto)
*  - llvm.memset.*   (detto)
*  - llvm.sqrt.*
*  - llvm.sin.*
*  - llvm.cos.*
*  - llvm.pow.*
*  - llvm.exp.*
*  - llvm.log.*
*  - llvm.fma.*
*  - llvm.fabs.*
*  - llvm.floor.*
*  - llvm.trap       (converted into abort)
* @endcode
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class LLVMIntrinsicConverter: private OrderedAllVisitor,
		private retdec::utils::NonCopyable {
public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~LLVMIntrinsicConverter() override;

	static void convert(ShPtr<Module> module);

private:
	LLVMIntrinsicConverter(ShPtr<Module> module);

	void performConversion();
	bool isIntrinsicFunc(ShPtr<Function> func) const;
	void convertIntrinsicFuncName(ShPtr<Function> func);
	void renameIntrinsicFunc(ShPtr<Function> func,
		const std::string &newName);
	void renameFloatIntrinsicFunc(ShPtr<Function> func,
		const std::string &baseName);
	void trimLastNArgsAndParams(ShPtr<CallExpr> expr,
		ShPtr<Function> func, unsigned m, unsigned n);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallExpr> expr) override;
	/// @}

private:
	/// Module in which LLVM intrinsic functions are converted.
	ShPtr<Module> module;

	/// Set of new names for changed LLVM intrinsics.
	StringSet renamedFuncNames;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
