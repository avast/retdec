/**
* @file include/retdec/llvmir2hll/ir/const_int.h
* @brief An integer constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_INT_H
#define RETDEC_LLVMIR2HLL_IR_CONST_INT_H

#include <cstddef>
#include <cstdint>
#include <string>

#include <llvm/ADT/APInt.h>
#include <llvm/ADT/APSInt.h>

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class IntType;
class Visitor;

/**
* @brief An integer constant.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstInt final: public Constant {
public:
	static ConstInt* create(std::int64_t value, unsigned bitWidth,
		bool isSigned = true);
	static ConstInt* create(const llvm::APInt &value,
		bool isSigned = true);
	static ConstInt* create(const llvm::APSInt &value);
	static ConstInt* getTwoToPositivePower(ConstInt* x);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual retdec::llvmir2hll::Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	void flipSign();

	bool isMinSigned() const;
	bool isSigned() const;
	bool isUnsigned() const;
	llvm::APSInt getValue() const;
	std::string toString(unsigned radix = 10,
		const std::string &prefix = "") const;
	std::string toHexString(const std::string &prefix = "0x") const;
	bool isNegative() const;
	bool isNegativeOne() const;
	bool isPositive() const;
	bool isZero() const;
	bool isOne() const;
	bool isMoreReadableInHexa() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

	static bool classof(const Value* v) {
		return v->getKind() == Value::ValueKind::ConstInt; }

private:
	/// Value of the constant.
	llvm::APSInt value;

	/// Type of the constant.
	IntType* type = nullptr;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit ConstInt(const llvm::APSInt &value);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
