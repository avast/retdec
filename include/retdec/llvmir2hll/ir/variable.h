/**
* @file include/retdec/llvmir2hll/ir/variable.h
* @brief A representation of a variable.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_VARIABLE_H
#define RETDEC_LLVMIR2HLL_IR_VARIABLE_H

#include <string>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Type;
class Visitor;

/**
* @brief A representation of a variable.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class Variable final: public Expression {
public:
	static ShPtr<Variable> create(const std::string &name, ShPtr<Type> type);

	virtual ~Variable() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	const std::string &getInitialName() const;
	const std::string &getName() const;
	bool hasName() const;
	bool isInternal() const;
	bool isExternal() const;
	ShPtr<Variable> copy() const;

	void setName(const std::string &newName);
	void setType(ShPtr<Type> newType);
	void markAsInternal();
	void markAsExternal();

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	Variable(const std::string &name, ShPtr<Type> type);

private:
	/// Initial name of the variable.
	std::string initialName;

	/// Name of the variable.
	std::string name;

	/// Type of the variable.
	ShPtr<Type> type;

	/// Is the variable internal?
	bool internal;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
