/**
* @file include/retdec/llvmir2hll/ir/function_type.h
* @brief A representation of a function type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_FUNCTION_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_FUNCTION_TYPE_H

#include <cstddef>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of a function type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class FunctionType final: public Type {
private:
	/// Container to store types of parameters.
	using Params = std::vector<ShPtr<Type>>;

public:
	/// Parameter iterator.
	using param_iterator = Params::const_iterator;

public:
	static ShPtr<FunctionType> create(ShPtr<Type> retType = VoidType::create());

	virtual ~FunctionType() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	/// @name Return Type
	/// @{
	void setRetType(ShPtr<Type> retType);
	ShPtr<Type> getRetType() const;
	/// @}

	/// @name Parameters
	bool hasParams() const;
	bool hasParam(std::size_t n) const;
	std::size_t getNumOfParams() const;
	void addParam(ShPtr<Type> paramType);
	ShPtr<Type> getParam(std::size_t n) const;

	param_iterator param_begin() const;
	param_iterator param_end() const;
	/// @}

	/// @name Variable Number of Arguments
	/// @{
	void setVarArg(bool isVarArg = true);
	bool isVarArg() const;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	FunctionType(ShPtr<Type> retType = VoidType::create());

private:
	/// Return type.
	ShPtr<Type> retType;

	/// Parameters.
	Params params;

	/// Takes the function a variable number of arguments?
	bool varArg;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
