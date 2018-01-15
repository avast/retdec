/**
* @file include/retdec/llvmir2hll/ir/function.h
* @brief A representation of a function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_FUNCTION_H
#define RETDEC_LLVMIR2HLL_IR_FUNCTION_H

#include <cstddef>
#include <string>

#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class Statement;
class Type;
class Variable;
class Visitor;

/**
* @brief A representation of a function.
*
* Use either create() or FunctionBuilder to create instances. Instances of this
* class have reference object semantics. This class is not meant to be
* subclassed.
*/
class Function final: public Value {
public:
	static ShPtr<Function> create(ShPtr<Type> retType, std::string name,
		VarVector params, VarSet localVars = VarSet(),
		ShPtr<Statement> body = nullptr, bool isVarArg = false);

	virtual ~Function() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	ShPtr<Type> getRetType() const;
	const std::string &getInitialName() const;
	const std::string &getName() const;
	const VarVector &getParams() const;
	ShPtr<Variable> getParam(std::size_t n) const;
	std::size_t getParamPos(ShPtr<Variable> param) const;
	std::size_t getNumOfParams() const;
	VarSet getLocalVars(bool includeParams = false) const;
	std::size_t getNumOfLocalVars(bool includeParams = false) const;
	bool hasLocalVar(ShPtr<Variable> var, bool includeParams = false) const;
	ShPtr<Statement> getBody() const;
	ShPtr<Variable> getAsVar() const;
	ShPtr<Type> getType() const;

	bool isVarArg() const;
	bool isDeclaration() const;
	bool isDefinition() const;
	bool hasParam(ShPtr<Variable> var) const;
	bool hasParam(std::size_t n) const;

	void setRetType(ShPtr<Type> newRetType);
	void setName(const std::string &newName);
	void setParams(VarVector newParams);
	void setLocalVars(VarSet newLocalVars);
	void addParam(ShPtr<Variable> var);
	void addLocalVar(ShPtr<Variable> var);
	void replaceParam(ShPtr<Variable> oldParam, ShPtr<Variable> newParam);
	void replaceLocalVar(ShPtr<Variable> oldVar, ShPtr<Variable> newVar);
	void removeLocalVar(ShPtr<Variable> var);
	void removeParam(ShPtr<Variable> param);
	void setBody(ShPtr<Statement> newBody);
	void setVarArg(bool isVarArg = true);
	void convertToDeclaration();

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject, ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Return type.
	ShPtr<Type> retType;

	/// Parameters.
	VarVector params;

	/// Local variables, including parameters.
	VarSet localVars;

	/// Function body.
	ShPtr<Statement> body;

	/// Variable corresponding to the function. This variable may be used when
	/// calling this function.
	ShPtr<Variable> funcVar;

	// Takes the function a variable number of arguments?
	bool varArg;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	Function(ShPtr<Type>, std::string name, VarVector params,
		VarSet localVars = VarSet(), ShPtr<Statement> body = nullptr,
		bool isVarArg = false);

	void updateUnderlyingVarType();
	void includeParamsIntoLocalVars();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
