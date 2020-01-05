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

class Module;
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
	static Function* create(Module* module, Type* retType,
		std::string name, VarVector params, VarSet localVars = VarSet(),
		Statement* body = nullptr, bool isVarArg = false);

	virtual Value* clone() override;

	virtual bool isEqualTo(Value* otherValue) const override;

	Type* getRetType() const;
	const std::string &getInitialName() const;
	const std::string &getName() const;
	const VarVector &getParams() const;
	Variable* getParam(std::size_t n) const;
	std::size_t getParamPos(Variable* param) const;
	std::size_t getNumOfParams() const;
	VarSet getLocalVars(bool includeParams = false) const;
	std::size_t getNumOfLocalVars(bool includeParams = false) const;
	bool hasLocalVar(Variable* var, bool includeParams = false) const;
	Statement* getBody() const;
	Variable* getAsVar() const;
	Type* getType() const;
	Module* getModule() const;
	AddressRange getAddressRange() const;
	Address getStartAddress() const;
	Address getEndAddress() const;

	bool isVarArg() const;
	bool isDeclaration() const;
	bool isDefinition() const;
	bool hasParam(Variable* var) const;
	bool hasParam(std::size_t n) const;

	void setRetType(Type* newRetType);
	void setName(const std::string &newName);
	void setParams(VarVector newParams);
	void setLocalVars(VarSet newLocalVars);
	void addParam(Variable* var);
	void addLocalVar(Variable* var);
	void replaceParam(Variable* oldParam, Variable* newParam);
	void replaceLocalVar(Variable* oldVar, Variable* newVar);
	void removeLocalVar(Variable* var);
	void removeParam(Variable* param);
	void setBody(Statement* newBody);
	void setVarArg(bool isVarArg = true);
	void convertToDeclaration();

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject, Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// The module to which the function belongs.
	Module* module = nullptr;

	/// Return type.
	Type* retType = nullptr;

	/// Parameters.
	VarVector params;

	/// Local variables, including parameters.
	VarSet localVars;

	/// Function body.
	Statement* body = nullptr;

	/// Variable corresponding to the function. This variable may be used when
	/// calling this function.
	Variable* funcVar = nullptr;

	// Takes the function a variable number of arguments?
	bool varArg;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	Function(Module* module, Type*, std::string name,
		VarVector params, VarSet localVars = VarSet(),
		Statement* body = nullptr, bool isVarArg = false);

	void updateUnderlyingVarType();
	void includeParamsIntoLocalVars();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
