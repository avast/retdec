/**
* @file src/llvmir2hll/ir/function.cpp
* @brief The implementation of the representation of a function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/container.h"

using retdec::utils::getNthItem;
using retdec::utils::hasItem;
using retdec::utils::removeItem;
using retdec::utils::setDifference;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new function.
*
* See create() for more information.
*/
Function::Function(ShPtr<Type> retType, std::string name, VarVector params,
		VarSet localVars, ShPtr<Statement> body, bool isVarArg):
			retType(retType), params(params), localVars(localVars),
			body(body), funcVar(), varArg(isVarArg) {
	includeParamsIntoLocalVars();

	// The following call cannot be moved into the initialization part because
	// at that point, the object corresponding to the constructed function is
	// not created yet.
	funcVar = Variable::create(name, getType());
}

/**
* @brief Destructs the function.
*/
Function::~Function() {}

bool Function::isEqualTo(ShPtr<Value> otherValue) const {
	// The types of compared instances have to match.
	ShPtr<Function> otherFunction = cast<Function>(otherValue);
	if (!otherFunction) {
		return false;
	}

	// The return types have to match.
	if (!getRetType()->isEqualTo(otherFunction->getRetType())) {
		return false;
	}

	// The names have to match.
	if (getName() != otherFunction->getName()) {
		return false;
	}

	// The possibilities of a variable number of arguments have to match.
	if (isVarArg() != otherFunction->isVarArg()) {
		return false;
	}

	// The number of parameters have to match.
	if (getNumOfParams() != otherFunction->getNumOfParams()) {
		return false;
	}

	// All parameters have to match.
	for (VarVector::const_iterator i = params.begin(), e = params.end(),
			j = otherFunction->params.begin(); i != e; ++i, ++j) {
		if (!(*i)->isEqualTo(*j)) {
			return false;
		}
	}

	// All local variables have to match.
	for (auto i = localVars.begin(), e = localVars.end(),
			j = otherFunction->localVars.begin(); i != e; ++i, ++j) {
		if (!(*i)->isEqualTo(*j)) {
			return false;
		}
	}

	// The bodies have to match.
	return body->isEqualTo(otherFunction->body);
}

/**
* @brief Returns function type.
*/
ShPtr<Type> Function::getRetType() const {
	return retType;
}

/**
* @brief Returns the initial name of the function.
*
* This is the name that was assigned to the function before any renaming.
*/
const std::string &Function::getInitialName() const {
	return funcVar->getInitialName();
}

/**
* @brief Returns function name.
*/
const std::string &Function::getName() const {
	return funcVar->getName();
}

/**
* @brief Returns function parameters.
*/
const VarVector &Function::getParams() const {
	return params;
}

/**
* @brief Returns the n-th parameter.
*
* The parameters are numbered in the following way:
* @code
* func(1, 2, 3, 4, ...)
* @endcode
*
* @par Preconditions
*  - <tt>0 < n <= NUM_OF_PARAMS</tt>, where @c NUM_OF_PARAMS is the number of
*    parameters that the function has
*/
ShPtr<Variable> Function::getParam(std::size_t n) const {
	PRECONDITION(n > 0, "n `" << n << "` is not > 0");
	PRECONDITION(n <= getNumOfParams(), "n `" << n << "`" << " is greater "
		"than the number of parameters (`" << getNumOfParams() << "`)");

	return getNthItem(params, n);
}

/**
* @brief Returns the position of the given parameter.
*
* The parameter numbering is described in getParam().
*
* @par Preconditions
*  - @a param is a parameter of the function
*/
std::size_t Function::getParamPos(ShPtr<Variable> param) const {
	std::size_t pos = 1;
	for (auto i = params.begin(), e = params.end(); i != e; ++i, ++pos) {
		if (*i == param) {
			return pos;
		}
	}
	PRECONDITION_FAILED("parameter " << param << " was not found");
	return 0;
}

/**
* @brief Returns the number of parameters.
*/
std::size_t Function::getNumOfParams() const {
	return params.size();
}

/**
* @brief Returns local variables of the function.
*
* @param[in] includeParams If @c true, function parameters will be included.
*/
VarSet Function::getLocalVars(bool includeParams) const {
	if (includeParams) {
		return localVars;
	}

	// Discard parameters.
	VarSet paramsSet(params.begin(), params.end());
	return setDifference(localVars, paramsSet);
}

/**
* @brief Returns the number of local variables.
*
* @param[in] includeParams If @c true, function parameters will be included.
*/
std::size_t Function::getNumOfLocalVars(bool includeParams) const {
	if (includeParams) {
		return localVars.size();
	}
	return localVars.size() - params.size();
}

/**
* @brief Returns @c true if @a var is a local variable of the function, @c
* false otherwise.
*
* @param[in] var Variable to be checked.
* @param[in] includeParams If @c true, function parameters will be also
*                          considered as local variables.
*/
bool Function::hasLocalVar(ShPtr<Variable> var, bool includeParams) const {
	if (includeParams) {
		return hasItem(localVars, var);
	}
	return hasItem(localVars, var) && !hasParam(var);
}

/**
* @brief Returns function body.
*/
ShPtr<Statement> Function::getBody() const {
	return body;
}

/**
* @brief Returns a variable corresponding the function.
*
* This variable may be used when calling this function.
*/
ShPtr<Variable> Function::getAsVar() const {
	return funcVar;
}

/**
* @brief Returns the type of the function.
*
* Currently, it returns the return type of the function, not the complete type
* of the function. This simplifies the fixing of signed/unsigned types.
*/
ShPtr<Type> Function::getType() const {
	return retType;
}

/**
* @brief Returns @c true if the function takes a variable number of arguments,
*        @c false otherwise.
*/
bool Function::isVarArg() const {
	return varArg;
}

/**
* @brief Returns @c true if the function is just a declaration,
*        @c false otherwise.
*/
bool Function::isDeclaration() const {
	return !body;
}

/**
* @brief Returns @c true if the function is a definition, @c false otherwise.
*/
bool Function::isDefinition() const {
	return body != nullptr;
}

/**
* @brief Returns @c true if @a var is a parameter of the function, @c false
*        otherwise.
*/
bool Function::hasParam(ShPtr<Variable> var) const {
	return hasItem(params, var);
}

/**
* @brief Returns @c true if the function has an n-th parameter, @c false
*        otherwise.
*
* The parameters are numbered in the following way:
* @code
* func(1, 2, 3, 4, ...)
* @endcode
*/
bool Function::hasParam(std::size_t n) const {
	return n >= 1 && n <= getNumOfParams();
}

/**
* @brief Sets a new return type;
*/
void Function::setRetType(ShPtr<Type> newRetType) {
	retType = newRetType;

	updateUnderlyingVarType();
}

/**
* @brief Sets a new name.
*/
void Function::setName(const std::string &newName) {
	funcVar->setName(newName);
}

/**
* @brief Sets a new parameter list.
*/
void Function::setParams(VarVector newParams) {
	for (auto &param : params) {
		param->removeObserver(shared_from_this());
	}
	for (auto &param : newParams) {
		param->addObserver(shared_from_this());
	}
	params = newParams;

	includeParamsIntoLocalVars();
	updateUnderlyingVarType();
}

/**
* @brief Sets a new set of local variables.
*/
void Function::setLocalVars(VarSet newLocalVars) {
	localVars = newLocalVars;
}

/**
* @brief Adds a new parameter to the function.
*
* @par Preconditions
*  - @a var is non-null
*/
void Function::addParam(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	params.push_back(var);
	var->addObserver(shared_from_this());

	includeParamsIntoLocalVars();
	updateUnderlyingVarType();
}

/**
* @brief Adds a new local variable to the function.
*
* If @a var is already a local variable in the function, this function does
* nothing.
*
* To add a local variable including a VarDefStmt, use addLocalVar() from
* Support/Utils.
*
* @par Preconditions
*  - @a var is non-null
*/
void Function::addLocalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	localVars.insert(var);
}

/**
* @brief Replaces @a oldParam with @a newParam.
*
* If @a oldParam does not correspond to any parameter, this function does
* nothing.
*/
void Function::replaceParam(ShPtr<Variable> oldParam, ShPtr<Variable> newParam) {
	// Does oldParam correspond to a parameter?
	auto oldParamIter = std::find(params.begin(), params.end(), oldParam);
	if (oldParamIter != params.end()) {
		// It does, so replace it.
		oldParam->removeObserver(shared_from_this());
		newParam->addObserver(shared_from_this());
		*oldParamIter = newParam;
	}

	updateUnderlyingVarType();
}

/**
* @brief Replaces @a oldVar with @a newVar.
*
* If @a oldVar does not correspond to any local variable, this function does
* nothing.
*
* @par Preconditions
*  - @a oldVar and @a newVar are non-null
*/
void Function::replaceLocalVar(ShPtr<Variable> oldVar, ShPtr<Variable> newVar) {
	PRECONDITION_NON_NULL(oldVar);
	PRECONDITION_NON_NULL(newVar);

	// Does oldVar correspond to a local variable?
	auto oldVarIter = localVars.find(oldVar);
	if (oldVarIter != localVars.end()) {
		// It does, so replace it.
		localVars.erase(oldVar);
		localVars.insert(newVar);
	}

	updateUnderlyingVarType();
}

/**
* @brief Removes the given variable from the set of local variables.
*
* This function does nothing if @a var is either a parameter of the function or
* the function does not have any local variable @a var.
*
* @par Preconditions
*  - @a var is non-null
*/
void Function::removeLocalVar(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	if (!hasParam(var)) {
		localVars.erase(var);
	}
}

/**
* @brief Removes the given parameter.
*
* If @a param is not a parameter of this function, this function does nothing.
*
* @par Preconditions
*  - @a param is non-null
*/
void Function::removeParam(ShPtr<Variable> param) {
	PRECONDITION_NON_NULL(param);

	removeItem(params, param);
	localVars.erase(param);
	updateUnderlyingVarType();
}

/**
* @brief Sets a new body.
*
* If @a newBody is the null pointer, this function becomes a declaration.
* Conversely, if @a newBody is non-null, this function becomes a definition.
*/
void Function::setBody(ShPtr<Statement> newBody) {
	if (body) {
		body->removeObserver(shared_from_this());
	}
	if (newBody) {
		newBody->addObserver(shared_from_this());
	}
	body = newBody;
}

/**
* @brief Sets the function's status concerning the number of arguments it takes.
*
* If @a isVarArg is @c true, it marks the function as with a variable number of
* arguments. Otherwise, it marks it as a function with a fixed number of
* arguments.
*/
void Function::setVarArg(bool isVarArg) {
	varArg = isVarArg;

	updateUnderlyingVarType();
}

/**
* @brief Makes the function to be a declaration.
*
* If the function is already a declaration, nothing happens. Once you make a
* function a declaration, the only way of making it a definition again is to
* set its body to a non-null pointer by setBody().
*
* When the function is converted from a definition into a declaration,
* observers are notified.
*/
void Function::convertToDeclaration() {
	if (!isDefinition()) {
		return;
	}

	setBody(ShPtr<Statement>());
	notifyObservers();
}

ShPtr<Value> Function::clone() {
	// Functions are not cloned (see the description of Value::clone()).
	return shared_from_this();
}

/**
* @brief Constructs a new function.
*
* @param[in] retType Function return type.
* @param[in] name Function name.
* @param[in] params Parameter list.
* @param[in] localVars Local variables (without parameters).
* @param[in] body Function body.
* @param[in] isVarArg @c true if the function takes a variable number of
*            arguments, @c false otherwise.
*
* If @a body is the null pointer, then the function is a declaration.
* Otherwise, it is a definition.
*
* To build functions in a simpler way, use FunctionBuilder.
*/
ShPtr<Function> Function::create(ShPtr<Type> retType, std::string name,
		VarVector params, VarSet localVars, ShPtr<Statement> body, bool isVarArg) {
	ShPtr<Function> func(new Function(retType, name, params, localVars, body,
		isVarArg));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	for (auto &param : params) {
		param->addObserver(func);
	}
	if (body) {
		body->addObserver(func);
	}

	return func;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is one of the
* parameters of this function, this function replaces it with @a arg. If @a
* subject is the null pointer and corresponds to a part of the function, this
* part of the function is removed.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of this function
*
* @par Preconditions
*  - @a subject is non-null
*
* @see Subject::update()
*/
void Function::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);

	//
	// Check body.
	//
	if (subject == body) {
		if (ShPtr<Statement> newBody = cast<Statement>(arg)) {
			setBody(newBody);
		} else {
			ASSERT_MSG(!arg,
				"arg was not expected here (we are removing a statement)");

			// We should remove the statement. However, if this is the only
			// statement in the function, just replace it with an empty
			// statement so the function doesn't become a declaration.
			if (body->hasSuccessor()) {
				setBody(body->getSuccessor());
			} else {
				setBody(EmptyStmt::create());
			}
		}
		return;
	}

	//
	// Check arguments and local variables.
	//
	ShPtr<Variable> oldVar(cast<Variable>(subject));
	ShPtr<Variable> newVar(cast<Variable>(arg));
	if (!oldVar || (!newVar && arg)) {
		return;
	}

	// The replaceParam(), removeParam(), and removeLocalVar() calls are safe;
	// if the variable doesn't correspond to a parameter or a local variable,
	// they do nothing.

	// Try arguments.
	if (newVar) {
		replaceParam(oldVar, newVar);
	} else {
		removeParam(oldVar);
	}

	// Try local variables.
	if (newVar) {
		replaceLocalVar(oldVar, newVar);
	} else {
		removeLocalVar(oldVar);
	}

	updateUnderlyingVarType();
}

void Function::accept(Visitor *v) {
	v->visit(ucast<Function>(shared_from_this()));
}

/**
* @brief Updates the type of the underlying variable.
*
* This function has to be called whenever the signature of the function is
* changed (e.g. its return type or parameters).
*/
void Function::updateUnderlyingVarType() {
	funcVar->setType(getType());
}

/**
* @brief Includes all parameters into the set of local variables.
*
* Parameters are local variables, too.
*/
void Function::includeParamsIntoLocalVars() {
	localVars.insert(params.begin(), params.end());
}

} // namespace llvmir2hll
} // namespace retdec
