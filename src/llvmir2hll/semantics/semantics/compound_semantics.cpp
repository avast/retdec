/**
* @file src/llvmir2hll/semantics/semantics/compound_semantics.cpp
* @brief Implementation of CompoundSemantics.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/semantics/semantics/compound_semantics.h"
#include "retdec/llvmir2hll/semantics/semantics_factory.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Tries to get an answer by asking all the semantics in the given list.
*
* @param[in] semanticsList List of semantics.
* @param[in] memFunc Pointer to a member function to be called on every
*                    semantics.
*
* @tparam ReturnType Type to be returned from the function (@c Maybe<ReturnType>).
* @tparam SemanticsListType Type of @a semanticsList.
* @tparam MemFuncType Type of @a memFunc.
*
* Goes through all the semantics in @a semanticsList, calls @a memFunc on
* each of them, and if an answer is obtained, it is returned. Otherwise, an "I
* don't know." answer is returned.
*/
template<typename ReturnType, typename SemanticsListType,
	typename MemFuncType>
Maybe<ReturnType> getAnswer(const SemanticsListType &semanticsList,
		MemFuncType memFunc) {
	// Go through all the semantics in the list and try to get an answer.
	for (const auto &semantics : semanticsList) {
		// The following code utilizes pointers to member functions. Since
		// ShPtr does not provide ->*, the syntax below is rather obscure,
		// although working.
		Maybe<ReturnType> answer(((*semantics).*memFunc)());
		if (answer) {
			return answer;
		}
	}

	// Don't know.
	return Nothing<ReturnType>();
}

/// Overloaded version of getAnswer<> for functions with one parameter.
/// See it and its implementation for more details.
template<typename ReturnType, typename SemanticsListType,
	typename MemFuncType, typename ParamType>
Maybe<ReturnType> getAnswer(const SemanticsListType &semanticsList,
		MemFuncType memFunc, const ParamType &param) {
	for (const auto &semantics : semanticsList) {
		Maybe<ReturnType> answer(((*semantics).*memFunc)(param));
		if (answer) {
			return answer;
		}
	}
	return Nothing<ReturnType>();
}

/// Overloaded version of getAnswer<> for functions with two parameters.
/// See it and its implementation for more details.
template<typename ReturnType, typename SemanticsListType,
	typename MemFuncType, typename Param1Type, typename Param2Type>
Maybe<ReturnType> getAnswer(const SemanticsListType &semanticsList,
		MemFuncType memFunc, const Param1Type &param1, const Param2Type &param2) {
	for (const auto &semantics : semanticsList) {
		Maybe<ReturnType> answer(((*semantics).*memFunc)(param1, param2));
		if (answer) {
			return answer;
		}
	}
	return Nothing<ReturnType>();
}

} // anonymous namespace

/**
* @brief Constructs the semantics.
*/
CompoundSemantics::CompoundSemantics(): providedSemantics() {}

/**
* @brief Creates a new semantics.
*/
ShPtr<CompoundSemantics> CompoundSemantics::create() {
	return ShPtr<CompoundSemantics>(new CompoundSemantics());
}

/**
* @brief Inserts the given semantics to the beginning of the list of compound
*        semantics that this instance provides.
*
* When the functions from the Semantics' interface are called, the newly added
* semantics is asked first.
*/
void CompoundSemantics::prependSemantics(ShPtr<Semantics> semantics) {
	providedSemantics.push_front(semantics);
}

/**
* @brief Inserts the given semantics to the end of the list of compound
*        semantics that this instance provides.
*
* When the functions from the Semantics' interface are called, the newly added
* semantics is asked last.
*/
void CompoundSemantics::appendSemantics(ShPtr<Semantics> semantics) {
	providedSemantics.push_back(semantics);
}

Maybe<std::string> CompoundSemantics::getMainFuncName() const {
	return getAnswer<std::string>(providedSemantics,
		&Semantics::getMainFuncName);
}

Maybe<std::string> CompoundSemantics::getCHeaderFileForFunc(
		const std::string &funcName) const {
	return getAnswer<std::string>(providedSemantics,
		&Semantics::getCHeaderFileForFunc, funcName);
}

Maybe<bool> CompoundSemantics::funcNeverReturns(
		const std::string &funcName) const {
	return getAnswer<bool>(providedSemantics,
		&Semantics::funcNeverReturns, funcName);
}

Maybe<std::string> CompoundSemantics::getNameOfVarStoringResult(
		const std::string &funcName) const {
	return getAnswer<std::string>(providedSemantics,
		&Semantics::getNameOfVarStoringResult, funcName);
}

Maybe<std::string> CompoundSemantics::getNameOfParam(
		const std::string &funcName, unsigned paramPos) const {
	return getAnswer<std::string>(providedSemantics,
		&Semantics::getNameOfParam, funcName, paramPos);
}

Maybe<IntStringMap> CompoundSemantics::getSymbolicNamesForParam(
		const std::string &funcName, unsigned paramPos) const {
	return getAnswer<IntStringMap>(providedSemantics,
		&Semantics::getSymbolicNamesForParam, funcName, paramPos);
}

} // namespace llvmir2hll
} // namespace retdec
