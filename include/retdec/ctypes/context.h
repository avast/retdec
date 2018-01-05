/**
* @file include/retdec/ctypes/context.h
* @brief Container for all C functions and types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_CONTEXT_H
#define RETDEC_CTYPES_CONTEXT_H

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/function_type.h"

namespace retdec {
namespace ctypes {

class Annotation;
class Function;
class PointerType;
class Type;

/**
* @brief Container for all C functions and types.
*/
class Context
{
	public:
		/// @name Access to functions.
		/// @{
		bool hasFunctionWithName(const std::string &name) const;
		std::shared_ptr<Function> getFunctionWithName(const std::string &name) const;
		void addFunction(const std::shared_ptr<Function> &function);
		/// @}

		/// @name Access to function types.
		/// @{
		bool hasFunctionType(const std::shared_ptr<Type> &returnType,
			const FunctionType::Parameters &parameters) const;
		std::shared_ptr<FunctionType> getFunctionType(const std::shared_ptr<Type> &returnType,
			const FunctionType::Parameters &parameters) const;
		void addFunctionType(const std::shared_ptr<FunctionType> &functionType);
		/// @}

		/// @name Access to named types.
		/// @{
		bool hasNamedType(const std::string &name) const;
		std::shared_ptr<Type> getNamedType(const std::string &name)const;
		void addNamedType(const std::shared_ptr<Type> &type);
		/// @}

		/// @name Access to pointer types.
		/// @{
		bool hasPointerType(const std::shared_ptr<Type> &pointedType) const;
		std::shared_ptr<PointerType> getPointerType(
			const std::shared_ptr<Type> &pointedType)const;
		void addPointerType(const std::shared_ptr<PointerType> &pointerType);
		/// @}

		/// @name Access to array types.
		/// @{
		bool hasArrayType(const std::shared_ptr<Type> &elementType,
			const ArrayType::Dimensions &dimensions) const;
		std::shared_ptr<ArrayType> getArrayType(const std::shared_ptr<Type> &elementType,
			const ArrayType::Dimensions &dimensions) const;
		void addArrayType(const std::shared_ptr<ArrayType> &arrayType);
		/// @}

		/// @name Access to annotations.
		/// @{
		bool hasAnnotation(const std::string &name) const;
		std::shared_ptr<Annotation> getAnnotation(const std::string &name)const;
		void addAnnotation(const std::shared_ptr<Annotation> &annot);
		/// @}

	private:
		using Functions = std::unordered_map<std::string, std::shared_ptr<Function>>;
		/// Stored functions.
		Functions functions;

		using FunctionTypes = std::map<
			std::pair<std::shared_ptr<Type>, FunctionType::Parameters>,
			std::shared_ptr<FunctionType>
		>;
		/// Stored function types, key is return type and parameters' types.
		FunctionTypes functionTypes;

		using NamedTypes = std::unordered_map<std::string, std::shared_ptr<Type>>;
		/// Stored types that can be identified by name.
		NamedTypes namedTypes;

		using PointerTypes = std::unordered_map<std::shared_ptr<Type>,
			std::shared_ptr<PointerType>>;
		/// Stored pointer types, key is type that they point to.
		PointerTypes pointerTypes;

		using ArrayTypes = std::map<
			std::pair<std::shared_ptr<Type>, ArrayType::Dimensions>,
			std::shared_ptr<ArrayType>
		>;
		/// Stored array types, key is element type and dimensions
		ArrayTypes arrayTypes;

		using Annotations = std::unordered_map<std::string, std::shared_ptr<Annotation>>;
		/// Stored annotations.
		Annotations annotations;
};

} // namespace ctypes
} // namespace retdec

#endif
