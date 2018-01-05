/**
* @file include/retdec/ctypes/function.h
* @brief A representation of a C functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_FUNCTION_H
#define RETDEC_CTYPES_FUNCTION_H

#include <memory>
#include <string>
#include <vector>

#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/function_declaration.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/header_file.h"

namespace retdec {
namespace ctypes {

class Context;
class Parameter;
class Type;

/**
* @brief A representation of a C function.
*/
class Function
{
	public:
		using Parameters = std::vector<Parameter>;
		using VarArgness = FunctionType::VarArgness;
		using parameter_iterator = Parameters::iterator;
		using const_parameter_iterator = Parameters::const_iterator;

	public:
		static std::shared_ptr<Function> create(
			const std::shared_ptr<Context> &context,
			const std::string &name,
			const std::shared_ptr<Type> &returnType,
			const Parameters &parameters,
			const CallConvention &callConvention = CallConvention(),
			VarArgness varArgness = VarArgness::IsNotVarArg
		);

		const std::string &getName() const;
		std::shared_ptr<FunctionType> getType() const;
		std::shared_ptr<Type> getReturnType() const;

		/// @name Function parameters.
		/// @{
		parameter_iterator parameter_begin();
		const_parameter_iterator parameter_begin() const;
		parameter_iterator parameter_end();
		const_parameter_iterator parameter_end() const;

		Parameters::size_type getParameterCount() const;
		const Parameter &getParameter(Parameters::size_type n) const;
		const std::string &getParameterName(Parameters::size_type n) const;
		std::shared_ptr<Type> getParameterType(Parameters::size_type n) const;

		bool isVarArg() const;
		/// @}

		/// @name Function call convention.
		/// @{
		void setCallConvention(const CallConvention &callConvention);
		const CallConvention &getCallConvention() const;
		/// @}

		/// @name Function declaration.
		/// @{
		void setDeclaration(const FunctionDeclaration &declaration);
		FunctionDeclaration getDeclaration() const;
		/// @}

		/// @name Function header file.
		/// @{
		void setHeaderFile(const HeaderFile &headerFile);
		HeaderFile getHeaderFile() const;
		/// @}

	private:
		// Instances are created by static method create().
		Function(
			const std::string &name,
			const std::shared_ptr<FunctionType> &functionType,
			const Parameters &parameters
		);

		static std::shared_ptr<FunctionType> createFunctionType(
			const std::shared_ptr<Context> &context,
			const std::shared_ptr<Type> &returnType,
			const Parameters &parameters,
			const CallConvention &callConvention,
			VarArgness varArgness
		);

	private:
		std::string name;
		std::shared_ptr<FunctionType> functionType;
		Parameters parameters;
		FunctionDeclaration declaration;
		HeaderFile headerFile;
};

} // namespace ctypes
} // namespace retdec

#endif
