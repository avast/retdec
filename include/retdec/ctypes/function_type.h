/**
* @file include/retdec/ctypes/function_type.h
* @brief A representation of a function type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_FUNCTION_TYPE_H
#define RETDEC_CTYPES_FUNCTION_TYPE_H

#include <memory>
#include <vector>

#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;
class Parameter;

/**
* @brief A representation of a function type.
*/
class FunctionType : public Type
{
	public:
		using Parameters = std::vector<std::shared_ptr<Type>>;
		using parameter_iterator = Parameters::iterator;
		using const_parameter_iterator = Parameters::const_iterator;

	public:
		enum class VarArgness {
			IsVarArg,
			IsNotVarArg
		};

	public:
		static std::shared_ptr<FunctionType> create(
			const std::shared_ptr<Context> &context,
			const std::shared_ptr<Type> &returnType,
			const Parameters &parameters,
			const CallConvention &callConvention = CallConvention(),
			VarArgness varArgness = VarArgness::IsNotVarArg
		);

		std::shared_ptr<Type> getReturnType() const;

		/// @name Function type parameters.
		/// @{
		parameter_iterator parameter_begin();
		const_parameter_iterator parameter_begin() const;
		parameter_iterator parameter_end();
		const_parameter_iterator parameter_end() const;

		Parameters::size_type getParameterCount() const;
		const Parameters &getParameters() const;
		std::shared_ptr<Type> getParameter(Parameters::size_type n) const;

		bool isVarArg() const;
		/// @}

		/// @name Function type call convention.
		/// @{
		void setCallConvention(const CallConvention &callConvention);
		const CallConvention &getCallConvention() const;
		/// @}

		virtual bool isFunction() const override;

		/// @name Visitor interface.
		/// @{
		virtual void accept(Visitor *v) override;
		/// @}

	private:
		FunctionType(
			const std::shared_ptr<Type> &returnType,
			const Parameters &parameters,
			const CallConvention &callConvention,
			VarArgness varArgness
		);

	private:
		std::shared_ptr<Type> returnType;
		Parameters parameters;
		CallConvention callConvention;
		VarArgness varArgness;
};

} // namespace ctypes
} // namespace retdec

#endif
