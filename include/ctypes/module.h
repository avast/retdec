/**
* @file include/ctypes/module.h
* @brief Main class for C functions representation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef CTYPES_MODULE_H
#define CTYPES_MODULE_H

#include <memory>
#include <string>
#include <unordered_map>

namespace ctypes {

class Context;
class Function;

/**
* @brief Storage for C functions.
*/
class Module
{
	public:
		explicit Module(const std::shared_ptr<Context> &context);

		bool hasFunctionWithName(const std::string &name) const;
		std::shared_ptr<Function> getFunctionWithName(const std::string &name) const;
		void addFunction(const std::shared_ptr<Function> &function);

		std::shared_ptr<Context> getContext() const;

	private:
		/// Container for all functions and types.
		std::shared_ptr<Context> context;

		using Functions = std::unordered_map<std::string, std::shared_ptr<Function>>;
		/// Container for functions in this module.
		Functions functions;
};

} // namespace ctypes

#endif
