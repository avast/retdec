/**
 * @file include/retdec/demangler/demangler_base.h
 * @brief Base class for demanglers.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_DEMANGLE_RETDEC_H
#define RETDEC_LLVM_DEMANGLE_RETDEC_H

#include <cstdint>
#include <string>
#include <memory>
#include <map>

#include "retdec/ctypesparser/ctypes_parser.h"

namespace retdec {

namespace ctypes {
class Module;
class Function;
class Type;
}

namespace demangler {

/**
 * Abstract base class for all demanglers
 */
class Demangler
{
public:
	enum Status : uint8_t
	{
		success = 0,
		init,
		init_fail,
		memory_alloc_failure,
		invalid_mangled_name,
		unknown,
	};

public:
	explicit Demangler(const std::string &compiler);

	virtual ~Demangler() = default;

	virtual std::string demangleToString(const std::string &mangled) = 0;

	virtual std::shared_ptr<ctypes::Function> demangleFunctionToCtypes(
		const std::string &mangled,
		std::unique_ptr<ctypes::Module> &module,
		const ctypesparser::CTypesParser::TypeWidths &typeWidths,
		const ctypesparser::CTypesParser::TypeSignedness &typeSignedness,
		unsigned defaultBitWidth) = 0;

	Status status();

protected:
	std::string _compiler;
	Status _status;
};

}
}

#endif //RETDEC_LLVM_DEMANGLE_RETDEC_H
