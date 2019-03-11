/**
 * @file include/retdec/demangler/demangler_base.h
 * @brief Demangler library.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVM_DEMANGLE_RETDEC_H
#define RETDEC_LLVM_DEMANGLE_RETDEC_H

#include <string>
#include <memory>

namespace retdec {

namespace ctypes {
	class Module;
}

namespace demangler {

/**
 * Abstract base class for all demanglers
 */
class Demangler
{
	public:
		enum Status: u_char
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

		virtual void demangleToModule(
			const std::string &mangled,
			std::unique_ptr<retdec::ctypes::Module> &module) {};

		Status status();

	protected:
		std::string _compiler;
		Status _status;
};

}
}

#endif //RETDEC_LLVM_DEMANGLE_RETDEC_H
