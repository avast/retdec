/**
 * @file include/retdec/llvmir-emul/exceptions.h
 * @brief Definitions of exceptions used in llvmir-emul library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_LLVMIR_EMUL_EXCEPTIONS_H
#define RETDEC_LLVMIR_EMUL_EXCEPTIONS_H

#include <cassert>
#include <sstream>
#include <stdexcept>

namespace retdec {
namespace llvmir_emul {

/**
 * Base class for all LlvmIrEmulator errors.
 */
class LlvmIrEmulatorBaseError : public std::exception
{
	public:
		virtual ~LlvmIrEmulatorBaseError()
		{
		}
};

/**
 * A general exception class for all LlvmIrEmulator errors.
 */
class LlvmIrEmulatorError : public LlvmIrEmulatorBaseError
{
	public:
		LlvmIrEmulatorError(const std::string& message) :
			_whatMessage(message)
		{
			assert(false);
		}

		virtual ~LlvmIrEmulatorError()
		{
		}

		virtual const char* what() const noexcept override
		{
			return _whatMessage.c_str();
		}

	private:
		/// Message returned by @c what() method.
		std::string _whatMessage;
};

} // llvmir_emul
} // retdec

#endif
