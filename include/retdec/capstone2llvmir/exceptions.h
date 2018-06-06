/**
 * @file include/retdec/capstone2llvmir/exceptions.h
 * @brief Definitions of exceptions used in capstone2llmvir library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_EXCEPTIONS_H
#define RETDEC_CAPSTONE2LLVMIR_EXCEPTIONS_H

#include <cassert>
#include <sstream>
#include <stdexcept>

#include <capstone/capstone.h>

namespace retdec {
namespace capstone2llvmir {

/**
 * Base class for all Capstone2LllvmIr errors.
 */
class Capstone2LlvmIrBaseError : public std::exception
{
	public:
		virtual ~Capstone2LlvmIrBaseError();
};

/**
 * An exception class encapsulating Capstone errors.
 */
class CapstoneError : public Capstone2LlvmIrBaseError
{
	public:
		CapstoneError(cs_err e);
		virtual ~CapstoneError();

		std::string getMessage() const;
		virtual const char* what() const noexcept override;

	private:
		/// Capstone error.
		cs_err _csError = CS_ERR_OK;
};

/**
 * An exception class related to Capstone mode setting errors.
 */
class Capstone2LlvmIrModeError : public Capstone2LlvmIrBaseError
{
	public:
		enum class eType
		{
			UNDEF,
			/// Basic mode cannot be used with this arch.
			BASIC_MODE,
			/// Extra mode cannot be used with this arch.
			EXTRA_MODE,
			/// Translator cannnot change basic mode for this architecture.
			BASIC_MODE_CHANGE
		};

	public:
		Capstone2LlvmIrModeError(cs_arch a, cs_mode m, eType t);
		virtual ~Capstone2LlvmIrModeError();

		std::string getMessage() const;
		virtual const char* what() const noexcept override;

	private:
		cs_arch _arch = CS_ARCH_ALL;
		cs_mode _mode = CS_MODE_LITTLE_ENDIAN;
		eType _type = eType::UNDEF;
};

/**
 * A general exception class for all Capstone2LlvmIr errors.
 */
class Capstone2LlvmIrError : public Capstone2LlvmIrBaseError
{
	public:
		Capstone2LlvmIrError(const std::string& message);
		virtual ~Capstone2LlvmIrError();

		virtual const char* what() const noexcept override;

	private:
		/// Message returned by @c what() method.
		std::string _whatMessage;
};

} // namespace capstone2llvmir
} // namespace retdec

#endif
