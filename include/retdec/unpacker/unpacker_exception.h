/**
 * @file include/retdec/unpacker/unpacker_exception.h
 * @brief Declaration of unpacker exceptions that can be subclassed in unpacker plugins.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_RETDEC_UNPACKER_EXCEPTION_H
#define RETDEC_UNPACKER_RETDEC_UNPACKER_EXCEPTION_H

#include <exception>
#include <sstream>
#include <string>

namespace retdec {
namespace unpacker {

/**
 * Base class for all unpacker exceptions. It provides the message that can be bound to the exception.
 */
class UnpackerException : public std::exception
{
public:
	/**
	 * Copy constructor.
	 *
	 * @param ex Another @ref UnpackerException object.
	 */
	UnpackerException(const UnpackerException& ex) : _msg(ex._msg)
	{
	}

	/**
	 * Override of what() method from std::exception. Provides C-string of exception message.
	 *
	 * @return C-string exception message.
	 */
	virtual const char* what() const noexcept override
	{
		return _msg.c_str();
	}

	/**
	 * Provides exception message.
	 *
	 * @return Exception message.
	 */
	const std::string& getMessage() const noexcept
	{
		return _msg;
	}

protected:
	template <typename... Args> explicit UnpackerException(const Args&... args)
	{
		std::stringstream ss;
		buildMessage(ss, args...);
		_msg = ss.str();
	}

private:
	template <typename T, typename... Args> void buildMessage(std::stringstream& ss, const T& data, const Args&... args)
	{
		ss << data;
		buildMessage(ss, args...);
	}

	void buildMessage(std::stringstream& /*ss*/)
	{
	}

	std::string _msg; ///< Exception message.
};

/**
 * Thrown in case of fatal error that should terminate the unpacking and end with error. These fatal errors
 * are e.g. malformed or corrupted data.
 */
class FatalException : public UnpackerException
{
public:
	template <typename... Args> FatalException(const Args&... args) : UnpackerException(args...) {}
};

/**
 * Thrown in case of unsupported input, whether it is file, packer version or any other.
 */
class UnsupportedInputException : public UnpackerException
{
public:
	template <typename... Args> UnsupportedInputException(const Args&... args) : UnpackerException(args...) {}
};

/**
 * Thrown in case of provided input file in unsupported format.
 *
 * This exception should report unsupported file.
 */
class UnsupportedFileException : public UnsupportedInputException
{
public:
	UnsupportedFileException() : UnsupportedInputException("Input file is in unsupported format.") {}
};

/**
 * Thrown when decompression algorithm fails to decompress the data.
 */
class DecompressionFailedException : public retdec::unpacker::FatalException
{
public:
	DecompressionFailedException() : FatalException("Failed to decompress compressed data.") {}
};

/**
 * Thrown in case of provided unsupported unpacking stub.
 *
 * This exception should report unsupported file.
 */
class UnsupportedStubException : public retdec::unpacker::UnsupportedInputException
{
public:
	UnsupportedStubException() : UnsupportedInputException("Unsupported unpacking stub detected.") {}
};

/**
 * Thrown if no entry point segment was found in the input file.
 */
class NoEntryPointException : public retdec::unpacker::FatalException
{
public:
	NoEntryPointException() : FatalException("No entry point segment found.") {}
};

} // namespace unpacker
} // namespace retdec

#endif
