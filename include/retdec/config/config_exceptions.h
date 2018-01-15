/**
 * @file include/retdec/config/config_exceptions.h
 * @brief Definitions of config exceptions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_CONFIG_EXCEPTIONS_H
#define RETDEC_CONFIG_CONFIG_EXCEPTIONS_H

#include <exception>
#include <string>

namespace retdec {
namespace config {

/**
 * Base class for Config exceptions which can be thrown to the outside world (library users).
 */
class Exception : public std::exception
{
};

/**
 * Config exception which can be thrown to the outside world (library users).
 * It represents an error during JSON parsing.
 * It contains an error message and line and column in JSON where error occurred.
 */
class ParseException : public Exception
{
	public:
		ParseException(const std::string& message, std::size_t line, std::size_t column) :
			_message(message),
			_line(line),
			_column(column),
			_whatMessage(_message +
					" @ line = " + std::to_string(_line) +
					", column = " + std::to_string(_column))
		{
		}

		std::string getMessage() const
		{
			return _message;
		}

		std::size_t getLine() const
		{
			return _line;
		}

		std::size_t getColumn() const
		{
			return _column;
		}

		/**
		 * @return Single throw message constructed from error message
		 *         and error line and column in JSON.
		 */
		virtual const char* what() const noexcept override
		{
			return _whatMessage.c_str();
		}

	private:
		/// Error message.
		std::string _message;
		/// Line in JSON where error occurred.
		std::size_t _line = 0;
		/// Column in JSON where error occurred.
		std::size_t _column = 0;
		/// Message returned by @c what() method.
		std::string _whatMessage;
};

/**
 * Config exception which can be thrown to the outside world (library users).
 * It is thrown when provided input file can not be opened.
 */
class FileNotFoundException : public Exception
{
	public:
		FileNotFoundException(const std::string& message) :
			_whatMessage(message)
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

/**
 * Config internal exception used only inside the library.
 * It is always caught by the library and therefore is never propagated to
 * the outside world (library users).
 */
class InternalException : public std::exception
{
	public:
		InternalException(const std::string& message, std::size_t position) :
			_message(message),
			_position(position)
		{
			_whatMessage = _message + " @ position = " + std::to_string(_position);
		}

		std::string getMessage() const
		{
			return _message;
		}

		std::size_t getPosition() const
		{
			return _position;
		}

		virtual const char* what() const noexcept override
		{
			return _whatMessage.c_str();
		}

	private:
		/// Error message.
		std::string _message;
		/// Position (byte distance from start) in JSON where error occurred.
		std::size_t _position = 0;
		/// Message returned by @c what() method.
		std::string _whatMessage;
};

} // namespace config
} // namespace retdec

#endif
