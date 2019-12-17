/**
 * @file src/serdes/utils.h
 * @brief Serialization/Deserialization utils.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_UTILS_H
#define RETDEC_SERDES_UTILS_H

#include <json/json.h>

namespace retdec {
namespace serdes {

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

//
//=============================================================================
// Safe (check type and throw exception) JSON value loading methods
//=============================================================================
//

void checkJsonValueIsObject(const Json::Value& val, const std::string& name);

Json::Value::Int safeGetInt(
		const Json::Value& val,
		const std::string& name = "",
		Json::Value::Int defaultValue = 0);

Json::Value::UInt safeGetUint(
		const Json::Value& val,
		const std::string& name = "",
		Json::Value::UInt defaultValue = 0);

Json::Value::UInt64 safeGetUint64(
		const Json::Value& val,
		const std::string& name = "",
		Json::Value::UInt64 defaultValue = 0);

double safeGetDouble(
		const Json::Value& val,
		const std::string& name = "",
		double defaultValue = 0.0);

std::string safeGetString(
		const Json::Value& val,
		const std::string& name = "",
		const std::string& defaultValue = "");

bool safeGetBool(
		const Json::Value& val,
		const std::string& name = "",
		bool defaultValue = false);

} // namespace serdes
} // namespace retdec

#endif
