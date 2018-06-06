/**
 * @file src/capstone2llvmir/exceptions.cpp
 * @brief Definitions of exceptions used in capstone2llmvir library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/capstone2llvmir/exceptions.h"
#include "capstone2llvmir/capstone_utils.h"

namespace retdec {
namespace capstone2llvmir {

//
//==============================================================================
// Capstone2LlvmIrBaseError
//==============================================================================
//

Capstone2LlvmIrBaseError::~Capstone2LlvmIrBaseError()
{

}

//
//==============================================================================
// CapstoneError
//==============================================================================
//

CapstoneError::CapstoneError(cs_err e) :
		_csError(e)
{

}

CapstoneError::~CapstoneError()
{

}

std::string CapstoneError::getMessage() const
{
	return cs_strerror(_csError);
}

const char* CapstoneError::what() const noexcept
{
	return getMessage().c_str();
}

//
//==============================================================================
// Capstone2LlvmIrModeError
//==============================================================================
//

Capstone2LlvmIrModeError::Capstone2LlvmIrModeError(
		cs_arch a,
		cs_mode m,
		eType t)
	:
		_arch(a),
		_mode(m),
		_type(t)
{

}

Capstone2LlvmIrModeError::~Capstone2LlvmIrModeError()
{

}

std::string Capstone2LlvmIrModeError::getMessage() const
{
	std::string ms = capstoneModeToString(_mode) + " ("
			+ std::to_string(static_cast<unsigned>(_mode)) + ")";
	std::string as = capstoneArchToString(_arch) + " ("
			+ std::to_string(static_cast<unsigned>(_arch)) + ")";

	std::string ret;
	switch (_type)
	{
		case eType::BASIC_MODE:
		{
			ret = "Basic mode: " + ms + " cannot be used with "
					"architecture: " + as;
			break;
		}
		case eType::EXTRA_MODE:
		{
			ret = "Extra mode: " + ms + " cannot be used with "
					"architecture: " + as;
			break;
		}
		case eType::BASIC_MODE_CHANGE:
		{
			ret = "Translator cannot change basic mode to: " + ms +
					" for architecture: " + as;
			break;
		}
		case eType::UNDEF:
		default:
		{
			ret = "Undefined type -- should not happen.";
			break;
		}

	}
	return ret;
}

const char* Capstone2LlvmIrModeError::what() const noexcept
{
	return getMessage().c_str();
}

//
//==============================================================================
// Capstone2LlvmIrError
//==============================================================================
//

Capstone2LlvmIrError::Capstone2LlvmIrError(const std::string& message) :
		_whatMessage(message)
{

}

Capstone2LlvmIrError::~Capstone2LlvmIrError()
{
}

const char* Capstone2LlvmIrError::what() const noexcept
{
	return _whatMessage.c_str();
}

} // namespace capstone2llvmir
} // namespace retdec
