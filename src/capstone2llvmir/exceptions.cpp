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
// CapstoneError
//==============================================================================
//

CapstoneError::CapstoneError(cs_err e): _csError(e) {}

std::string CapstoneError::getMessage() const
{
	return cs_strerror(_csError);
}

const char* CapstoneError::what() const noexcept
{
	return cs_strerror(_csError);
}

//
//==============================================================================
// ModeSettingError
//==============================================================================
//

ModeSettingError::ModeSettingError(cs_arch a, cs_mode m, eType t): _arch(a), _mode(m), _type(t)
{
	_getMessage();
}

std::string ModeSettingError::getMessage() const
{
	return _whatMessage;
}

void ModeSettingError::_getMessage() noexcept
{
	std::string ms = capstoneModeToString(_mode) + " (" + std::to_string(static_cast<unsigned>(_mode)) + ")";
	std::string as = capstoneArchToString(_arch) + " (" + std::to_string(static_cast<unsigned>(_arch)) + ")";

	std::string ret;
	switch (_type)
	{
	case eType::BASIC_MODE: {
		ret = "Basic mode: " + ms
			+ " cannot be used with "
			  "architecture: "
			+ as;
		break;
	}
	case eType::EXTRA_MODE: {
		ret = "Extra mode: " + ms
			+ " cannot be used with "
			  "architecture: "
			+ as;
		break;
	}
	case eType::BASIC_MODE_CHANGE: {
		ret = "Translator cannot change basic mode to: " + ms + " for architecture: " + as;
		break;
	}
	case eType::UNDEF:
	default: {
		ret = "Undefined type -- should not happen.";
		break;
	}
	}
	_whatMessage = ret;
}

const char* ModeSettingError::what() const noexcept
{
	return _whatMessage.c_str();
}

//
//==============================================================================
// UnexpectedOperandsError
//==============================================================================
//

UnexpectedOperandsError::UnexpectedOperandsError(cs_insn* i, const std::string& comment): _insn(i), _comment(comment)
{
	_getMessage();
}

void UnexpectedOperandsError::_getMessage() noexcept
{
	std::stringstream ret;

	ret << "Unexpected operand @ " << std::hex << _insn->address << " : " << _insn->mnemonic << " " << _insn->op_str;
	if (!_comment.empty())
	{
		ret << "\n"
			<< "Comment: " << _comment;
	}

	_whatMessage = ret.str();
}

const char* UnexpectedOperandsError::what() const noexcept
{
	return _whatMessage.c_str();
}

//
//==============================================================================
// UnhandledInstructionError
//==============================================================================
//

UnhandledInstructionError::UnhandledInstructionError(cs_insn* i, const std::string& comment):
	_insn(i), _comment(comment)
{
	_getMessage();
}

void UnhandledInstructionError::_getMessage() noexcept
{
	std::stringstream ret;

	ret << "Unhandled instruction @ " << std::hex << _insn->address << " : " << _insn->mnemonic << " " << _insn->op_str;
	if (!_comment.empty())
	{
		ret << "\n"
			<< "Comment: " << _comment;
	}

	_whatMessage = ret.str();
}

const char* UnhandledInstructionError::what() const noexcept
{
	return _whatMessage.c_str();
}

//
//==============================================================================
// GenericError
//==============================================================================
//

GenericError::GenericError(const std::string& message): _whatMessage(message) {}

const char* GenericError::what() const noexcept
{
	return _whatMessage.c_str();
}

} // namespace capstone2llvmir
} // namespace retdec
