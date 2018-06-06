/**
* @file src/bin2llvmir/optimizations/decoder/jump_targets.cpp
* @brief Jump targets representation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/jump_targets.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/capstone.h"

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// JumpTarget
//==============================================================================
//

Config* JumpTarget::config = nullptr;

JumpTarget::JumpTarget()
{

}

JumpTarget::JumpTarget(
		retdec::utils::Address a,
		eType t,
		cs_mode m,
		retdec::utils::Address f,
		utils::Maybe<std::size_t> sz)
		:
		_address(a),
		_size(sz),
		_type(t),
		_fromAddress(f),
		_mode(m)
{
	if (config->getConfig().architecture.isArmOrThumb() && _address % 2)
	{
		_mode = CS_MODE_THUMB;
		_address -= 1;
	}
}

bool JumpTarget::operator<(const JumpTarget& o) const
{
	if (getType() == o.getType())
	{
		if (getAddress() == o.getAddress())
		{
			return getFromAddress() < o.getFromAddress();
		}
		else
		{
			return getAddress() < o.getAddress();
		}
	}
	else
	{
		return getType() < o.getType();
	}
}

retdec::utils::Address JumpTarget::getAddress() const
{
	return _address;
}

bool JumpTarget::hasSize() const
{
	return _size.isDefined();
}

utils::Maybe<std::size_t> JumpTarget::getSize() const
{
	return _size;
}

JumpTarget::eType JumpTarget::getType() const
{
	return _type;
}

retdec::utils::Address JumpTarget::getFromAddress() const
{
	return _fromAddress;
}

cs_mode JumpTarget::getMode() const
{
	return _mode;
}

void JumpTarget::setMode(cs_mode m) const
{
	_mode = m;
}

std::ostream& operator<<(std::ostream &out, const JumpTarget& jt)
{
	std::string t;
	switch (jt.getType())
	{
		case JumpTarget::eType::CONTROL_FLOW_BR_FALSE:
			t = "CONTROL_FLOW_BR_FALSE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_BR_TRUE:
			t = "CONTROL_FLOW_BR_TRUE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_SWITCH_CASE:
			t = "CONTROL_FLOW_SWITCH_CASE";
			break;
		case JumpTarget::eType::CONTROL_FLOW_CALL_TARGET:
			t = "CONTROL_FLOW_CALL_TARGET";
			break;
		case JumpTarget::eType::CONTROL_FLOW_RETURN_TARGET:
			t = "CONTROL_FLOW_RETURN_TARGET";
			break;
		case JumpTarget::eType::CONFIG:
			t = "CONFIG";
			break;
		case JumpTarget::eType::ENTRY_POINT:
			t = "ENTRY_POINT";
			break;
		case JumpTarget::eType::SELECTED_RANGE_START:
			t = "SELECTED_RANGE_START";
			break;
		case JumpTarget::eType::IMPORT:
			t = "IMPORT";
			break;
		case JumpTarget::eType::EXPORT:
			t = "EXPORT";
			break;
		case JumpTarget::eType::DEBUG:
			t = "DEBUG";
			break;
		case JumpTarget::eType::SYMBOL:
			t = "SYMBOL";
			break;
		case JumpTarget::eType::STATIC_CODE:
			t = "STATIC_CODE";
			break;
		case JumpTarget::eType::VTABLE:
			t = "VTABLE";
			break;
		case JumpTarget::eType::LEFTOVER:
			t = "LEFTOVER";
			break;
		default:
			assert(false && "unknown type");
			t = "unknown";
			break;
	}

	out << jt.getAddress() << " (" << t << ")";

	auto& arch = jt.config->getConfig().architecture;
	out << " (" << capstone_utils::mode2string(arch, jt.getMode()) << ")";

	if (jt.getFromAddress().isDefined())
	{
		out << ", from = " << jt.getFromAddress();
	}
	if (jt.hasSize())
	{
		out << ", size = " << jt.getSize();
	}

	return out;
}

//
//==============================================================================
// JumpTargets
//==============================================================================
//

Config* JumpTargets::config = nullptr;

const JumpTarget* JumpTargets::push(
		retdec::utils::Address a,
		JumpTarget::eType t,
		cs_mode m,
		retdec::utils::Address f,
		utils::Maybe<std::size_t> sz)
{
	static auto& arch = config->getConfig().architecture;

	if (a.isDefined())
	{
		if (arch.isArmOrThumb() && a % 2)
		{
			m = CS_MODE_THUMB;
			a -= 1;
		}

		if ((arch.isArmOrThumb() && m == CS_MODE_ARM && a % 4)
				|| (arch.isArmOrThumb() && m == CS_MODE_THUMB && a % 2)
				|| (arch.isMipsOrPic32() && a % 4)
				|| (arch.isPpc() && a % 4))
		{
			LOG << "\t\t" << "[-] JT not aligned @ " << a << std::endl;
		}
		else
		{
			LOG << "\t\t" << "[+] JT @ " << a << std::endl;
			return &(*_data.emplace(a, t, m, f, sz).first);
		}
	}

	return nullptr;
}

std::size_t JumpTargets::size() const
{
	return _data.size();
}

void JumpTargets::clear()
{
	_data.clear();
}

bool JumpTargets::empty()
{
	return _data.empty();
}

const JumpTarget& JumpTargets::top()
{
	return *_data.begin();
}

void JumpTargets::pop()
{
	_data.erase(top());
}

auto JumpTargets::begin()
{
	return _data.begin();
}

auto JumpTargets::end()
{
	return _data.end();
}

std::ostream& operator<<(std::ostream &out, const JumpTargets& jts)
{
	out << "Jump targets:" << std::endl;
	for (auto& jt : jts._data)
	{
		out << "\t" << jt << std::endl;
	}
	return out;
}

} // namespace bin2llvmir
} // namespace retdec
