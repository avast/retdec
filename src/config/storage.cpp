/**
 * @file src/config/storage.cpp
 * @brief Decompilation configuration manipulation: storage.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <vector>

#include "retdec/config/storage.h"

namespace {

const std::string JSON_type      = "type";
const std::string JSON_value     = "value";
const std::string JSON_regNum    = "registerNumber";
const std::string JSON_regClass  = "registerClass";

const std::vector<std::string> typeStrings =
{
	"undefined",
	"global",
	"register",
	"stack"
};

} // anonymous namespace

namespace retdec {
namespace config {

Storage::Storage() :
		type(eType::UNDEFINED)
{

}

Storage Storage::undefined()
{
	return Storage();
}

Storage Storage::onStack(int offset)
{
	Storage ret;
	ret.type = eType::STACK;
	ret._stackOffset = offset;
	return ret;
}

/**
 * Create on stack storage associtated with the provided register number.
 */
Storage Storage::onStack(int offset, unsigned registerNumber)
{
	Storage ret;
	ret.type = eType::STACK;
	ret._stackOffset = offset;
	ret._registerNumber = registerNumber;
	return ret;
}

Storage Storage::inMemory(const retdec::utils::Address& address)
{
	assert(address.isDefined());
	Storage ret;
	ret.type = eType::GLOBAL;
	ret._globalAddress = address;
	return ret;
}

/**
 * There are two possible register flavours: named and numbered registers.
 * This creates register storage using register name.
 */
Storage Storage::inRegister(const std::string& registerName)
{
	Storage ret;
	ret.type = eType::REGISTER;
	ret._registerName = registerName;
	return ret;
}

/**
 * There are two possible register flavours: named and numbered registers.
 * This creates register storage using register number.
 */
Storage Storage::inRegister(unsigned registerNumber)
{
	Storage ret;
	ret.type = eType::REGISTER;
	ret._registerNumber = registerNumber;
	return ret;
}

/**
 * There are two possible register flavours: named and numbered registers.
 * This creates register storage using register name, which also contains
 * information about register's number and class.
 */
Storage Storage::inRegister(
		const std::string& registerName,
		unsigned registerNumber,
		const std::string& registerClass)
{
	Storage ret;
	ret.type = eType::REGISTER;
	ret._registerName = registerName;
	ret._registerNumber = registerNumber;
	ret._registerClass = registerClass;
	return ret;
}

Storage Storage::fromJsonValue(const Json::Value& val)
{
	Storage ret;
	ret.readJsonValue(val);
	return ret;
}

void Storage::readJsonValue(const Json::Value& val)
{
	std::string enumStr = safeGetString(val, JSON_type);
	auto it = std::find(typeStrings.begin(), typeStrings.end(), enumStr);
	if (it == typeStrings.end())
	{
		type = eType::UNDEFINED;
	}
	else
	{
		type = static_cast<eType>( std::distance(typeStrings.begin(), it) );
	}

	if (isMemory())
	{
		_globalAddress = safeGetAddress(val, JSON_value);
	}
	else if (isRegister())
	{
		_registerName = safeGetString(val, JSON_value);
	}
	else if (isStack())
	{
		_stackOffset = safeGetInt(val, JSON_value);
	}
	else
	{
		assert(isUndefined());
	}

	if (val.isMember(JSON_regNum))
	{
		_registerNumber = safeGetUint(val, JSON_regNum);
	}

	if (val.isMember(JSON_regClass))
	{
		_registerClass = safeGetString(val, JSON_regClass);
	}
}

Json::Value Storage::getJsonValue() const
{
	Json::Value obj;

	if (isMemory())
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(eType::GLOBAL) ];
		obj[JSON_value] = toJsonValue(getAddress());
	}
	else if (isRegister())
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(eType::REGISTER) ];
		obj[JSON_value] = getRegisterName();
	}
	else if (isStack())
	{
		obj[JSON_type] = typeStrings[ static_cast<size_t>(eType::STACK) ];
		obj[JSON_value] = getStackOffset();
	}
	else
	{
		assert(isUndefined());
		obj[JSON_type] = typeStrings[ static_cast<size_t>(eType::UNDEFINED) ];
	}

	auto registerNumber = getRegisterNumber();
	if (registerNumber.isDefined())
	{
		obj[JSON_regNum] = registerNumber.getValue();
	}

	if (!getRegisterClass().empty())
	{
		obj[JSON_regClass] = getRegisterClass();
	}

	return obj;
}

bool Storage::isDefined() const
{
	return !isUndefined();
}

bool Storage::isUndefined() const
{
	return type == eType::UNDEFINED;
}

bool Storage::isMemory() const
{
	return type == eType::GLOBAL;
}

bool Storage::isRegister() const
{
	return type == eType::REGISTER;
}

bool Storage::isStack() const
{
	return type == eType::STACK;
}

/**
 * @param[out] globalAddress If storage is global this is set to its address.
 *                           Otherwise it is set to an undefined value.
 */
bool Storage::isMemory(retdec::utils::Address& globalAddress) const
{
	globalAddress = _globalAddress;
	return isMemory();
}

/**
 * @param[out] registerName If storage is register this is set to its name.
 *                          Otherwise it is set to an undefined value.
 *                          If register number was set, but name was not,
 *                          this may be empty even if storage is a register.
 */
bool Storage::isRegister(std::string& registerName) const
{
	registerName = _registerName;
	return isRegister();
}

/**
 * @param[out] registerNumber If register number is set, return it in parameter.
 *                            Otherwise parameter is left unchanged.
 * @return If register number is set, return @c true.
 *         Otherwise return @c false.
 */
bool Storage::isRegister(int& registerNumber) const
{
	if (_registerNumber.isDefined())
	{
		registerNumber = _registerNumber;
		return true;
	}
	else
	{
		return false;
	}
}

/**
 * @param[out] stackOffset If storage is starck this is set to its offset.
 *                         Otherwise it is set to an undefined value.
 */
bool Storage::isStack(int& stackOffset) const
{
	stackOffset = _stackOffset;
	return isStack();
}

/**
 * @return If storage is global return its address.
 *         Otherwise return an undefined value.
 */
retdec::utils::Address Storage::getAddress() const
{
	return _globalAddress;
}

/**
 * @return If storage is register return its name.
 *         Otherwise return an undefined value.
 */
std::string Storage::getRegisterName() const
{
	return _registerName;
}

/**
 * @return If storage is stack return its offset.
 *         Otherwise return an undefined value.
 */
int Storage::getStackOffset() const
{
	return _stackOffset;
}

/**
 * This method can be used on any storage type, which might contain register number.
 * Right now, it is either register or stack storage.
 * @return If register number is set, return defined value.
 *         Otherwise return undefined value.
 */
retdec::utils::Maybe<unsigned> Storage::getRegisterNumber() const
{
	return _registerNumber;
}

/**
 * @return Register's class or empty string if class of register (or any
 * other storage type) not set.
 */
std::string Storage::getRegisterClass() const
{
	return _registerClass;
}

} // namespace config
} // namespace retdec
