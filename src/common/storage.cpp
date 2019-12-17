/**
 * @file src/common/storage.cpp
 * @brief Common object storage representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <cassert>
#include <vector>

#include "retdec/common/storage.h"
#include "retdec/common/address.h"

namespace retdec {
namespace common {

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

Storage Storage::inMemory(const retdec::common::Address& address)
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
		unsigned registerNumber)
{
	Storage ret;
	ret.type = eType::REGISTER;
	ret._registerName = registerName;
	ret._registerNumber = registerNumber;
	return ret;
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
bool Storage::isMemory(retdec::common::Address& globalAddress) const
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
	if (_registerNumber.has_value())
	{
		registerNumber = _registerNumber.value();
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
retdec::common::Address Storage::getAddress() const
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
std::optional<unsigned> Storage::getRegisterNumber() const
{
	return _registerNumber;
}

void Storage::setRegisterNumber(unsigned registerNumber)
{
	_registerNumber = registerNumber;
}

} // namespace common
} // namespace retdec
