/**
 * @file src/config/objects.cpp
 * @brief Decompilation configuration manipulation: objects.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/config/objects.h"

namespace {

const std::string JSON_name       = "name";
const std::string JSON_realName   = "realName";
const std::string JSON_storage    = "storage";
const std::string JSON_type       = "type";
const std::string JSON_fromDebug  = "isFromDebug";
const std::string JSON_cryptoDesc = "cryptoDescription";

} // anonymous namespace

namespace retdec {
namespace config {

//
//=============================================================================
// Object
//=============================================================================
//

Object::Object(const std::string& name, const Storage& storage) :
		_name(name),
		_storage(storage)
{
	assert( !getName().empty() );
}

/**
 * Reads JSON object (associative array) holding object information.
 * @param val JSON object.
 */
Object Object::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Object");

	Object ret(
			safeGetString(val, JSON_name),
			Storage::fromJsonValue(val[JSON_storage])
	);

	ret.setRealName( safeGetString(val, JSON_realName) );
	ret.setCryptoDescription( safeGetString(val, JSON_cryptoDesc) );
	ret.setIsFromDebug( safeGetBool(val, JSON_fromDebug) );
	ret.type.readJsonValue( val[JSON_type] );

	return ret;
}

/**
 * Returns JSON object (associative array) holding object information.
 * @return JSON object.
 */
Json::Value Object::getJsonValue() const
{
	Json::Value obj;

	if (!getName().empty()) obj[JSON_name] = getName();
	if (!getRealName().empty()) obj[JSON_realName] = getRealName();
	if (!getCryptoDescription().empty()) obj[JSON_cryptoDesc] = getCryptoDescription();
	if (isFromDebug()) obj[JSON_fromDebug] = isFromDebug();

	if (type.isDefined()) obj[JSON_type] = type.getJsonValue();
	if (_storage.isDefined()) obj[JSON_storage] = _storage.getJsonValue();

	return obj;
}

/**
 * Object are equal if their names are equal.
 * @param o Other object.
 */
bool Object::operator==(const Object& o) const
{
	return _name == o._name;
}

/**
 * Objects are compared by their uniqie IDs (i.e. names).
 */
bool Object::operator<(const Object& o) const
{
	return _name < o._name;
}

void Object::setRealName(const std::string& n)
{
	_realName = n;
}

void Object::setCryptoDescription(const std::string& d)
{
	_cryptoDescription = d;
}

void Object::setIsFromDebug(bool b)
{
	_fromDebug = b;
}

bool Object::isFromDebug() const
{
	return _fromDebug;
}

/**
 * @return Object's ID is its name.
 */
const std::string& Object::getId() const
{
	return getName();
}

const std::string& Object::getName() const
{
	return _name;
}

/**
 * @return Real name of this object to appear in output C.
 * This may or may not differ from @c name.
 */
const std::string& Object::getRealName() const
{
	return _realName;
}

const std::string& Object::getCryptoDescription() const
{
	return _cryptoDescription;
}

const Storage& Object::getStorage() const
{
	return _storage;
}

//
//=============================================================================
// ObjectContainer
//=============================================================================
//

/**
 * @return Pointer to object or @c nullptr if not found.
 */
const Object* ObjectSequentialContainer::getObjectByName(
		const std::string& name) const
{
	return getElementById(name);
}

/**
 * @return Pointer to object or @c nullptr if not found.
 */
const Object* ObjectSequentialContainer::getObjectByRealName(
		const std::string& name) const
{
	for (auto& elem : _data)
	{
		if (elem.getRealName() == name)
			return &elem;
	}
	return nullptr;
}

const Object* ObjectSequentialContainer::getObjectByNameOrRealName(
		const std::string& name) const
{
	auto* ret = getObjectByName(name);
	return ret ? ret : getObjectByRealName(name);
}

//
//=============================================================================
// ObjectSetContainer
//=============================================================================
//

/**
 * @return Pointer to object or @c nullptr if not found.
 */
const Object* ObjectSetContainer::getObjectByName(
		const std::string& name) const
{
	return getElementById(name);
}

/**
 * @return Pointer to object or @c nullptr if not found.
 * @note This search have linear time complexity.
 */
const Object* ObjectSetContainer::getObjectByRealName(
		const std::string& name) const
{
	for (auto& elem : _data)
	{
		if (elem.second.getRealName() == name)
			return &elem.second;
	}
	return nullptr;
}

/**
 * @return Pointer to object or @c nullptr if not found.
 * @note This search have up to linear time complexity.
 */
const Object* ObjectSetContainer::getObjectByNameOrRealName(
		const std::string& name) const
{
	auto* ret = getObjectByName(name);
	return ret ? ret : getObjectByRealName(name);
}

//
//=============================================================================
// RegisterContainer
//=============================================================================
//

/**
 * Only register objects are allowed to be inserted.
 * See @c BaseSetContainer::insert();
 * Non-register objects are not inserted and pair {end(), false} is returned.
 */
std::pair<RegisterContainer::iterator,bool> RegisterContainer::insert(const Object& e)
{
	if (e.getStorage().isRegister())
	{
		return BaseAssociativeContainer::insert(e);
	}
	else
	{
		assert(false && "object other than register is inserted");
		return {RegisterContainer::end(), false};
	}
}

std::pair<RegisterContainer::iterator,bool> RegisterContainer::insert(
		const std::string& name)
{
	auto s = retdec::config::Storage::inRegister(name);
	auto r = retdec::config::Object(name, s);
	r.setRealName(name);
	return insert(r);
}

//
//=============================================================================
// GlobalVarContainer
//=============================================================================
//

GlobalVarContainer::GlobalVarContainer() :
		ObjectSetContainer()
{

}

GlobalVarContainer::GlobalVarContainer(const GlobalVarContainer& o) :
		ObjectSetContainer(o)
{
	*this = o;
}

/**
 * We need to make sure pointers in @c _addr2global are valid -- point
 * to the new @c _data container, not the old one.
 */
GlobalVarContainer& GlobalVarContainer::operator=(const GlobalVarContainer& o)
{
	if (this != &o)
	{
		ObjectSetContainer::operator=(o);
		_addr2global.clear();
		for (auto& p : _data)
		{
			_addr2global[p.second.getStorage().getAddress()] = &p.second;
		}
	}
	return *this;
}

/**
 * @return Pointer to global object or @c nullptr if not found.
 */
const Object* GlobalVarContainer::getObjectByAddress(
		const retdec::utils::Address& address) const
{
	auto fIt = _addr2global.find(address);
	return fIt != _addr2global.end() ? fIt->second : nullptr;
}

/**
 * Besides calling the underlying container's insert which checks (and replaces)
 * for existing elements with the same unique ID (name), this method also check
 * for elements with the same global address. Such elements are also removed
 * before adding the new element, since container is not allowed to hold two
 * ebjects with the same global address. Moreover, @c _addr2global is also
 * updated.
 */
std::pair<GlobalVarContainer::iterator,bool> GlobalVarContainer::insert(
		const Object& e)
{
	assert(e.getStorage().isMemory());
	if (!e.getStorage().isMemory())
	{
		return {end(), false};
	}

	auto existing = getObjectByAddress(e.getStorage().getAddress());
	if (existing)
	{
		erase(*existing);
	}

	auto retPair = BaseAssociativeContainer::insert(e);

	const Object* obj = &retPair.first->second;
	const auto& addr = e.getStorage().getAddress();
	auto res = _addr2global.emplace(addr,obj);
	if (!res.second)
	{
		// There is already an object on this address, so overwrite it
		// to ensure that it is updated.
		res.first->second = obj;
	}

	return retPair;
}

/**
 * Clear both underlying container and @c addr2global map.
 */
void GlobalVarContainer::clear()
{
	_data.clear();
	_addr2global.clear();
}

/**
 * Erase from both underlying container and @c addr2global map.
 */
size_t GlobalVarContainer::erase(const Object& val)
{
	assert(val.getStorage().isMemory());
	if (val.getStorage().isMemory())
	{
		_addr2global.erase(val.getStorage().getAddress());
	}
	return _data.erase(val.getId());
}

} // namespace config
} // namespace retdec
