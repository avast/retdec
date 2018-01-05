/**
 * @file src/config/classes.cpp
 * @brief Decompilation configuration manipulation: classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/classes.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace {

const std::string JSON_name           = "name";
const std::string JSON_demangledName  = "demangledName";
const std::string JSON_superClasses   = "superClasses";
const std::string JSON_virtualMethods = "virtualMethods";
const std::string JSON_constructors   = "constructors";
const std::string JSON_destructors    = "destructors";
const std::string JSON_methods        = "methods";
const std::string JSON_vtables        = "virtualTables";

} // anonymous namespace

namespace retdec {
namespace config {

//
//=============================================================================
// Class
//=============================================================================
//

Class::Class(const std::string& className) :
		_name(className)
{

}

/**
 * Reads JSON object (associative array) holding class information.
 * @param val JSON object.
 */
Class Class::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Class");

	Class ret(safeGetString(val, JSON_name));

	ret.setDemangledName(safeGetString(val, JSON_demangledName));
	readJsonStringValueVisit(ret._superClasses, val[JSON_superClasses]);
	readJsonStringValueVisit(ret.virtualMethods, val[JSON_virtualMethods]);
	readJsonStringValueVisit(ret.constructors, val[JSON_constructors]);
	readJsonStringValueVisit(ret.destructors, val[JSON_destructors]);
	readJsonStringValueVisit(ret.methods, val[JSON_methods]);
	readJsonStringValueVisit(ret.virtualTables, val[JSON_vtables]);

	return ret;
}

/**
 * Returns JSON object (associative array) holding class information.
 * @return JSON object.
 */
Json::Value Class::getJsonValue() const
{
	Json::Value val;

	if (!getName().empty()) val[JSON_name] = getName();
	if (!getDemangledName().empty()) val[JSON_demangledName] = getDemangledName();

	val[JSON_superClasses]   = getJsonStringValueVisit(_superClasses);
	val[JSON_virtualMethods] = getJsonStringValueVisit(virtualMethods);
	val[JSON_constructors]   = getJsonStringValueVisit(constructors);
	val[JSON_destructors]    = getJsonStringValueVisit(destructors);
	val[JSON_methods]        = getJsonStringValueVisit(methods);
	val[JSON_vtables]        = getJsonStringValueVisit(virtualTables);

	return val;
}

/**
 * @return Class's ID is its name.
 */
std::string Class::getId() const
{
	return getName();
}

std::string Class::getName() const
{
	return _name;
}

std::string Class::getDemangledName() const
{
	return _demangledName;
}

const std::vector<std::string>& Class::getSuperClasses() const
{
	return _superClasses;
}

void Class::setDemangledName(const std::string& demangledName)
{
	_demangledName = demangledName;
}

/**
* Has the class a constructor of the given name?
*/
bool Class::hasConstructor(const std::string& name) const
{
	return hasItem(constructors, name);
}

/**
* Has the class a destructor of the given name?
*/
bool Class::hasDestructor(const std::string& name) const
{
	return hasItem(destructors, name);
}

/**
* Has the class a method of the given name?
*
* Only non-virtual methods are considered. If you want to check whether a class
* has a virtual method, use hasVirtualMethod().
*/
bool Class::hasMethod(const std::string& name) const
{
	return hasItem(methods, name);
}

/**
* Has the class a virtual method of the given name?
*/
bool Class::hasVirtualMethod(const std::string& name) const
{
	return hasItem(virtualMethods, name);
}

/**
* Does a function with the given name belong to the class?
*
* The function may be a constructor, destructor, method, or virtual method.
*/
bool Class::hasFunction(const std::string& name) const
{
	return hasConstructor(name) ||
		hasDestructor(name) ||
		hasMethod(name) ||
		hasVirtualMethod(name);
}

/**
 * New super class is added only if there is not existing superclass of that name.
 * @return @c True if superclass was added, @c false otherwise.
 */
bool Class::addSuperClass(const std::string& superClass)
{
	for (auto& s : _superClasses)
	{
		if (s == superClass)
			return false;
	}
	_superClasses.push_back(superClass);
	return true;
}

/**
 * Classes are ordered by their names.
 */
bool Class::operator<(const Class& o) const
{
	return getName() < o.getName();
}

/**
 * Classes are equal if their names are equal.
 */
bool Class::operator==(const Class& o) const
{
	return getName() == o.getName();
}

} // namespace config
} // namespace retdec
