/**
 * @file src/common/class.cpp
 * @brief Common class representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/class.h"
#include "retdec/utils/container.h"

using retdec::utils::hasItem;

namespace retdec {
namespace common {

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

void Class::setName(const std::string& name)
{
	_name = name;
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

} // namespace common
} // namespace retdec
