/**
 * @file include/retdec/common/class.h
 * @brief Common class representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_CLASS_H
#define RETDEC_COMMON_CLASS_H

#include <set>
#include <string>
#include <vector>

namespace retdec {
namespace common {

/**
 * Represents C++ class.
 * Class name is its unique ID.
 */
class Class
{
	public:
		Class(const std::string& className = std::string());

		/// @name Class get methods.
		/// @{
		std::string getId() const;
		std::string getName() const;
		std::string getDemangledName() const;
		const std::vector<std::string>& getSuperClasses() const;
		bool hasConstructor(const std::string& name) const;
		bool hasDestructor(const std::string& name) const;
		bool hasMethod(const std::string& name) const;
		bool hasVirtualMethod(const std::string& name) const;
		bool hasFunction(const std::string& name) const;
		/// @}

		/// @name Class set methods.
		/// @{
		void setName(const std::string& name);
		void setDemangledName(const std::string& demangledName);
		/// @}

		/// @name Class modification methods.
		/// @{
		bool addSuperClass(const std::string& superClass);
		/// @}

		bool operator<(const Class& o) const;
		bool operator==(const Class& o) const;

	public:
		std::set<std::string> superClasses;
		std::set<std::string> virtualMethods;
		std::set<std::string> constructors;
		std::set<std::string> destructors;
		std::set<std::string> methods;
		std::set<std::string> virtualTables;

	private:
		std::string _name;
		std::string _demangledName;
		std::vector<std::string> _superClasses;
};

/**
 * A set container with classes.
 */
struct ClassCompare
{
	using is_transparent = void;

	bool operator()(const Class& c1, const Class& c2) const
	{
		return c1 < c2;
	}
	bool operator()(const std::string& id, Class const& c) const
	{
		return id < c.getName();
	}
	bool operator()(const Class& c, const std::string& id) const
	{
		return c.getName() < id;
	}
};
using ClassContainer = std::set<Class, ClassCompare>;

} // namespace common
} // namespace retdec

#endif
