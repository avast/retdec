/**
 * @file include/retdec/config/classes.h
 * @brief Decompilation configuration manipulation: classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_CLASSES_H
#define RETDEC_CONFIG_CLASSES_H

#include <string>
#include <vector>

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents C++ class.
 * Class name is its unique ID.
 */
class Class
{
	public:
		explicit Class(const std::string& className);
		static Class fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

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
class ClassContainer : public BaseSetContainer<Class>
{

};

} // namespace config
} // namespace retdec

#endif
