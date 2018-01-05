/**
* @file include/retdec/llvmir2hll/support/factory.h
* @brief Implementation of the Object Factory design pattern.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is based on the following book:
*  - A. Alexandrescu: "Modern C++ Design: Generic Programming and Design
*    Patterns Applied", Addison-Wesley, 2001
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_FACTORY_H
#define RETDEC_LLVMIR2HLL_SUPPORT_FACTORY_H

#include <map>
#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"

/**
* @brief Registers an object with @a objectId at @a factory.
*
* @param objectId Identifier of the object.
* @param objectIdVarName Name of the variable used to hold @a objectId.
* @param factory Name of the factory.
* @param createFunc Function to be used for creating objects.
*
* For example, the following code snippet registers a Python HLL writer:
* @code
* REGISTER_AT_FACTORY("py", PY_HLL_WRITER_ID, HLLWriterFactory, PyHLLWriter::create);
* @endcode
*
* This macro creates a <tt>const std::string</tt> constant in an anonymous
* namespace named @a objectIdVarName whose value is @a objectId. It is supposed
* to be used only in implementation files (i.e. @c .cpp files).
*/
// Implementation notes:
//
// - The registration is done in a call to an anonymous lambda function. It
//   returns objectId, which is used to initialize the objectIdVarName constant.
//
// - The created constant is static. We do not use an anonymous namespace for
//   that because gcc with -pedantic reports a warning when a semicolon is used
//   after the closing }. Thus, the user would have to use this macro without
//   the ending semicolon, which would feel unnatural.
#define REGISTER_AT_FACTORY(objectId, objectIdVarName, factory, createFunc) \
	static const std::string objectIdVarName = [] { \
		factory::getInstance().registerObject(objectId, createFunc); \
		return objectId; \
	} ()

namespace retdec {
namespace llvmir2hll {

/**
* @brief Handles the "Unknown Type" error in an object factory.
*
* @tparam ObjectIDType Type of the used object identifiers.
* @tparam AbstractObject Base class of all classes whose instances are to be
*                        created by a factory.
*
* This default implementation returns the null pointer.
*/
template<typename ObjectIDType, class AbstractObject>
class DefaultFactoryError {
public:
	/**
	* @brief Reaction to the "Unknown Type" error.
	*
	* @param[in] id Object's ID.
	* @return The null pointer.
	*/
	static ShPtr<AbstractObject> onUnknownType(ObjectIDType id) {
		return ShPtr<AbstractObject>();
	}

protected:
	/**
	* @brief Default constructor.
	*/
	DefaultFactoryError() = default;

	/**
	* @brief Destructor.
	*/
	~DefaultFactoryError() = default;
};

/**
* @brief Implementation of a generic object factory.
*
* Implements the Object Factory design pattern - creates instances of objects
* according to the given object identifier.

* For details, see the following book:
*  - A. Alexandrescu: "Modern C++ Design: Generic Programming and Design
*    Patterns Applied", Addison-Wesley, 2001
*
* @tparam AbstractObject Base class of all classes whose instances are to be
*                        created by a factory.
* @tparam ObjectIDType Type of an object's identifier.
* @tparam ObjectCreator Type of a function used to create instances of
*                       AbstractObject.
* @tparam FactoryErrorPolicy Policy to be used when trying to instantiate an
*                            object with unknown identifier.
*
* FactoryErrorPolicy requirements:
*  - A class template with two template parameters
*    @c ObjectIDType and @c AbstractObject.
*  - Defines a public function
*    @code
*    static ShPtr<AbstractObject> onUnknownType(ObjectIDType id);
*    @endcode
*    which handles the "Unknown Type" error.
*
* It supports ObjectCreators with up to five parameters.
*/
template<
	class AbstractObject,
	typename ObjectIDType,
	typename ObjectCreator = ShPtr<AbstractObject> (*)(),
	template<typename, class>
		class FactoryErrorPolicy = DefaultFactoryError
>
class Factory: public FactoryErrorPolicy<ObjectIDType, AbstractObject> {
private:
	/// Type of a container used to map an object ID to its creator function.
	using IDToObjectMap = std::map<ObjectIDType, ObjectCreator>;

public:
	/**
	* @brief Default constructor.
	*/
	Factory(): associations() {}

	/**
	* @brief Registers the given object.
	*
	* @param[in] id Object's ID.
	* @param[in] creator Creator to be used to create instances.
	* @return @c true if the registration was successful, @c false otherwise.
	*
	* Every ID can be registered only once. If someone tries to register
	* the same object twice, this function will return false.
	*/
	bool registerObject(ObjectIDType id, ObjectCreator creator) {
		return associations.insert(typename IDToObjectMap::value_type(
			id, creator)).second;
	}

	/**
	* @brief Unregisters the given object.
	*
	* @param[in] id Object's ID.
	* @return @c true if the unregistration was successful, @c false otherwise.
	*/
	bool unregisterObject(const ObjectIDType &id) const {
		return associations.erase(id) == 1;
	}

	/**
	* @brief Creates an instance of the given object with the given arguments.
	*
	* @param[in] id Object's ID.
	* @param args Arguments to be passed to the instance's constructor.
	* @return Instance of the given object.
	*/
	template<typename... Args>
	ShPtr<AbstractObject> createObject(const ObjectIDType &id,
			Args &&... args) const {
		auto i = associations.find(id);
		if (i != associations.end()) {
			// Instantiate the object via the registered function.
			return (i->second)(std::forward<Args>(args)...);
		}
		return this->onUnknownType(id); // "this" is necessary here
	}

	/**
	* @brief Returns a vector of all registered object IDs.
	*/
	std::vector<ObjectIDType> getRegisteredObjects() const {
		std::vector<ObjectIDType> regObjects;
		for (const auto &item : associations) {
			regObjects.push_back(item.first);
		}
		return regObjects;
	}

	/**
	* @brief Returns @a true if there is an object registered with the selected
	*        ID, @c false otherwise.
	*/
	bool isRegistered(const ObjectIDType &id) const {
		return associations.find(id) != associations.end();
	}

private:
	/// Container used to map an object ID to its creator function.
	IDToObjectMap associations;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
