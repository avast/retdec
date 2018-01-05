/**
 * @file include/retdec/config/objects.h
 * @brief Decompilation configuration manipulation: objects.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_OBJECTS_H
#define RETDEC_CONFIG_OBJECTS_H

#include <string>

#include "retdec/config/base.h"
#include "retdec/config/storage.h"
#include "retdec/config/types.h"
#include "retdec/utils/test.h"

namespace retdec {
namespace config {

GTEST_FORWARD_TEST(
		GlobalVarContainerTests,
		ElementWithTheSameAddressGetsReplaced)
GTEST_FORWARD_TEST(
		GlobalVarContainerTests,
		OperationsOnUnderlyingContainerAreReflectedInaddr2global)

/**
 * Represents object (i.e. register, stack, global, parameter).
 *
 * Object's name is its unique ID.
 *
 * Besides common members like name and type, objects may also have
 * additional information meaningful only to their particular
 * flavour (storage type).
 * Global objects have addresses they are located on.
 * Register objects have names of registers they are stored in.
 * Stack objects have their stack frame offset.
 * Parameters have no additional information.
 */
class Object
{
	public:
		Object(const std::string& name, const Storage& storage);
		static Object fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

		bool operator==(const Object& o) const;
		bool operator<(const Object& o) const;

		/// @name Object query methods.
		/// @{
		bool isFromDebug() const;
		/// @}

		/// @name Object set methods.
		/// @{
		void setRealName(const std::string& n);
		void setCryptoDescription(const std::string& d);
		void setIsFromDebug(bool b);
		/// @}

		/// @name Object get methods.
		/// @{
		const std::string& getId() const;
		const std::string& getName() const;
		const std::string& getRealName() const;
		const std::string& getCryptoDescription() const;
		const Storage& getStorage() const;
		/// @}

	public:
		Type type;

	protected:
		/// Unique ID -- name used in LLVM IR.
		std::string _name;
		Storage _storage;
		/// Real name of this object to appear in output C.
		/// This may or may not differ from @c name.
		std::string _realName;
		std::string _cryptoDescription;
		bool _fromDebug = false;
};

/**
 * Sequential container of objects.
 * The order of objects in this container is important
 * (e.g. function parameters).
 */
class ObjectSequentialContainer : public BaseSequentialContainer<Object>
{
	public:
		const Object* getObjectByName(const std::string& name) const;
		const Object* getObjectByRealName(const std::string& name) const;
		const Object* getObjectByNameOrRealName(const std::string& name) const;
};

/**
 * Set container of objects.
 * The order of objects in this container is unimportant (e.g. local variables).
 */
class ObjectSetContainer : public BaseAssociativeContainer<std::string, Object>
{
	public:
		const Object* getObjectByName(const std::string& name) const;
		const Object* getObjectByRealName(const std::string& name) const;
		const Object* getObjectByNameOrRealName(const std::string& name) const;
};

/**
 * Set container for register objects.
 * Only register objects are allowed to be inserted -- other objects
 * are not inserted.
 */
class RegisterContainer : public ObjectSetContainer
{
	public:
		virtual std::pair<iterator,bool> insert(const Object& e) override;
		std::pair<iterator,bool> insert(const std::string& name);
};

/**
 * Set container which makes sure no two objects have the same address or name.
 * See @c insert() method for details.
 */
class GlobalVarContainer : public ObjectSetContainer
{
	public:
		GlobalVarContainer();
		GlobalVarContainer(const GlobalVarContainer& o);
		GlobalVarContainer& operator=(const GlobalVarContainer& o);

		const Object* getObjectByAddress(
				const retdec::utils::Address& address) const;

		/// @name Reimplemented base container methods.
		///
		/// They need to be reimplemented to modify both underlying container
		/// and @c addr2global map.
		/// @{
		virtual std::pair<iterator,bool> insert(const Object& e) override;
		void clear();
		size_t erase(const Object& val);
		/// @}

	private:
		/// Map allows fast global variables search by address.
		std::map<retdec::utils::Address, const Object*> _addr2global;

		GTEST_FRIEND_TEST(
				GlobalVarContainerTests,
				ElementWithTheSameAddressGetsReplaced);
		GTEST_FRIEND_TEST(
				GlobalVarContainerTests,
				OperationsOnUnderlyingContainerAreReflectedInaddr2global);
};

} // namespace config
} // namespace retdec

#endif
