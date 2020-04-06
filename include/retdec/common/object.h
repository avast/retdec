/**
 * @file include/retdec/common/object.h
 * @brief Common object representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_OBJECT_H
#define RETDEC_COMMON_OBJECT_H

#include <map>
#include <vector>
#include <string>

#include "retdec/common/storage.h"
#include "retdec/common/type.h"

namespace retdec {
namespace common {

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
		Object();
		Object(const std::string& name, const common::Storage& storage);

		bool operator==(const Object& o) const;
		bool operator<(const Object& o) const;

		/// @name Object query methods.
		/// @{
		bool isFromDebug() const;
		/// @}

		/// @name Object set methods.
		/// @{
		void setName(const std::string& n);
		void setRealName(const std::string& n);
		void setCryptoDescription(const std::string& d);
		void setIsFromDebug(bool b);
		void setStorage(const common::Storage& s);
		/// @}

		/// @name Object get methods.
		/// @{
		const std::string& getId() const;
		const std::string& getName() const;
		const std::string& getRealName() const;
		const std::string& getCryptoDescription() const;
		const common::Storage& getStorage() const;
		/// @}

	public:
		common::Type type;

	protected:
		/// Unique ID -- name used in LLVM IR.
		std::string _name;
		common::Storage _storage;
		/// Real name of this object to appear in output C.
		/// This may or may not differ from @c name.
		std::string _realName;
		std::string _cryptoDescription;
		bool _fromDebug = false;
};

struct ObjectCompare
{
	using is_transparent = void;

	bool operator()(const Object& o1, const Object& o2) const
	{
		return o1 < o2;
	}
	bool operator()(const std::string& id, Object const& o) const
	{
		return id < o.getName();
	}
	bool operator()(const Object& o, const std::string& id) const
	{
		return o.getName() < id;
	}
};

/**
 * Sequential container of objects.
 * The order of objects in this container is important
 * (e.g. function parameters).
 */
class ObjectSequentialContainer : public std::vector<Object>
{
	public:
		const Object* getObjectByName(const std::string& name) const;
};

/**
 * Set container of objects.
 * The order of objects in this container is unimportant (e.g. local variables).
 */
class ObjectSetContainer : public std::set<Object, ObjectCompare>
{
	public:
		const Object* getObjectByName(const std::string& name) const;
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
				const retdec::common::Address& address) const;

		/// @name Reimplemented base container methods.
		///
		/// They need to be reimplemented to modify both underlying container
		/// and @c addr2global map.
		/// @{
		std::pair<iterator,bool> insert(const Object& e);
		std::pair<iterator,bool> insert(iterator, const Object& e);
		void clear();
		size_t erase(const Object& val);
		/// @}

	public:
		/// Map allows fast global variables search by address.
		std::map<retdec::common::Address, const Object*> _addr2global;
};

} // namespace common
} // namespace retdec

#endif
