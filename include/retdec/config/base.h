/**
 * @file include/retdec/config/base.h
 * @brief Decompilation configuration manipulation: base.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_BASE_H
#define RETDEC_CONFIG_BASE_H

#include <algorithm>
#include <list>
#include <map>
#include <set>
#include <vector>

#include <json/json.h>

#include "retdec/config/config_exceptions.h"
#include "retdec/utils/address.h"
#include "retdec/utils/const.h"

namespace retdec {
namespace config {

//
//=============================================================================
// Safe (check type and throw exception) JSON value loading methods
//=============================================================================
//

void checkJsonValueIsObject(const Json::Value& val, const std::string& name);

Json::Value::Int safeGetInt(
		const Json::Value& val,
		const std::string& name = "",
		Json::Value::Int defaultValue = 0);

Json::Value::UInt safeGetUint(
		const Json::Value& val,
		const std::string& name = "",
		Json::Value::UInt defaultValue = 0);

retdec::utils::Address safeGetAddress(
		const Json::Value& val,
		const std::string& name = "");

Json::Value::UInt64 safeGetUint64(
		const Json::Value& val,
		const std::string& name = "",
		Json::Value::UInt64 defaultValue = 0);

double safeGetDouble(
		const Json::Value& val,
		const std::string& name = "",
		double defaultValue = 0.0);

std::string safeGetString(
		const Json::Value& val,
		const std::string& name = "",
		const std::string& defaultValue = "");

bool safeGetBool(
		const Json::Value& val,
		const std::string& name = "",
		bool defaultValue = false);

//
//=============================================================================
// Conversions to JSON values.
//=============================================================================
//

std::string toJsonValue(retdec::utils::Address a);

//
//=============================================================================
// AddressRangeJson
//=============================================================================
//

class AddressRangeJson : public retdec::utils::AddressRange
{
	public:
		AddressRangeJson() : AddressRange() {}
		AddressRangeJson(retdec::utils::Address f, retdec::utils::Address s) : AddressRange(f, s) {}
		explicit AddressRangeJson(const std::string& r) : AddressRange(r) {}

		static AddressRangeJson fromJsonValue(const Json::Value& val)
		{
			AddressRangeJson ret;
			ret.readJsonValue(val);
			return ret;
		}

		/**
		 * Creates JSON object (associative array) representing address range <start, end).
		 * @return Created JSON object.
		 */
		Json::Value getJsonValue() const
		{
			Json::Value pair;

			if (getStart().isDefined() && getEnd().isDefined())
			{
				pair["start"] = toJsonValue(getStart());
				pair["end"] = toJsonValue(getEnd());
			}

			return pair;
		}

		/**
		 * Reads JSON object (associative array) representing address range <start, end).
		 * @param val JSON object to read.
		 */
		void readJsonValue(const Json::Value& val)
		{
			if ( val.isNull() )
			{
				return;
			}

			setStartEnd(
					safeGetAddress(val, "start"),
					safeGetAddress(val, "end"));
		}
};

//
//=============================================================================
// BaseSequentialContainer
//=============================================================================
//

/**
 * Base sequential container class.
 * Elements are stored in the same order they were inserted.
 * Method @c insert() makes sure that elements in containers are unique.
 *
 * Elements must implement these methods:
 * <tt>Json::Value getJsonValue() const;</tt>
 * <tt>void readJsonValue(Json::Value& val);</tt>
 */
template <class Elem>
class BaseSequentialContainer
{
	public:
		using iterator       = typename std::list<Elem>::iterator;
		using const_iterator = typename std::list<Elem>::const_iterator;

	public:
		virtual ~BaseSequentialContainer() {}

		iterator begin()             { return _data.begin(); }
		const_iterator begin() const { return _data.begin(); }
		iterator end()               { return _data.end(); }
		const_iterator end() const   { return _data.end(); }
		size_t size() const          { return _data.size(); }
		bool empty() const           { return _data.empty(); }
		Elem& front()                { return _data.front(); }
		void clear()                 { _data.clear(); }

		Elem& operator[](std::size_t n)
		{
			auto it = _data.begin();
			std::advance(it, n);
			return *it;
		}

		/**
		 * Method keeps elements in container unique.
		 * New element is added only if there is no equal element in
		 * container so far.
		 * If there is equal element, it is rewritten (updated) with the
		 * new element, but container size does not change.
		 * Update is important, because some new element's members may
		 * differ from the existing ones even if the two elements are
		 * considered equal.
		 * Equality is often determined by single element's member,
		 * which is unique (e.g. name, address).
		 * However, other members of equal elements may differ.
		 *
		 * @param e Element to insert.
		 */
		void insert(const Elem& e)
		{
			for (auto& elem : _data)
			{
				if (elem == e)
				{
					elem = e;
					return;
				}
			}
			_data.push_back( e );
		}

		/**
		 * @return @c True if containers have the same size and all their
		 * elements are the same. @c False otherwise.
		 */
		bool operator==(const BaseSequentialContainer<Elem>& val) const
		{
			if (size() != val.size())
			{
				return false;
			}

			auto i1 = begin();
			auto e1 = end();
			auto i2 = val.begin();
			auto e2 = val.end();
			for (; i1 != e1 && i2 != e2; ++i1, ++i2)
			{
				if (!(*i1 == *i2))
				{
					return false;
				}
			}

			return true;
		}
		bool operator!=(const BaseSequentialContainer<Elem>& val) const
		{
			return !(*this == val);
		}

	public:
		/**
		 * Creates array of JSON objects created from elements of this container.
		 * @return Created JSON array.
		 */
		Json::Value getJsonValue() const
		{
			Json::Value array(Json::arrayValue);

			for (auto& elem : _data)
			{
				array.append( elem.getJsonValue() );
			}

			return array;
		}

		/**
		 * Reads array of JSON objects into elements of this container.
		 * Container is cleared before parsing - it contains only new objects afterwards.
		 * @param val JSON array to read.
		 */
		void readJsonValue(const Json::Value& val)
		{
			clear();

			for (auto& elem : val)
			{
				if ( ! elem.isNull() )
				{
					_data.push_back( Elem::fromJsonValue(elem) );
				}
			}
		}

	public:
		/**
		 * Get pointer to element by its ID.
		 * @param id ID of the element to get.
		 * @return Element with the specified ID or @c nullptr if not found.
		 */
		template<typename ID>
		const Elem* getElementById(const ID& id) const
		{
			for (auto& e : _data)
			{
				if (e.getId() == id)
					return &e;
			}
			return nullptr;
		}

	protected:
		std::list<Elem> _data;
};

//
//=============================================================================
// BaseAssociativeContainer
//=============================================================================
//

/**
 * Base associative container class.
 * Class's behaviour is slightly different than std::map. See @c insert() method
 * for details.
 *
 * Elements must implement these methods:
 * <tt>Elem(const ID&)</tt>
 * <tt>Elem(Json::Value& val)</tt>
 * <tt>ID getId() const;</tt>
 * <tt>Json::Value getJsonValue() const;</tt>
 * <tt>void readJsonValue(Json::Value& val);</tt>
 */
template <class ID, class Elem>
class BaseAssociativeContainer
{
	public:
		using iterator       = typename std::map<ID, Elem>::iterator;
		using const_iterator = typename std::map<ID, Elem>::const_iterator;

	public:
		virtual ~BaseAssociativeContainer() {}

		iterator begin()             { return _data.begin(); }
		const_iterator begin() const { return _data.begin(); }
		iterator end()               { return _data.end(); }
		const_iterator end() const   { return _data.end(); }
		size_t size() const          { return _data.size(); }
		bool empty() const           { return _data.empty(); }
		void clear()                 { _data.clear(); }
		size_t erase(const ID& k)    { return _data.erase(k); }

		/**
		 * This method behaves slightly different than std::map::insert().
		 * If element with key equal to some existing element is inserted,
		 * the existing element is updated (rewritten) with the new element.
		 * Update is important, because some new element's members may
		 * differ from the existing ones even if the two elements are
		 * considered equal.
		 * Equality is often determined by single element's member,
		 * which is unique (e.g. name, address).
		 * However, other members of equal elements may differ.
		 *
		 * @param e Element to insert.
		 */
		virtual std::pair<iterator,bool> insert(const Elem& e)
		{
			auto res = _data.emplace(e.getId(), e);
			if (!res.second)
			{
				// There is already an object on this address, so overwrite it
				// to ensure that it is updated.
				res.first->second = e;
			}
			return res;
		}

	public:
		/**
		 * Creates array of JSON objects created from elements of this container.
		 * @return Created JSON array.
		 */
		Json::Value getJsonValue() const
		{
			Json::Value array(Json::arrayValue);

			for (auto& elem : _data)
			{
				array.append( elem.second.getJsonValue() );
			}

			return array;
		}

		/**
		 * Reads array of JSON objects into elements of this container.
		 * Container is cleared before parsing - it contains only new objects afterwards.
		 * @param val JSON array to read.
		 */
		void readJsonValue(const Json::Value& val)
		{
			clear();

			for (auto& elem : val)
			{
				if ( ! elem.isNull() )
				{
					insert( Elem::fromJsonValue(elem) );
				}
			}
		}

	public:
		/**
		 * Get pointer to element by its ID.
		 * @param id ID of the element to get.
		 * @return Element with the specified ID or @c nullptr if not found.
		 */
		Elem* getElementById(const ID& id)
		{
			return retdec::utils::likeConstVersion(
				this, &BaseAssociativeContainer::getElementById, id);
		}

		/// const version of getElementById().
		const Elem* getElementById(const ID& id) const
		{
			auto f = _data.find(id);
			if (f != _data.end())
				return &f->second;
			else
				return nullptr;
		}

	protected:
		std::map<ID, Elem> _data;
};

//
//=============================================================================
// BaseSetContainer
//=============================================================================
//

/**
 * Base set container class.
 * Class's behaviour is slightly different than std::set. See @c insert() method
 * for details.
 *
 * Elements must implement these three methods:
 * <tt>bool operator<(const ID&) const;</tt>
 * <tt>Json::Value getJsonValue() const;</tt>
 * <tt>void readJsonValue(Json::Value&);</tt>
 */
template <class Elem>
class BaseSetContainer
{
	public:
		using iterator       = typename std::set<Elem>::iterator;
		using const_iterator = typename std::set<Elem>::const_iterator;

	public:
		virtual ~BaseSetContainer() {}

		iterator begin()                    { return _data.begin(); }
		const_iterator begin() const        { return _data.begin(); }
		iterator end()                      { return _data.end(); }
		const_iterator end() const          { return _data.end(); }
		iterator find (const Elem& v)       { return _data.find(v); }
		const_iterator find (const Elem& v) const { return _data.find(v); }
		size_t size() const                 { return _data.size(); }
		bool empty() const                  { return _data.empty(); }
		void clear()                        { _data.clear(); }
		size_t erase(const Elem& val)       { return _data.erase(val); }

		/**
		 * This method behaves slightly different than std::set::insert().
		 * If element equal to some existing element is inserted,
		 * the existing element is updated (rewritten) with the new element.
		 * Update is important, because some new element's members may
		 * differ from the existing ones even if the two elements are
		 * considered equal.
		 * Equality is often determined by single element's member,
		 * which is unique (e.g. name, address).
		 * However, other members of equal elements may differ.
		 *
		 * @param e Element to insert.
		 * @return Result of std::set::insert(). However, because potential
		 * existing element is removed, @c pair::second is always true.
		 */
		virtual std::pair<iterator,bool> insert(const Elem& e)
		{
			_data.erase( e );
			return _data.insert( e );
		}

	public:
		/**
		 * Creates array of JSON objects created from elements of this container.
		 * @return Created JSON array.
		 */
		Json::Value getJsonValue() const
		{
			Json::Value array(Json::arrayValue);

			for (auto& elem : _data)
			{
				array.append( elem.getJsonValue() );
			}

			return array;
		}

		/**
		 * Reads array of JSON objects into elements of this container.
		 * Container is cleared before parsing - it contains only new objects afterwards.
		 * @param val JSON array to read.
		 */
		void readJsonValue(const Json::Value& val)
		{
			for (auto& elem : val)
			{
				if ( ! elem.isNull() )
				{
					insert( Elem::fromJsonValue(elem) );
				}
			}
		}

	public:
		/**
		 * Get pointer to element by its ID.
		 * @param id ID of the element to get.
		 * @return Element with the specified ID or @c nullptr if not found.
		 */
		template<typename ID>
		const Elem* getElementById(const ID& id) const
		{
			for (auto& elem : _data)
			{
				if (elem.getId() == id)
					return &elem;
			}
			return nullptr;
		}

	protected:
		std::set<Elem> _data;
};

//
//=============================================================================
// Helper methods
//=============================================================================
//

/**
 * Creates array of JSON objects created from strings in the provided container.
 * @param data String container.
 * @return Created JSON array.
 */
template<typename Container>
Json::Value getJsonStringValueVisit(const Container& data)
{
	Json::Value array(Json::arrayValue);
	for (auto& elem : data)
	{
		array.append(elem);
	}
	return array;
}

void readJsonStringValueVisit(std::set<std::string>& data, const Json::Value& node);
void readJsonStringValueVisit(std::vector<std::string>& data, const Json::Value& node);

} // namespace config
} // namespace retdec

#endif
