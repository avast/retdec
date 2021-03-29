/**
 * @file include/retdec/serdes/address.h
 * @brief C++ standard types (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_STD_H
#define RETDEC_SERDES_STD_H

#include <map>
#include <type_traits>

#include <rapidjson/document.h>
#include <rapidjson/encodings.h>

namespace retdec {
namespace serdes {

/**
 * Explicitly instantiate all the needed serialization functions of form:
 * @code
 *     template <typename Writer>
 *     void serialize(Writer&, const T&)
 * @endcode
 */
#define SERIALIZE_EXPLICIT_INSTANTIATION(T)                                    \
	template void serialize(                                                   \
		rapidjson::PrettyWriter<rapidjson::StringBuffer>&,                     \
		const T&);                                                             \
	template void serialize(                                                   \
		rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::ASCII<>>&, \
		const T&);

int64_t deserializeInt64(
	const rapidjson::Value& val,
	const std::string& key,
	int64_t defaultValue = 0);

uint64_t deserializeUint64(
	const rapidjson::Value& val,
	const std::string& key,
	uint64_t defaultValue = 0);

bool deserializeBool(
	const rapidjson::Value& val,
	const std::string& key,
	bool defaultValue = false);

double deserializeDouble(
	const rapidjson::Value& val,
	const std::string& key,
	double defaultValue = 0.0);

std::string deserializeString(
	const rapidjson::Value& val,
	const std::string& key,
	const std::string& defaultValue = "");

void deserialize(const rapidjson::Value& val, const char*& str);
void deserialize(const rapidjson::Value& val, std::string& s);

template<typename ContainerOfDeserializableObjects>
void deserializeContainer(
		const rapidjson::Value& val,
		const std::string& key,
		ContainerOfDeserializableObjects& objs)
{
	objs.clear();

	auto array = val.FindMember(key);
	if (array != val.MemberEnd() && array->value.IsArray())
	{
		for (auto i = array->value.Begin(), e = array->value.End(); i != e; ++i)
		{
			auto& obj = *i;
			if (!obj.IsNull())
			{
				typename ContainerOfDeserializableObjects::value_type v;
				deserialize(obj, v);
				objs.insert(objs.end(), v);
			}
		}
	}
}

template <typename DeserializableObject>
void deserialize(
		const rapidjson::Value& val,
		const std::string& key,
		DeserializableObject& obj)
{
	auto res = val.FindMember(key);
	if (res != val.MemberEnd())
	{
		deserialize(res->value, obj);
	}
}

template <typename Writer>
void serializeInt64(
		Writer& writer,
		const std::string& key,
		int64_t value,
		bool doSerialize = true)
{
	if (doSerialize)
	{
		writer.String(key);
		writer.Int64(value);
	}
}

template <typename Writer>
void serializeUint64(
		Writer& writer,
		const std::string& key,
		uint64_t value,
		bool doSerialize = true)
{
	if (doSerialize)
	{
		writer.String(key);
		writer.Uint64(value);
	}
}

template <typename Writer>
void serializeBool(
		Writer& writer,
		const std::string& key,
		bool value,
		bool serializeIfFalse = true)
{
	if (value || serializeIfFalse)
	{
		writer.String(key);
		writer.Bool(value);
	}
}

template <typename Writer>
void serializeDouble(Writer& writer, const std::string& key, double value)
{
	writer.String(key);
	writer.Double(value);
}

template <typename Writer>
void serializeString(
		Writer& writer,
		const std::string& key,
		const std::string& value,
		bool serializeIfValueEmpty = false)
{
	if (!value.empty() || serializeIfValueEmpty)
	{
		writer.String(key);
		writer.String(value);
	}
}

template <typename Writer>
void serialize(
		Writer& writer,
		const std::string& value)
{
	writer.String(value);
}

template<typename Writer, typename ContainerOfSerializableObjects>
void serializeContainer(
		Writer& writer,
		const std::string& key,
		const ContainerOfSerializableObjects& objs,
		bool serializeIfContainerEmpty = false)
{
	if (!objs.empty() || serializeIfContainerEmpty)
	{
		writer.String(key);
		writer.StartArray();
		for (auto& obj : objs)
		{
			serialize(writer, obj);
		}
		writer.EndArray();
	}
}

template <typename Writer, typename SerializableObject>
void serialize(
		Writer& writer,
		const std::string& key,
		const SerializableObject& obj,
		bool doSerialize = true)
{
	if (doSerialize)
	{
		writer.String(key);
		serialize(writer, obj);
	}
}

} // namespace serdes
} // namespace retdec

#endif