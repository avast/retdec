/**
* @file src/ctypesparser/json_ctypes_parser.cpp
* @brief Parser for C-types from JSON files.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>
#include <istream>
#include <regex>
#include <sstream>

#include <rapidjson/error/en.h>

#include "ctypes/annotation_in.h"
#include "ctypes/annotation_inout.h"
#include "ctypes/annotation_optional.h"
#include "ctypes/annotation_out.h"
#include "ctypes/context.h"
#include "ctypes/floating_point_type.h"
#include "ctypes/function_declaration.h"
#include "ctypes/function_type.h"
#include "ctypes/header_file.h"
#include "ctypes/integral_type.h"
#include "ctypes/member.h"
#include "ctypes/module.h"
#include "ctypes/parameter.h"
#include "ctypes/pointer_type.h"
#include "ctypes/struct_type.h"
#include "ctypes/type.h"
#include "ctypes/typedefed_type.h"
#include "ctypes/union_type.h"
#include "ctypes/unknown_type.h"
#include "ctypes/void_type.h"
#include "ctypesparser/json_ctypes_parser.h"
#include "tl-cpputils/container.h"
#include "tl-cpputils/string.h"

namespace {

const std::string JSON_functions   = "functions";
const std::string JSON_types       = "types";

const std::string JSON_call_conv   = "call_conv";
const std::string JSON_decl        = "decl";
const std::string JSON_header      = "header";
const std::string JSON_name        = "name";
const std::string JSON_params      = "params";
const std::string JSON_ret_type    = "ret_type";
const std::string JSON_vararg      = "vararg";

const std::string JSON_annotations          = "annotations";
const std::string JSON_array                = "array";
const std::string JSON_bit_width            = "bit_width";
const std::string JSON_array_dimensions     = "dimensions";
const std::string JSON_array_element        = "element_type";
const std::string JSON_enum                 = "enum";
const std::string JSON_enum_items           = "items";
const std::string JSON_enum_value           = "value";
const std::string JSON_integral_type        = "integral_type";
const std::string JSON_floating_point_type  = "floating_point_type";
const std::string JSON_function_type        = "function";
const std::string JSON_members              = "members";
const std::string JSON_modified_type        = "modified_type";
const std::string JSON_pointed_type         = "pointed_type";
const std::string JSON_pointer              = "pointer";
const std::string JSON_qualifier            = "qualifier";
const std::string JSON_structure            = "structure";
const std::string JSON_type                 = "type";
const std::string JSON_typedef              = "typedef";
const std::string JSON_typedefed_type       = "typedefed_type";
const std::string JSON_union                = "union";
const std::string JSON_unknown_type         = "unknown";
const std::string JSON_void                 = "void";

} // anonymous namespace

namespace ctypesparser {

const rapidjson::Value &safeGetObject(const rapidjson::Value &val, const std::string &name)
{
	auto res = val.FindMember(name.c_str());
	if (res != val.MemberEnd() && res->value.IsObject())
	{
		return res->value;
	}
	else
	{
		std::string errMsg = name + " must be an object value";
		throw CTypesParseError(errMsg);
	}
}

const rapidjson::Value &safeGetArray(const rapidjson::Value &val, const std::string &name)
{
	auto res = val.FindMember(name.c_str());
	if (res != val.MemberEnd() && res->value.IsArray())
	{
		return res->value;
	}
	else
	{
		std::string errMsg = name + " must be an array value";
		throw CTypesParseError(errMsg);
	}
}

std::string safeGetString(
	const rapidjson::Value &val,
	const std::string &name,
	const rapidjson::Value &defaultValue = rapidjson::Value())
{
	auto res = val.FindMember(name.c_str());
	if (res != val.MemberEnd() && res->value.IsString())
	{
		return res->value.GetString();
	}
	else if (defaultValue.IsString())
	{
		return defaultValue.GetString();
	}
	else
	{
		std::string errMsg = name + " must be a string value";
		throw CTypesParseError(errMsg);
	}
}

int64_t safeGetInt64(
	const rapidjson::Value &val,
	const std::string &name,
	const rapidjson::Value &defaultValue = rapidjson::Value())
{
	auto res = val.FindMember(name.c_str());
	if (res != val.MemberEnd() && res->value.IsInt64())
	{
		return res->value.GetInt64();
	}
	else if (defaultValue.IsInt64())
	{
		return defaultValue.GetInt64();
	}
	else
	{
		std::string errMsg = name + " must be an int value";
		throw CTypesParseError(errMsg);
	}
}

bool safeGetBool(
	const rapidjson::Value &val,
	const std::string &name,
	const rapidjson::Value &defaultValue = rapidjson::Value())
{
	auto res = val.FindMember(name.c_str());
	if (res != val.MemberEnd() && res->value.IsBool())
	{
		return res->value.GetBool();
	}
	else if (defaultValue.IsBool())
	{
		return defaultValue.GetBool();
	}
	else
	{
		std::string errMsg = name + " must be a bool value";
		throw CTypesParseError(errMsg);
	}
}

/**
* @brief Constructs a new parser.
*/
JSONCTypesParser::JSONCTypesParser() = default;

/**
* @brief Constructs a new parser.
*
* @param defaultBitWidth BitWidth used for types that are not in typeWidths.
*/
JSONCTypesParser::JSONCTypesParser(unsigned defaultBitWidth):
	CTypesParser(defaultBitWidth) {}

/**
* @brief Gets additional info about failure in parsing and throws exception.
*
* @throw CTypesParseError
*/
void JSONCTypesParser::handleParsingFailure(const rapidjson::ParseResult &err) const
{
	std::ostringstream errMsg;
	errMsg << "Failed to parse JSON.\n";
	errMsg << "Error (offset " << err.Offset() << "): " << GetParseError_En(err.Code());
	errMsg << std::endl;

	throw CTypesParseError(errMsg.str());
}

/**
* @brief Parses C-types from JSON representation.
*
* @param[in] stream Input stream containing C-types in JSON.
* @param[in] typeWidths C-types' bit widths.
* @param[in] callConvention Function call convention.
*
* @return Module filled with C-types information.
*
* @throw CTypesParseError when the input JSON is invalid.
*
* Call convention is used when function itself does not specify its call convention.
*/
std::unique_ptr<ctypes::Module> JSONCTypesParser::parse(
	std::istream &stream,
	const CTypesParser::TypeWidths &typeWidths,
	const ctypes::CallConvention &callConvention)
{
	auto module = std::make_unique<ctypes::Module>(context);
	parseInto(stream, module, typeWidths, callConvention);
	return module;
}

/**
* @brief Parses C-types from JSON representation to user's module.
*
* @param[in] stream Input stream containing C-types in JSON.
* @param[in] module User's module.
* @param[in] typeWidths C-types' bit widths.
* @param[in] callConvention Function call convention.
*
* @throw CTypesParseError when the input JSON is invalid.
*
* Call convention is used when function itself does not specify its call
* convention.
*/
void JSONCTypesParser::parseInto(
	std::istream &stream,
	std::unique_ptr<ctypes::Module> &module,
	const CTypesParser::TypeWidths &typeWidths,
	const ctypes::CallConvention &callConvention)
{
	assert(module && "violated precondition - module cannot be null");

	context = module->getContext();
	defaultCallConv = callConvention;
	this->typeWidths = typeWidths;

	std::string buffer = loadJson(stream);
	// The rapidjson library requires a null-terminated string.
	buffer.push_back('\0');
	auto root = parseJson(&buffer[0]);
	parseJsonIntoModule(root, module);
}

/**
* @brief Loads JSON from the input stream to a string.
*/
std::string JSONCTypesParser::loadJson(std::istream &stream) const
{
	std::ostringstream sstr;
	sstr << stream.rdbuf();
	if (!stream.good())
	{
		throw CTypesParseError("Failed to read from the input stream.");
	}
	return sstr.str();
}

/**
* @brief Parses JSON in-situ.
*
* @throw CTypesParseError when the input JSON is invalid.
*/
std::unique_ptr<rapidjson::Document> JSONCTypesParser::parseJson(char *buffer) const
{
	auto root = std::make_unique<rapidjson::Document>();
	rapidjson::ParseResult res = root->ParseInsitu(buffer);
	if (!res)
	{
		handleParsingFailure(res);
	}
	return root;
}

/**
* @brief Parses C-types from JSON representation.
*
* @param root Whole JSON containing functions and types.
* @param module Container for parsed functions.
*
* Call convention is used when function itself does not specify its call convention.
*/
void JSONCTypesParser::parseJsonIntoModule(
	const std::unique_ptr<rapidjson::Document> &root,
	std::unique_ptr<ctypes::Module> &module)
{
	// We need a clean context for each JSON because types may have different keys.
	parserContext.clear();
	const rapidjson::Value &functions = safeGetObject(*root, JSON_functions);

	addTypesToMap(safeGetObject(*root, JSON_types));
	for (auto i = functions.MemberBegin(), e = functions.MemberEnd(); i != e; ++i)
	{
		auto newFunction = getOrParseFunction(i->name.GetString(), i->value);
		module->addFunction(newFunction);
	}
}

/**
* @brief Stores @c types part of JSON to map.
*
* We need fast random access to types, but @c RapidJSON method @c FindMember
* uses linear search.
*/
void JSONCTypesParser::addTypesToMap(const rapidjson::Value &types)
{
	// We need an empty map for each JSON.
	typesMap.clear();
	for (auto i = types.MemberBegin(), e = types.MemberEnd(); i != e; ++i)
	{
		typesMap.emplace(i->name.GetString(), i);
	}
}

/**
* @brief Returns function from context, if already stored, otherwise parse new one.
*
* @param funcName Name of function.
* @param jsonFunction JSON representation of function.
*/
std::shared_ptr<ctypes::Function> JSONCTypesParser::getOrParseFunction(
	const std::string &funcName,
	const rapidjson::Value &jsonFunction)
{
	auto cachedFunc = context->getFunctionWithName(funcName);
	return cachedFunc ? cachedFunc :
		parseFunction(jsonFunction, funcName);
}

/**
* @brief Parses C function from JSON representation.
*
* @param function JSON object representing one function.
* @param fName Name of new function.
*
* Call convention is used when function itself does not specify its call
* convention. This function should be called from getOrParseFunction(), where
* function name is parsed from JSON.
*/
std::shared_ptr<ctypes::Function> JSONCTypesParser::parseFunction(
	const rapidjson::Value &function,
	const std::string &fName)
{
	std::string retTypeKey = safeGetString(function, JSON_ret_type);
	std::shared_ptr<ctypes::Type> returnType = getOrParseType(retTypeKey);

	auto parameters = parseParameters(safeGetArray(function, JSON_params));

	auto varArgness = parseVarArgness(function);
	ctypes::CallConvention callConv(parseCallConv(function));

	auto newFunction = ctypes::Function::create(
		context, fName, returnType, parameters, callConv, varArgness);

	std::string fDecl = safeGetString(function, JSON_decl);
	newFunction->setDeclaration(ctypes::FunctionDeclaration(fDecl));

	std::string fHeader = safeGetString(function, JSON_header);
	newFunction->setHeaderFile(ctypes::HeaderFile(fHeader));

	return newFunction;
}

/**
* @brief Parses function parameters from JSON representation.
*
* @param jsonParams JSON object representing function parameters.
*/
ctypes::Function::Parameters JSONCTypesParser::parseParameters(
	const rapidjson::Value &jsonParams)
{
	ctypes::Function::Parameters parameters;

	for (auto i = jsonParams.Begin(), e = jsonParams.End(); i != e; ++i)
	{
		parameters.emplace_back(parseParameter(*i));
	}
	return parameters;
}

/**
* @brief Parses function parameter from JSON representation.
*
* @param param JSON object representing one function parameter.
*/
ctypes::Parameter JSONCTypesParser::parseParameter(
	const rapidjson::Value &param)
{
	static const rapidjson::Value emptyAnnotation("");
	std::string annotationStr = safeGetString(param, JSON_annotations, emptyAnnotation);
	ctypes::Parameter::Annotations annots;

	if (!annotationStr.empty())
	{
		annots = parseAnnotations(annotationStr);
	}

	std::string paramName = safeGetString(param, JSON_name);
	std::string paramTypeKey = safeGetString(param, JSON_type);

	return ctypes::Parameter(paramName, getOrParseType(paramTypeKey), annots);
}

/**
* @brief Returns @c IsVarArg when @c function has varArg attribute
*        set to @c true, @c IsNotVarArg otherwise.
*/
ctypes::FunctionType::VarArgness JSONCTypesParser::parseVarArgness(
	const rapidjson::Value &function) const
{
	static const rapidjson::Value defaultVarArg(rapidjson::Type::kFalseType);
	return safeGetBool(function, JSON_vararg, defaultVarArg) ?
		ctypes::FunctionType::VarArgness::IsVarArg :
		ctypes::FunctionType::VarArgness::IsNotVarArg;
}

/**
* @brief Returns @c call_conv attribute's value if exists, default otherwise.
*/
std::string JSONCTypesParser::parseCallConv(
	const rapidjson::Value &function) const
{
	const std::string cc = std::string(defaultCallConv);
	return safeGetString(
			function,
			JSON_call_conv,
			rapidjson::Value(rapidjson::StringRef(cc.c_str()))
		);
}

/**
* @brief Parses parameter's annotations.
*
* Distinguish @c in, @c out and @c inout annotations, they all may be optional.
*/
ctypes::Parameter::Annotations JSONCTypesParser::parseAnnotations(
	const std::string &annot) const
{
	ctypes::Parameter::Annotations annotations;
	if (tl_cpputils::contains(annot, "Inout"))
	{
		annotations.insert(ctypes::AnnotationInOut::create(context, annot));
	}
	else if (tl_cpputils::containsCaseInsensitive(annot, "out"))
	{
		annotations.insert(ctypes::AnnotationOut::create(context, annot));
	}
	else if (tl_cpputils::containsCaseInsensitive(annot, "in"))
	{
		annotations.insert(ctypes::AnnotationIn::create(context, annot));
	}

	if (tl_cpputils::contains(annot, "opt"))
	{
		annotations.insert(ctypes::AnnotationOptional::create(context, annot));
	}
	return annotations;
}

/**
* @brief Parses function type from JSON representation.
*
* @param jsonFuncType JSON object representing one function type.
*/
std::shared_ptr<ctypes::FunctionType> JSONCTypesParser::parseFunctionType(
	const rapidjson::Value &jsonFuncType)
{
	auto retType = getOrParseType(safeGetString(jsonFuncType, JSON_ret_type));
	auto params = parseFunctionTypeParameters(
		safeGetArray(jsonFuncType, JSON_params));
	auto varArgness = parseVarArgness(jsonFuncType);
	ctypes::CallConvention callConv(parseCallConv(jsonFuncType));
	return ctypes::FunctionType::create(context, retType, params, callConv, varArgness);
}

/**
* @brief Parses function type parameters from JSON representation.
*
* @param jsonParams JSON object representing function parameters.
*
* Ignores parameters' names.
*/
ctypes::FunctionType::Parameters JSONCTypesParser::parseFunctionTypeParameters(
	const rapidjson::Value &jsonParams)
{
	ctypes::FunctionType::Parameters params;
	for (auto i = jsonParams.Begin(), e = jsonParams.End(); i != e; ++i)
	{
		params.emplace_back(getOrParseType(safeGetString(*i, JSON_type)));
	}
	return params;
}

/**
* @brief Returns C type from parser's context or parses it from JSON representation.
*
* @param typeKey Key of type stored in JSON types.
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::getOrParseType(
	const std::string &typeKey)
{
	auto cachedType = tl_cpputils::mapGetValueOrDefault(parserContext, typeKey);
	return cachedType ? cachedType : parseType(typeKey);
}

/**
* @brief Parses C-type from JSON representation.
*
* @param typeKey Key of type stored in JSON types.
*
* Parsed types are stored in @c parserContext, so you should use @c
* getOrParseType() method.
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseType(
	const std::string &typeKey)
{
	const rapidjson::Value &jsonType = tl_cpputils::mapGetValueOrDefault(typesMap, typeKey)->value;
	std::string typeOfType = safeGetString(jsonType, JSON_type);
	std::shared_ptr<ctypes::Type> parsedType;

	// To make the parsing as fast as possible, the types should be ordered by
	// the number of their occurrences in our JSONS.
	if (typeOfType == JSON_typedef)
	{
		parsedType = parseTypedefedType(jsonType);
	}
	else if (typeOfType == JSON_pointer)
	{
		parsedType = parsePointer(jsonType);
	}
	else if (typeOfType == JSON_integral_type)
	{
		parsedType = parseIntegralType(jsonType);
	}
	else if (typeOfType == JSON_structure)
	{
		parsedType = parseStruct(jsonType);
	}
	else if (typeOfType == JSON_void)
	{
		parsedType = ctypes::VoidType::create();
	}
	else if (typeOfType == JSON_function_type)
	{
		parsedType = parseFunctionType(jsonType);
	}
	else if (typeOfType == JSON_array)
	{
		parsedType = parseArray(jsonType);
	}
	else if (typeOfType == JSON_floating_point_type)
	{
		parsedType = parseFloatingPointType(jsonType);
	}
	else if (typeOfType == JSON_enum)
	{
		parsedType = parseEnum(jsonType);
	}
	else if (typeOfType == JSON_union)
	{
		parsedType = parseUnion(jsonType);
	}
	else if (typeOfType == JSON_qualifier)
	{
		parsedType = getOrParseType(safeGetString(jsonType, JSON_modified_type));
	}
	else
	{
		parsedType = ctypes::UnknownType::create();
	}

	parserContext.emplace(typeKey, parsedType);
	return parsedType;
}

/**
* @brief Parses integral type from JSON representation.
*
* @param type JSON object representing integral type.
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseIntegralType(
	const rapidjson::Value &type)
{
	return getOrParseNamedType(type,
		[&type, this](const std::string &typeName)
		{
			auto bitWidth = safeGetInt64(
				type,
				JSON_bit_width,
				rapidjson::Value(this->getIntegralTypeBitWidth(typeName))
			);
			auto sign = tl_cpputils::contains(typeName, "unsigned") ?
				ctypes::IntegralType::Signess::Unsigned :
				ctypes::IntegralType::Signess::Signed;
			return ctypes::IntegralType::create(context, typeName, bitWidth, sign);
		}
	);
}

/**
* @brief Parses floating point type from JSON representation.
*
* @param type JSON object representing floating point type.
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseFloatingPointType(
	const rapidjson::Value &type)
{
	return getOrParseNamedType(type,
		[&type, this](const std::string &typeName)
		{
			auto bitWidth = safeGetInt64(
				type,
				JSON_bit_width,
				rapidjson::Value(this->getBitWidthOrDefault(typeName))
			);
			return ctypes::FloatingPointType::create(context, typeName, bitWidth);
		}
	);
}

/**
* @brief Returns bit width stored in @c typeWidths for integral type.
*
* Returns default bit width if not found.
*/
unsigned JSONCTypesParser::getIntegralTypeBitWidth(const std::string &type) const
{
	std::string toSearch;

	static const std::regex reChar("\\bchar\\b");
	static const std::regex reShort("\\bshort\\b");
	static const std::regex reLongLong("\\blong long\\b");
	static const std::regex reLong("\\blong\\b");
	static const std::regex reInt("\\bint\\b");
	static const std::regex reUnSigned("^(un)?signed$");

	// Ignore type's sign, use only core info about bit width to search in map
	// - smaller map.
	// Order of getting core type is important - int should be last - short int
	// should be treated as short, same long. Long long differs from long.
	if (std::regex_search(type, reChar))
	{
		toSearch = "char";
	}
	else if (std::regex_search(type, reShort))
	{
		toSearch = "short";
	}
	else if (std::regex_search(type, reLongLong))
	{
		toSearch = "long long";
	}
	else if (std::regex_search(type, reLong))
	{
		toSearch = "long";
	}
	else if (std::regex_search(type, reInt))
	{
		toSearch = "int";
	}
	else if (std::regex_search(type, reUnSigned))
	{
		toSearch = "int";
	}
	else
	{
		toSearch = type;
	}
	return getBitWidthOrDefault(toSearch);
}

/**
* @brief Returns bit width stored in @c typeWidths for type, default if not found.
*/
unsigned JSONCTypesParser::getBitWidthOrDefault(const std::string &typeName) const
{
	return tl_cpputils::mapGetValueOrDefault(typeWidths, typeName, defaultBitWidth);
}

/**
* @brief Parses typedef from JSON representation.
*
* @param jsonTypedef JSON object representing typedefed type.
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseTypedefedType(
	const rapidjson::Value &jsonTypedef)
{
	return getOrParseNamedType(jsonTypedef,
		[&jsonTypedef, this](const std::string &typeName) -> std::shared_ptr<ctypes::Type>
		{
			static std::vector<std::string> previousTypedefs;
			std::shared_ptr<ctypes::Type> aliasedType;

			if (tl_cpputils::hasItem(previousTypedefs, typeName))
			{
				return ctypes::UnknownType::create();
			}
			else
			{
				previousTypedefs.emplace_back(typeName);
				std::string aliasedTypeKey = safeGetString(
					jsonTypedef, JSON_typedefed_type);
				aliasedType = (aliasedTypeKey == JSON_unknown_type) ?
					ctypes::UnknownType::create() :
					this->getOrParseType(aliasedTypeKey);
				if (typeName == previousTypedefs[0])
				{   // returned from all nested types
					previousTypedefs.clear();
				}
			}
			return ctypes::TypedefedType::create(context, typeName, aliasedType);
		}
	);
}

/**
* @brief Returns named type from context, if already stored, otherwise parse new type.
*
* @param jsonType Type to get/parse.
* @param parseType Function to parse specific type (typedef, struct...).
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::getOrParseNamedType(
	const rapidjson::Value &jsonType,
	const std::function<
		std::shared_ptr<ctypes::Type> (const std::string &typeName)
	> &parseType
)
{
	auto typeName = safeGetString(jsonType, JSON_name);
	auto cachedType = context->getNamedType(typeName);
	return cachedType ? cachedType : parseType(typeName);
}
/**
* @brief Parses struct from JSON representation.
*
* @param jsonStruct JSON object representing struct.
*
* A new struct is created at the beginning (like a forward declaration) and its
* members are set subsequently. This prevents parser from infinite looping, as
* in the following case:
* @code
* struct x { struct x *next; };
* @endcode
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseStruct(
	const rapidjson::Value &jsonStruct)
{
	return getOrParseNamedType(jsonStruct,
		[&jsonStruct, this](const std::string &typeName)
		{
			auto newStruct = ctypes::StructType::create(context, typeName, {});
			newStruct->setMembers(
				this->parseMembers(safeGetArray(jsonStruct, JSON_members))
			);
			return newStruct;
		}
	);
}

/**
* @brief Parses union from JSON representation.
*
* @param jsonUnion JSON object representing union.
*
* A new union is created at the beginning (like a forward declaration) and its
* members are set subsequently. This prevents parser from infinite looping, as
* in the following case:
* @code
* union x { union x *next; };
* @endcode
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseUnion(
	const rapidjson::Value &jsonUnion)
{
	return getOrParseNamedType(jsonUnion,
		[&jsonUnion, this](const std::string &typeName)
		{
			auto newUnion = ctypes::UnionType::create(context, typeName, {});
			newUnion->setMembers(
				this->parseMembers(safeGetArray(jsonUnion, JSON_members))
			);
			return newUnion;
		}
	);
}

/**
* @brief Parses composite type's members.
*
* @param jsonMembers JSON object representing composite type's members.
*/
ctypes::CompositeType::Members JSONCTypesParser::parseMembers(
	const rapidjson::Value &jsonMembers)
{
	ctypes::CompositeType::Members members;
	for (auto i = jsonMembers.Begin(), e = jsonMembers.End(); i != e; ++i)
	{
		std::string memberTypeKey = safeGetString(*i, JSON_type);
		std::string memberName = safeGetString(*i, JSON_name);
		members.emplace_back(memberName, getOrParseType(memberTypeKey));
	}
	return members;
}

/**
* @brief Parses pointer from JSON representation.
*
* @param jsonPointer JSON object representing pointer.
*/
std::shared_ptr<ctypes::PointerType> JSONCTypesParser::parsePointer(
	const rapidjson::Value &jsonPointer)
{
	std::string pointedTypeKey = safeGetString(jsonPointer, JSON_pointed_type);
	auto pointedType = getOrParseType(pointedTypeKey);
	return ctypes::PointerType::create(context, pointedType, getBitWidthOrDefault("*"));
}

/**
* @brief Parses array from JSON representation.
*
* @param jsonArray JSON object representing array.
*/
std::shared_ptr<ctypes::ArrayType> JSONCTypesParser::parseArray(
	const rapidjson::Value &jsonArray)
{
	std::string elementTypeKey = safeGetString(jsonArray, JSON_array_element);
	auto elementType = getOrParseType(elementTypeKey);

	auto dimensions = parseArrayDimensions(safeGetArray(jsonArray, JSON_array_dimensions));
	return ctypes::ArrayType::create(context, elementType, dimensions);
}

/**
* @brief Parses array dimensions from JSON representation.
*
* @param jsonDimensions JSON array containing dimensions.
*/
ctypes::ArrayType::Dimensions JSONCTypesParser::parseArrayDimensions(
	const rapidjson::Value &jsonDimensions) const
{
	ctypes::ArrayType::Dimensions dimensions;

	for (auto i = jsonDimensions.Begin(), e = jsonDimensions.End(); i != e; ++i)
	{
		dimensions.emplace_back(i->IsInt() ? i->GetInt() : ctypes::ArrayType::UNKNOWN_DIMENSION);
	}
	return dimensions;
}

/**
* @brief Parses enum type from JSON representation.
*
* @param jsonEnum JSON object representing enum.
*/
std::shared_ptr<ctypes::Type> JSONCTypesParser::parseEnum(
	const rapidjson::Value &jsonEnum)
{
	return getOrParseNamedType(jsonEnum,
		[&jsonEnum, this](const std::string &typeName)
		{
			auto values = this->parseEnumItems(safeGetArray(jsonEnum, JSON_enum_items));
			return ctypes::EnumType::create(context, typeName, values);
		}
	);
}

/**
* @brief Parses enum values from JSON representation.
*
* @param jsonEnumItems JSON object representing enum values.
*/
ctypes::EnumType::Values JSONCTypesParser::parseEnumItems(
	const rapidjson::Value &jsonEnumItems) const
{
	static const auto defaultValue = rapidjson::Value(ctypes::EnumType::DEFAULT_VALUE);

	ctypes::EnumType::Values values;
	for (auto i = jsonEnumItems.Begin(), e = jsonEnumItems.End(); i != e; ++i)
	{
		values.emplace_back(
			safeGetString(*i, JSON_name),
			safeGetInt64(*i, JSON_enum_value, defaultValue)
		);
	}
	return values;
}

} // namespace ctypesparser
