/**
 * @file src/serdes/function.cpp
 * @brief Function (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/function.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/basic_block.h"
#include "retdec/serdes/calling_convention.h"
#include "retdec/serdes/function.h"
#include "retdec/serdes/object.h"
#include "retdec/serdes/storage.h"
#include "retdec/serdes/type.h"
#include "retdec/serdes/std.h"

#include "retdec/serdes/std.h"

namespace {

const std::string JSON_name          = "name";
const std::string JSON_realName      = "realName";
const std::string JSON_demangledName = "demangledName";
const std::string JSON_comment       = "comment";
const std::string JSON_decStr        = "declarationStr";
const std::string JSON_startAddr     = "startAddr";
const std::string JSON_endAddr       = "endAddr";
const std::string JSON_fncType       = "fncType";
const std::string JSON_cc            = "callingConvention";
const std::string JSON_returnStorage = "returnStorage";
const std::string JSON_fbStorage     = "frameBaseStorage";
const std::string JSON_returnType    = "returnType";
const std::string JSON_parameters    = "parameters";
const std::string JSON_locals        = "locals";
const std::string JSON_srcFileName   = "srcFileName";
const std::string JSON_startLine     = "startLine";
const std::string JSON_endLine       = "endLine";
const std::string JSON_fromDebug     = "isFromDebug";
const std::string JSON_wrappedName   = "wrappedFunctionName";
const std::string JSON_isConstructor = "isConstructor";
const std::string JSON_isDestructor  = "isDestructor";
const std::string JSON_isVirtual     = "isVirtual";
const std::string JSON_isExported    = "isExported";
const std::string JSON_isVariadic    = "isVariadic";
const std::string JSON_isThumb       = "isThumb";
const std::string JSON_usedCrypto    = "usedCryptoConstants";
const std::string JSON_basicBlocks   = "basicBlocks";

std::vector<std::string> fncTypes =
{
	"decompilerDefined",
	"userDefined",
	"staticallyLinked",
	"dynamicallyLinked",
	"syscall",
	"idiom"
};

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::Function& f)
{
	writer.StartObject();

	serializeString(writer, JSON_name, f.getName());
	serialize(writer, JSON_cc, f.callingConvention);
	serializeString(
			writer,
			JSON_fncType,
			fncTypes[static_cast<size_t>(f.getLinkType())]
	);

	serializeString(writer, JSON_realName, f.getRealName());
	serializeString(writer, JSON_demangledName, f.getDemangledName());
	serializeString(writer, JSON_comment, f.getComment());
	serializeString(writer, JSON_decStr, f.getDeclarationString());
	serializeString(writer, JSON_wrappedName, f.getWrappedFunctionName());
	serializeString(writer, JSON_srcFileName, f.getSourceFileName());
	serialize(writer, JSON_startAddr, f.getStart(), f.getStart().isDefined());
	serialize(writer, JSON_endAddr, f.getEnd(), f.getEnd().isDefined());
	serialize(writer, JSON_startLine, f.getStartLine(), f.getStartLine().isDefined());
	serialize(writer, JSON_endLine, f.getEndLine(), f.getEndLine().isDefined());

	serializeBool(writer, JSON_fromDebug, f.isFromDebug(), false);
	serializeBool(writer, JSON_isConstructor, f.isConstructor(), false);
	serializeBool(writer, JSON_isDestructor, f.isDestructor(), false);
	serializeBool(writer, JSON_isVirtual, f.isVirtual(), false);
	serializeBool(writer, JSON_isExported, f.isExported(), false);
	serializeBool(writer, JSON_isVariadic, f.isVariadic(), false);
	serializeBool(writer, JSON_isThumb, f.isThumb(), false);

	serialize(writer, JSON_returnStorage, f.returnStorage, f.returnStorage.isDefined());
	serialize(writer, JSON_fbStorage, f.frameBaseStorage, f.frameBaseStorage.isDefined());
	serialize(writer, JSON_returnType, f.returnType, f.returnType.isDefined());

	serializeContainer(writer, JSON_locals, f.locals);
	serializeContainer(writer, JSON_parameters, f.parameters);
	serializeContainer(writer, JSON_basicBlocks, f.basicBlocks);
	serializeContainer(writer, JSON_usedCrypto, f.usedCryptoConstants);

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::Function)

void deserialize(const rapidjson::Value& val, common::Function& f)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	f.setName( deserializeString(val, JSON_name) );
	f.setRealName( deserializeString(val, JSON_realName) );
	f.setDemangledName( deserializeString(val, JSON_demangledName) );
	f.setComment( deserializeString(val, JSON_comment) );
	f.setDeclarationString( deserializeString(val, JSON_decStr) );
	f.setWrappedFunctionName( deserializeString(val, JSON_wrappedName) );
	f.setSourceFileName( deserializeString(val, JSON_srcFileName) );
	f.setIsFromDebug( deserializeBool(val, JSON_fromDebug) );
	f.setIsConstructor( deserializeBool(val, JSON_isConstructor) );
	f.setIsDestructor( deserializeBool(val, JSON_isDestructor) );
	f.setIsVirtual( deserializeBool(val, JSON_isVirtual) );
	f.setIsExported( deserializeBool(val, JSON_isExported) );
	f.setIsVariadic( deserializeBool(val, JSON_isVariadic) );
	f.setIsThumb( deserializeBool(val, JSON_isThumb) );

	common::Address s;
	deserialize(val, JSON_startAddr, s);
	f.setStart(s);

	common::Address e;
	deserialize(val, JSON_endAddr, e);
	f.setEnd(e);

	common::Address sl;
	deserialize(val, JSON_startLine, sl);
	f.setStartLine(sl);

	common::Address el;
	deserialize(val, JSON_endLine, el);
	f.setEndLine(el);

	deserialize(val, JSON_cc, f.callingConvention);
	deserialize(val, JSON_returnStorage, f.returnStorage);
	deserialize(val, JSON_fbStorage, f.frameBaseStorage);
	deserialize(val, JSON_returnType, f.returnType);

	deserializeContainer(val, JSON_locals, f.locals);
	deserializeContainer(val, JSON_parameters, f.parameters);
	deserializeContainer(val, JSON_usedCrypto, f.usedCryptoConstants);
	deserializeContainer(val, JSON_basicBlocks, f.basicBlocks);

	std::string enumStr = deserializeString(val, JSON_fncType);
	auto it = std::find(fncTypes.begin(), fncTypes.end(), enumStr);
	if (it != fncTypes.end())
	{
		f.setLinkType(static_cast<common::Function::eLinkType>(
				std::distance(fncTypes.begin(), it)));
	}
}

} // namespace serdes
} // namespace retdec
