/**
 * @file src/serdes/function.cpp
 * @brief Function (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/function.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/basic_block.h"
#include "retdec/serdes/calling_convention.h"
#include "retdec/serdes/function.h"
#include "retdec/serdes/object.h"
#include "retdec/serdes/storage.h"
#include "retdec/serdes/type.h"
#include "retdec/serdes/std.h"

#include "serdes/utils.h"

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
	"userDefined",
	"staticallyLinked",
	"dynamicallyLinked",
	"syscall",
	"idiom"
};

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::Function& f)
{
	Json::Value fnc;

	fnc[JSON_name]      = f.getName();
	fnc[JSON_cc]        = serdes::serialize(f.callingConvention);
	fnc[JSON_fncType]   = fncTypes[ static_cast<size_t>(f.getLinkType()) ];

	if (!f.getRealName().empty()) fnc[JSON_realName] = f.getRealName();
	if (!f.getDemangledName().empty()) fnc[JSON_demangledName] = f.getDemangledName();
	if (!f.getComment().empty()) fnc[JSON_comment] = f.getComment();
	if (!f.getDeclarationString().empty()) fnc[JSON_decStr] = f.getDeclarationString();
	if (!f.getWrappedFunctionName().empty()) fnc[JSON_wrappedName] = f.getWrappedFunctionName();
	if (!f.getSourceFileName().empty()) fnc[JSON_srcFileName] = f.getSourceFileName();
	if (f.getStart().isDefined()) fnc[JSON_startAddr] = serdes::serialize(f.getStart());
	if (f.getEnd().isDefined()) fnc[JSON_endAddr] = serdes::serialize(f.getEnd());
	if (f.getStartLine().isDefined()) fnc[JSON_startLine] = serdes::serialize(f.getStartLine());
	if (f.getEndLine().isDefined()) fnc[JSON_endLine] = serdes::serialize(f.getEndLine());
	if (f.isFromDebug()) fnc[JSON_fromDebug] = f.isFromDebug();
	if (f.isConstructor()) fnc[JSON_isConstructor] = f.isConstructor();
	if (f.isDestructor()) fnc[JSON_isDestructor] = f.isDestructor();
	if (f.isVirtual()) fnc[JSON_isVirtual] = f.isVirtual();
	if (f.isExported()) fnc[JSON_isExported] = f.isExported();
	if (f.isVariadic()) fnc[JSON_isVariadic] = f.isVariadic();
	if (f.isThumb()) fnc[JSON_isThumb] = f.isThumb();

	if (!f.locals.empty()) fnc[JSON_locals] = serdes::serialize(f.locals);
	if (!f.parameters.empty()) fnc[JSON_parameters] = serdes::serialize(f.parameters);
	if (f.returnStorage.isDefined()) fnc[JSON_returnStorage] = serdes::serialize(f.returnStorage);
	if (f.frameBaseStorage.isDefined()) fnc[JSON_fbStorage] = serdes::serialize(f.frameBaseStorage);
	if (f.returnType.isDefined()) fnc[JSON_returnType] = serdes::serialize(f.returnType);
	if (!f.basicBlocks.empty()) fnc[JSON_basicBlocks] = serdes::serialize(f.basicBlocks);

	fnc[JSON_usedCrypto] = serdes::serialize(f.usedCryptoConstants);

	return fnc;
}

void deserialize(const Json::Value& val, common::Function& f)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	f.setName(safeGetString(val, JSON_name));
	f.setRealName( safeGetString(val, JSON_realName) );
	f.setDemangledName( safeGetString(val, JSON_demangledName) );
	f.setComment( safeGetString(val, JSON_comment) );
	f.setDeclarationString( safeGetString(val, JSON_decStr) );
	f.setWrappedFunctionName( safeGetString(val, JSON_wrappedName) );
	f.setSourceFileName( safeGetString(val, JSON_srcFileName) );
	f.setIsFromDebug( safeGetBool(val, JSON_fromDebug) );
	f.setIsConstructor( safeGetBool(val, JSON_isConstructor) );
	f.setIsDestructor( safeGetBool(val, JSON_isDestructor) );
	f.setIsVirtual( safeGetBool(val, JSON_isVirtual) );
	f.setIsExported( safeGetBool(val, JSON_isExported) );
	f.setIsVariadic( safeGetBool(val, JSON_isVariadic) );
	f.setIsThumb( safeGetBool(val, JSON_isThumb) );

	common::Address s;
	serdes::deserialize(val[JSON_startAddr], s);
	f.setStart(s);

	common::Address e;
	serdes::deserialize(val[JSON_endAddr], e);
	f.setEnd(e);

	common::Address sl;
	serdes::deserialize(val[JSON_startLine], sl);
	f.setStartLine(sl);

	common::Address el;
	serdes::deserialize(val[JSON_endLine], el);
	f.setEndLine(el);

	serdes::deserialize(val[JSON_cc], f.callingConvention);
	serdes::deserialize(val[JSON_returnStorage], f.returnStorage);
	serdes::deserialize(val[JSON_fbStorage], f.frameBaseStorage);
	serdes::deserialize(val[JSON_returnType], f.returnType);
	serdes::deserialize(val[JSON_locals], f.locals);
	serdes::deserialize(val[JSON_parameters], f.parameters);
	serdes::deserialize(val[JSON_usedCrypto], f.usedCryptoConstants);
	serdes::deserialize(val[JSON_basicBlocks], f.basicBlocks);

	std::string enumStr = safeGetString(val, JSON_fncType);
	auto it = std::find(fncTypes.begin(), fncTypes.end(), enumStr);
	if (it != fncTypes.end())
	{
		f.setLinkType(static_cast<common::Function::eLinkType>(
				std::distance(fncTypes.begin(), it)));
	}
}

} // namespace serdes
} // namespace retdec
