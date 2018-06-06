/**
 * @file src/config/functions.cpp
 * @brief Decompilation configuration manipulation: functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/config/functions.h"
#include "retdec/utils/const.h"

using retdec::utils::likeConstVersion;

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
const std::string JSON_returnType    = "returnType";
const std::string JSON_parameters    = "parameters";
const std::string JSON_locals        = "locals";
const std::string JSON_srcFileName   = "srcFileName";
const std::string JSON_startLine     = "startLine";
const std::string JSON_endLine       = "endLine";
const std::string JSON_fixed         = "wasFixed";
const std::string JSON_fromDebug     = "isFromDebug";
const std::string JSON_wrappedName   = "wrappedFunctionName";
const std::string JSON_isConstructor = "isConstructor";
const std::string JSON_isDestructor  = "isDestructor";
const std::string JSON_isVirtual     = "isVirtual";
const std::string JSON_isExported    = "isExported";
const std::string JSON_isVariadic    = "isVariadic";
const std::string JSON_isThumb       = "isThumb";
const std::string JSON_usedCrypto    = "usedCryptoConstants";

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
namespace config {

//
//=============================================================================
// Function
//=============================================================================
//

Function::Function(const std::string& id) :
		_name(id)
{

}

/**
 * Reads JSON object (associative array) holding function information.
 * @param val JSON object.
 */
Function Function::fromJsonValue(const Json::Value& val)
{
	checkJsonValueIsObject(val, "Function");

	Function ret(safeGetString(val, JSON_name));

	ret.setRealName( safeGetString(val, JSON_realName) );
	ret.setDemangledName( safeGetString(val, JSON_demangledName) );
	ret.setComment( safeGetString(val, JSON_comment) );
	ret.setDeclarationString( safeGetString(val, JSON_decStr) );
	ret.setWrappedFunctionName( safeGetString(val, JSON_wrappedName) );
	ret.setSourceFileName( safeGetString(val, JSON_srcFileName) );
	ret.setStartEnd(
			safeGetAddress(val, JSON_startAddr),
			safeGetAddress(val, JSON_endAddr));
	ret.setStartLine( safeGetAddress(val, JSON_startLine) );
	ret.setEndLine( safeGetAddress(val, JSON_endLine) );
	ret.setIsFixed( safeGetBool(val, JSON_fixed) );
	ret.setIsFromDebug( safeGetBool(val, JSON_fromDebug) );
	ret.setIsConstructor( safeGetBool(val, JSON_isConstructor) );
	ret.setIsDestructor( safeGetBool(val, JSON_isDestructor) );
	ret.setIsVirtual( safeGetBool(val, JSON_isVirtual) );
	ret.setIsExported( safeGetBool(val, JSON_isExported) );
	ret.setIsVariadic( safeGetBool(val, JSON_isVariadic) );
	ret.setIsThumb( safeGetBool(val, JSON_isThumb) );

	ret.callingConvention.readJsonValue( val[JSON_cc] );
	ret.returnStorage.readJsonValue( val[JSON_returnStorage] );
	ret.returnType.readJsonValue( val[JSON_returnType] );
	ret.parameters.readJsonValue( val[JSON_parameters] );
	ret.locals.readJsonValue( val[JSON_locals] );

	readJsonStringValueVisit(ret.usedCryptoConstants, val[JSON_usedCrypto]);

	std::string enumStr = safeGetString(val, JSON_fncType);
	auto it = std::find(fncTypes.begin(), fncTypes.end(), enumStr);
	if (it != fncTypes.end())
	{
		ret._linkType = static_cast<eLinkType>( std::distance(fncTypes.begin(), it) );
	}

	return ret;
}

/**
 * Returns JSON object (associative array) holding function information.
 * @return JSON object.
 */
Json::Value Function::getJsonValue() const
{
	Json::Value fnc;

	fnc[JSON_name]      = getName();
	fnc[JSON_cc]        = callingConvention.getJsonValue();
	fnc[JSON_fncType]   = fncTypes[ static_cast<size_t>(_linkType) ];

	if (!getRealName().empty()) fnc[JSON_realName] = getRealName();
	if (!getDemangledName().empty()) fnc[JSON_demangledName] = getDemangledName();
	if (!getComment().empty()) fnc[JSON_comment] = getComment();
	if (!getDeclarationString().empty()) fnc[JSON_decStr] = getDeclarationString();
	if (!getWrappedFunctionName().empty()) fnc[JSON_wrappedName] = getWrappedFunctionName();
	if (!getSourceFileName().empty()) fnc[JSON_srcFileName] = getSourceFileName();
	if (getStart().isDefined()) fnc[JSON_startAddr] = toJsonValue(getStart());
	if (getEnd().isDefined()) fnc[JSON_endAddr] = toJsonValue(getEnd());
	if (getStartLine().isDefined()) fnc[JSON_startLine] = toJsonValue(getStartLine());
	if (getEndLine().isDefined()) fnc[JSON_endLine] = toJsonValue(getEndLine());
	if (isFixed()) fnc[JSON_fixed] = isFixed();
	if (isFromDebug()) fnc[JSON_fromDebug] = isFromDebug();
	if (isConstructor()) fnc[JSON_isConstructor] = isConstructor();
	if (isDestructor()) fnc[JSON_isDestructor] = isDestructor();
	if (isVirtual()) fnc[JSON_isVirtual] = isVirtual();
	if (isExported()) fnc[JSON_isExported] = isExported();
	if (isVariadic()) fnc[JSON_isVariadic] = isVariadic();
	if (isThumb()) fnc[JSON_isThumb] = isThumb();

	if (!parameters.empty()) fnc[JSON_parameters] = parameters.getJsonValue();
	if (!locals.empty()) fnc[JSON_locals] = locals.getJsonValue();
	if (returnStorage.isDefined()) fnc[JSON_returnStorage] = returnStorage.getJsonValue();
	if (returnType.isDefined()) fnc[JSON_returnType] = returnType.getJsonValue();

	fnc[JSON_usedCrypto] = getJsonStringValueVisit(usedCryptoConstants);

	return fnc;
}

bool Function::isUserDefined() const       { return _linkType == USER_DEFINED; }
bool Function::isStaticallyLinked() const  { return _linkType == STATICALLY_LINKED; }
bool Function::isDynamicallyLinked() const { return _linkType == DYNAMICALLY_LINKED; }
bool Function::isSyscall() const           { return _linkType == SYSCALL; }
bool Function::isIdiom() const             { return _linkType == IDIOM; }
bool Function::isFixed() const             { return _fixed; }
bool Function::isFromDebug() const         { return _fromDebug; }
bool Function::isConstructor() const       { return _constructor; }
bool Function::isDestructor() const        { return _destructor; }
bool Function::isVirtual() const           { return _virtualFunction; }
bool Function::isExported() const          { return _exported; }
bool Function::isVariadic() const          { return _variadic; }
bool Function::isThumb() const             { return _thumb; }

/**
 * Some functions are just wrappers/adapters for other functions.
 * i.e. they just call other function in their body.
 * This member holds name of such called (wrapped) function.
 * If it is empty, then this Function is not wrapper.
 */
bool Function::isWrapper() const           { return !getWrappedFunctionName().empty(); }

void Function::setName(const std::string& n)                { _name = n; }
void Function::setRealName(const std::string& n)            { _realName = n; }
void Function::setDemangledName(const std::string& n)       { _demangledName = n; }
void Function::setComment(const std::string& c)             { _comment = c; }
void Function::addComment(const std::string& c)             { _comment += c; }
void Function::setDeclarationString(const std::string& s)   { _declarationString = s; }
void Function::setSourceFileName(const std::string& n)      { _sourceFileName = n; }
void Function::setWrappedFunctionName(const std::string& n) { _wrapperdFunctionName = n; }
void Function::setStartLine(const retdec::utils::Address& l)       { _startLine = l; }
void Function::setEndLine(const retdec::utils::Address& l)         { _endLine = l; }
void Function::setIsUserDefined()                           { _linkType = USER_DEFINED; }
void Function::setIsStaticallyLinked()                      { _linkType = STATICALLY_LINKED; }
void Function::setIsDynamicallyLinked()                     { _linkType = DYNAMICALLY_LINKED; }
void Function::setIsSyscall()                               { _linkType = SYSCALL; }
void Function::setIsIdiom()                                 { _linkType = IDIOM; }
void Function::setIsFixed(bool f)                           { _fixed = f; }
void Function::setIsFromDebug(bool d)                       { _fromDebug = d; }
void Function::setIsConstructor(bool f)                     { _constructor = f; }
void Function::setIsDestructor(bool f)                      { _destructor = f; }
void Function::setIsVirtual(bool f)                         { _virtualFunction = f; }
void Function::setIsExported(bool f)                        { _exported = f; }
void Function::setIsVariadic(bool f)                        { _variadic = f; }
void Function::setIsThumb(bool f)                           { _thumb = f; }

const std::string& Function::getId() const           { return getName(); }
const std::string& Function::getName() const         { return _name; }
const std::string& Function::getRealName() const     { return _realName; }
std::string Function::getDemangledName() const       { return _demangledName; }
std::string Function::getComment() const             { return _comment; }
std::string Function::getDeclarationString() const   { return _declarationString; }
std::string Function::getSourceFileName() const      { return _sourceFileName; }
std::string Function::getWrappedFunctionName() const { return _wrapperdFunctionName; }
LineNumber Function::getStartLine() const            { return _startLine; }
LineNumber Function::getEndLine() const              { return _endLine; }

/**
 *
 * @param o Other function.
 * @return
 */
bool Function::operator<(const Function& o) const
{
	return _name < o._name;
}
/**
 *
 * @param o Other function to compare this instance with.
 * @return
 */
bool Function::operator==(const Function& o) const
{
	return _name == o._name;
}
/**
 *
 * @param o Other function.
 * @return
 */
bool Function::operator!=(const Function& o) const
{
	return !(*this == o);
}

//
//=============================================================================
// FunctionContainer
//=============================================================================
//

/**
 * @return @c True if container contains a function of the specified name.
 */
bool FunctionContainer::hasFunction(const std::string& name)
{
	return getFunctionByName(name) != nullptr;
}

/**
 * @return Pointer to function or @c nullptr if not found.
 */
Function* FunctionContainer::getFunctionByName(const std::string& name)
{
	return likeConstVersion(this, &FunctionContainer::getFunctionByName, name);
}

/// const version of getFunctionByName().
const Function* FunctionContainer::getFunctionByName(const std::string& name) const
{
	return getElementById(name);
}

/**
 * @return Pointer to function or @c nullptr if not found.
 */
Function* FunctionContainer::getFunctionByStartAddress(const retdec::utils::Address& addr)
{
	for (auto& elem : _data)
	{
		if (addr == elem.second.getStart())
		{
			return &elem.second;
		}
	}

	return nullptr;
}

Function* FunctionContainer::getFunctionByRealName(const std::string& name)
{
	for (auto& elem : _data)
	{
		if (name == elem.second.getRealName())
		{
			return &elem.second;
		}
	}

	return nullptr;
}

} // namespace config
} // namespace retdec
