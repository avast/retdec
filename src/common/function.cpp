/**
 * @file src/common/function.cpp
 * @brief Common function representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>

#include "retdec/common/function.h"

namespace retdec {
namespace common {

//
//=============================================================================
// Function
//=============================================================================
//

Function::Function(const std::string& name) :
		_name(name)
{

}

Function::Function(
		retdec::common::Address start,
		retdec::common::Address end,
		const std::string& name)
		:
		retdec::common::AddressRange(start, end),
		_name(name)
{

}

bool Function::isDecompilerDefined() const { return _linkType == DECOMPILER_DEFINED; }
bool Function::isUserDefined() const       { return _linkType == USER_DEFINED; }
bool Function::isStaticallyLinked() const  { return _linkType == STATICALLY_LINKED; }
bool Function::isDynamicallyLinked() const { return _linkType == DYNAMICALLY_LINKED; }
bool Function::isSyscall() const           { return _linkType == SYSCALL; }
bool Function::isIdiom() const             { return _linkType == IDIOM; }
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
void Function::setStartLine(const retdec::common::Address& l)       { _startLine = l; }
void Function::setEndLine(const retdec::common::Address& l)         { _endLine = l; }
void Function::setIsDecompilerDefined()                     { _linkType = DECOMPILER_DEFINED; }
void Function::setIsUserDefined()                           { _linkType = USER_DEFINED; }
void Function::setIsStaticallyLinked() const                { _linkType = STATICALLY_LINKED; }
void Function::setIsDynamicallyLinked() const               { _linkType = DYNAMICALLY_LINKED; }
void Function::setIsSyscall()                               { _linkType = SYSCALL; }
void Function::setIsIdiom()                                 { _linkType = IDIOM; }
void Function::setIsFromDebug(bool d)                       { _fromDebug = d; }
void Function::setIsConstructor(bool f)                     { _constructor = f; }
void Function::setIsDestructor(bool f)                      { _destructor = f; }
void Function::setIsVirtual(bool f)                         { _virtualFunction = f; }
void Function::setIsExported(bool f)                        { _exported = f; }
void Function::setIsVariadic(bool f)                        { _variadic = f; }
void Function::setIsThumb(bool f)                           { _thumb = f; }
void Function::setLinkType(Function::eLinkType lt)          { _linkType = lt; }

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
Function::eLinkType Function::getLinkType() const    { return _linkType; }

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

const Function* FunctionContainer::getFunctionByName(
		const std::string& name) const
{
	auto fit = find(name);
	return fit != end() ? &(*fit) : nullptr;
}

/**
 * @return Pointer to function or @c nullptr if not found.
 */
const Function* FunctionContainer::getFunctionByStartAddress(
		const retdec::common::Address& addr) const
{
	for (auto& elem : *this)
	{
		if (addr == elem.getStart())
		{
			return &elem;
		}
	}

	return nullptr;
}

const Function* FunctionContainer::getFunctionByRealName(
	const std::string& name) const
{
	for (auto& elem : *this)
	{
		if (name == elem.getRealName())
		{
			return &elem;
		}
	}

	return nullptr;
}

//
//=============================================================================
// FunctionSet
//=============================================================================
//

/**
 * Get function containing the address @p a.
 */
const retdec::common::Function* FunctionSet::getRange(
		const retdec::common::Address& a) const
{
	if (empty())
	{
		return nullptr;
	}

	auto pos = lower_bound(a);

	if (pos == end())
	{
		auto last = rbegin();
		return (last->contains(a)) ? (&(*last)) : (nullptr);
	}

	if (pos != begin() && pos->getStart() != a)
	{
		pos--;
	}

	return pos->contains(a) ? &(*pos) : nullptr;
}

} // namespace common
} // namespace retdec
