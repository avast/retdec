/**
* @file src/ctypes/composite_type.cpp
* @brief Implementation of CompositeType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/composite_type.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/member.h"
#include "retdec/utils/container.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new composite type.
*/
CompositeType::CompositeType(const std::string &name, const Members &members):
	Type(name, 0), members(members) {}

/**
* @brief Returns an iterator to the member.
*/
CompositeType::member_iterator CompositeType::member_begin()
{
	return members.begin();
}

/**
* @brief Returns a constant iterator to the member.
*/
CompositeType::const_member_iterator CompositeType::member_begin() const
{
	return members.begin();
}

/**
* @brief Returns an iterator past the last member.
*/
CompositeType::member_iterator CompositeType::member_end()
{
	return members.end();
}

/**
* @brief Returns a constant iterator past the last member.
*/
CompositeType::const_member_iterator CompositeType::member_end() const
{
	return members.end();
}

/**
* @brief Returns the number of members.
*
* Does not matter whether function takes variable number of members or not.
*/
CompositeType::Members::size_type CompositeType::getMemberCount() const
{
	return members.size();
}

/**
* @brief Returns the n-th member.
*
* @par Preconditions
*  - <tt>0 < n <= MemberCount</tt>
*
* The members are numbered starting with @c 1.
*/
const Member &CompositeType::getMember(Members::size_type n) const
{
	return retdec::utils::getNthItem(members, n);
}

/**
* @brief Returns the n-th member's name.
*
* @par Preconditions
*  - <tt>0 < n <= MemberCount</tt>
*
* The members are numbered starting with @c 1.
*/
const std::string &CompositeType::getMemberName(Members::size_type n) const
{
	return getMember(n).getName();
}

/**
* @brief Returns the n-th member's type.
*
* @par Preconditions
*  - <tt>0 < n <= MemberCount</tt>
*
* The members are numbered starting with @c 1.
*/
std::shared_ptr<Type> CompositeType::getMemberType(Members::size_type n) const
{
	return getMember(n).getType();
}

/**
* @brief Sets new members to composite type.
*
* Overwrites old members. Iterators (returned by member_{begin|end}())
* pointing to the old members become invalid.
*/
void CompositeType::setMembers(const Members &members)
{
	this->members = members;
}

} // namespace ctypes
} // namespace retdec
