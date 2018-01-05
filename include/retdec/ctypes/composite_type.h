/**
* @file include/retdec/ctypes/composite_type.h
* @brief A representation of composite types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_COMPOSITE_TYPE_H
#define RETDEC_CTYPES_COMPOSITE_TYPE_H

#include <memory>
#include <string>
#include <vector>

#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

class Context;
class Member;

/**
* @brief A representation of composite type.
*/
class CompositeType: public Type
{
	public:
		using Members = std::vector<Member>;
		using member_iterator = Members::iterator;
		using const_member_iterator = Members::const_iterator;

	public:
		/// @name Composite type members.
		/// @{
		member_iterator member_begin();
		const_member_iterator member_begin() const;
		member_iterator member_end();
		const_member_iterator member_end() const;

		Members::size_type getMemberCount() const;
		const Member &getMember(Members::size_type n) const;
		const std::string &getMemberName(Members::size_type n) const;
		std::shared_ptr<Type> getMemberType(Members::size_type n) const;

		void setMembers(const Members &members);
		/// @}

	protected:
		CompositeType(const std::string &name, const Members &members);

	protected:
		Members members;
};

} // namespace ctypes
} // namespace retdec

#endif
