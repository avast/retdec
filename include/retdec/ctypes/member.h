/**
* @file include/retdec/ctypes/member.h
* @brief A representation of a struct's and union's members.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_MEMBER_H
#define RETDEC_CTYPES_MEMBER_H

#include <memory>
#include <string>

namespace retdec {
namespace ctypes {

class Type;

/**
* @brief A representation of a composite type (struct, union) member.
*/
class Member
{
	public:
		Member(const std::string &name, const std::shared_ptr<Type> &type);

		const std::string &getName() const;
		std::shared_ptr<Type> getType() const;

		bool operator==(const Member &other) const;
		bool operator!=(const Member &other) const;

	private:
		std::string name;
		std::shared_ptr<Type> type;
};

} // namespace ctypes
} // namespace retdec

#endif
