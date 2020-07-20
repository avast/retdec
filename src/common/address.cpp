/**
 * @file src/common/address.cpp
 * @brief Address, address pair and other derived class representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <climits>
#include <cstdio>
#include <vector>

#include "retdec/common/address.h"
#include "retdec/utils/conversion.h"

namespace retdec {
namespace common {

//
//=============================================================================
//  Address
//=============================================================================
//

const uint64_t Address::Undefined = ULLONG_MAX;

Address::Address() :
		address(Address::Undefined)
{
}

Address::Address(uint64_t a) :
		address(a)
{
}

Address::Address(const std::string &a) :
		address(Address::Undefined)
{
	try
	{
		size_t idx = 0;
		unsigned long long ull = std::stoull(a, &idx, 0);
		if (idx == a.size()) // no leftovers
		{
			address = ull;
		}
	}
	catch (const std::invalid_argument&)
	{
		// nothing -> undefined value.
	}
}

Address::operator uint64_t() const
{
	return address;
}

Address::operator bool() const
{
	return isDefined() && address;
}

Address& Address::operator++()
{
	if (isDefined())
		address++;

	return *this;
}
Address Address::operator++(int)
{
	if (isDefined())
		address++;

	return *this;
}

Address& Address::operator--()
{
	if (isDefined())
		address--;

	return *this;
}
Address Address::operator--(int)
{
	if (isDefined())
		address--;

	return *this;
}

Address& Address::operator+=(const Address& rhs)
{
	address += rhs;
	return *this;
}
Address& Address::operator-=(const Address& rhs)
{
	address -= rhs;
	return *this;
}
Address& Address::operator|=(const Address& rhs)
{
	address |= rhs;
	return *this;
}

bool Address::isUndefined() const
{
	return address == Address::Undefined;
}

bool Address::isDefined() const
{
	return !isUndefined();
}

uint64_t Address::getValue() const
{
	assert( isDefined() );
	return address;
}

std::string Address::toHexString() const
{
	assert(isDefined());
	return utils::intToHexString(address);
}

std::string Address::toHexPrefixString() const
{
	assert(isDefined());

	return "0x" + toHexString();
}

std::ostream& operator<<(std::ostream &out, const Address &a)
{
	if (a.isDefined())
		return out << a.toHexPrefixString();
	else
		return out << "UNDEFINED";
}

//
//=============================================================================
//  AddressRange
//=============================================================================
//

AddressRange stringToAddrRange(const std::string &r)
{
	AddressRange ar;

	unsigned long long f = 0, s = 0;
	int ret = std::sscanf(r.c_str(), "0x%llx-0x%llx", &f, &s);
	if (ret == 2 && f <= s)
	{
		ar.setStartEnd(f, s);
	}

	return ar;
}

} // namespace common
} // namespace retdec
