/**
 * @file src/utils/address.cpp
 * @brief Address, address pair and other derived class representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>
#include <climits>
#include <cstdio>
#include <iostream>
#include <vector>

#include "retdec/utils/address.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace utils {

//
//=============================================================================
//  Address
//=============================================================================
//

const uint64_t Address::getUndef = ULLONG_MAX;

Address::Address() :
		address(Address::getUndef)
{
}

Address::Address(uint64_t a) :
		address(a)
{
}

Address::Address(const std::string &a) :
		address(Address::getUndef)
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
	return address == Address::getUndef;
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

	std::stringstream ss;
	ss << std::hex << address;
	return ss.str();
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

AddressRange::AddressRange()
{
}

AddressRange::AddressRange(Address f) : Range<Address>(f, Address::getUndef)
{
}

AddressRange::AddressRange(Address f, Address s) : Range<Address>(f, s)
{
}

AddressRange::AddressRange(const std::string &r)
{
	unsigned long long f = 0, s = 0;
	int ret = std::sscanf(r.c_str(), "0x%llx-0x%llx", &f, &s);
	if (ret == 2 && f <= s)
	{
		setStartEnd(f, s);
	}
}

bool AddressRange::operator<(const AddressRange &o) const
{
	return getStart() < o.getStart();
}

bool AddressRange::operator==(const AddressRange &o) const
{
	return getStart() == o.getStart() && getEnd() == o.getEnd();
}

bool AddressRange::operator!=(const AddressRange &o) const
{
	return !(*this == o);
}

std::ostream& operator<< (std::ostream &out, const AddressRange &r)
{
	return out << std::hex << "<" << r.getStart() << ", " << r.getEnd() << ")";
}

//
//=============================================================================
//  AddressRangeContainer
//=============================================================================
//

std::ostream& operator<<(std::ostream &out, const AddressRangeContainer &r)
{
	for (auto &rr : r)
		out << rr << std::endl;
	return out;
}

AddressRangeContainer::iterator AddressRangeContainer::begin()
{
	return _ranges.begin();
}

AddressRangeContainer::const_iterator AddressRangeContainer::begin() const
{
	return _ranges.begin();
}

AddressRangeContainer::iterator AddressRangeContainer::end()
{
	return _ranges.end();
}

AddressRangeContainer::const_iterator AddressRangeContainer::end() const
{
	return _ranges.end();
}

std::size_t AddressRangeContainer::size() const
{
	return _ranges.size();
}

bool AddressRangeContainer::empty() const
{
	return _ranges.empty();
}

void AddressRangeContainer::clear()
{
	_ranges.clear();
}

bool AddressRangeContainer::operator==(const AddressRangeContainer &o) const
{
	return _ranges == o._ranges;
}

bool AddressRangeContainer::operator!=(const AddressRangeContainer &o) const
{
	return !(*this == o);
}

std::pair<AddressRangeContainer::iterator,bool> AddressRangeContainer::insert(
		const AddressRange &r)
{
	AddressRangeContainer::iterator betweenOldFirst = _ranges.end();
	AddressRangeContainer::iterator betweenOldLast = _ranges.end();

	auto pos = _ranges.lower_bound(r);
	if (pos != _ranges.begin())
	{
		--pos; // Move to previous no matter what.
	}
	while (pos != _ranges.end() && pos->getStart() <= r.getEnd())
	{
		if (pos->contains(r.getStart())
				|| pos->contains(r.getEnd())
				|| r.contains(pos->getStart())
				|| r.contains(pos->getEnd())
				|| pos->getStart() == r.getEnd()
				|| pos->getEnd() == r.getStart())
		{
			if (betweenOldFirst == _ranges.end())
			{
				betweenOldFirst = pos;
			}
			betweenOldLast = pos;
		}
		++pos;
	}

	// Not overlapping -> insert brand new.
	//
	if (betweenOldFirst == _ranges.end())
	{
		return _ranges.insert(r);
	}
	// Inserted range fully in some existing range -> do not insert anything.
	//
	else if (betweenOldFirst == betweenOldLast && betweenOldFirst->contains(r))
	{
		return {betweenOldFirst, false};
	}
	// Some other combo -> find min/max, remove all old, insert new.
	//
	else
	{
		auto min = std::min(r.getStart(), betweenOldFirst->getStart());
		auto max = std::max(r.getEnd(), betweenOldLast->getEnd());

		_ranges.erase(betweenOldFirst, ++betweenOldLast);
		return _ranges.insert(AddressRange(min, max));
	}
}

std::pair<AddressRangeContainer::iterator,bool> AddressRangeContainer::insert(
		const Address& s,
		const Address& e)
{
	return insert(AddressRange(s, e));
}

const AddressRange* AddressRangeContainer::getRange(Address addr) const
{
	if (_ranges.empty())
	{
		return nullptr;
	}

	// c++14 should allow _ranges.lower_bound(addr)
	auto pos = _ranges.lower_bound(AddressRange(addr, addr));

	if (pos == _ranges.end())
	{
		auto last = _ranges.rbegin();
		return (last->contains(addr)) ? (&(*last)) : (nullptr);
	}

	if (pos != _ranges.begin() && pos->getStart() != addr)
	{
		pos--;
	}

	return pos->contains(addr) ? &(*pos) : nullptr;
}

bool AddressRangeContainer::contains(Address addr) const
{
	return getRange(addr) != nullptr;
}

bool AddressRangeContainer::containsExact(AddressRange r) const
{
	auto* rr = getRange(r.getStart());
	return rr ? *rr == r : false;
}

void AddressRangeContainer::remove(const AddressRange &r)
{
	auto pos = _ranges.lower_bound(r);
	if (pos != _ranges.begin())
	{
		--pos; // Move to previous no matter what.
	}
	while (pos != _ranges.end() && pos->getStart() <= r.getEnd())
	{
		if (pos->contains(r.getStart())
				|| pos->contains(r.getEnd())
				|| r.contains(pos->getStart())
				|| r.contains(pos->getEnd()))
		{
			AddressRange old = *pos;
			pos = _ranges.erase(pos);
			if (old.getStart() < r.getStart())
			{
				_ranges.emplace(old.getStart(), r.getStart());
			}
			if (old.getEnd() > r.getEnd())
			{
				_ranges.emplace(r.getEnd(), old.getEnd());
			}
		}
		else
		{
			++pos;
		}
	}
}

void AddressRangeContainer::remove(const Address& s, const Address& e)
{
	return remove(AddressRange(s, e));
}

} // namespace utils
} // namespace retdec
