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

namespace retdec {
namespace utils {

//
//=============================================================================
//  Address
//=============================================================================
//

const uint64_t Address::getUndef = ULLONG_MAX;

Address::Address() :
		address( Address::getUndef )
{
}

Address::Address(uint64_t a) :
		address(a)
{
}

Address::operator uint64_t() const
{
	return address;
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
		return out << std::hex << a.address;
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
		setStart(f);
		setEnd(s);
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
	return out << std::hex << "<" << r.getStart() << "--" << r.getEnd() << ">";
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
	return ranges.begin();
}

AddressRangeContainer::const_iterator AddressRangeContainer::begin() const
{
	return ranges.begin();
}

AddressRangeContainer::iterator AddressRangeContainer::end()
{
	return ranges.end();
}

AddressRangeContainer::const_iterator AddressRangeContainer::end() const
{
	return ranges.end();
}

std::size_t AddressRangeContainer::size() const
{
	return ranges.size();
}

bool AddressRangeContainer::empty() const
{
	return ranges.empty();
}

void AddressRangeContainer::clear()
{
	ranges.clear();
}

bool AddressRangeContainer::operator==(const AddressRangeContainer &o) const
{
	return ranges == o.ranges;
}

bool AddressRangeContainer::operator!=(const AddressRangeContainer &o) const
{
	return !(*this == o);
}

std::pair<AddressRangeContainer::iterator,bool> AddressRangeContainer::insert(
		const AddressRange &r)
{
	std::vector<AddressRangeContainer::iterator> betweenOld;

	auto pos = ranges.lower_bound(r);
	if (pos != ranges.begin())
	{
		--pos; // Move to previous no matter what.
	}
	while (pos != ranges.end() && pos->getStart() <= (r.getEnd() + 1))
	{
		if (pos->contains(r.getStart())
				|| pos->contains(r.getEnd())
				|| r.contains(pos->getStart())
				|| r.contains(pos->getEnd())
				|| pos->getStart() == (r.getEnd() + 1)
				|| pos->getEnd() == (r.getStart() - 1))
		{
			betweenOld.push_back(pos);
		}
		++pos;
	}

	// Not overlapping -> insert brand new.
	//
	if (betweenOld.empty())
	{
		return ranges.insert(r);
	}
	// Inserted range fully in some existing range -> do not insert anything.
	//
	else if (betweenOld.size() == 1 && (*betweenOld.begin())->contains(r))
	{
		return {*betweenOld.begin(), false};
	}
	// Some other combo -> find min/max, remove all old, insert new.
	//
	else
	{
		auto min = r.getStart();
		auto max = r.getEnd();
		for (auto it : betweenOld)
		{
			min = std::min(min, it->getStart());
			max = std::max(max, it->getEnd());
		}
		auto last = betweenOld.back();
		ranges.erase(betweenOld.front(), ++last);
		return ranges.insert(AddressRange(min, max));
	}
}

std::pair<AddressRangeContainer::iterator,bool> AddressRangeContainer::insert(
		const Address& s,
		const Address& e)
{
	return insert(AddressRange(s, e));
}

const AddressRange* AddressRangeContainer::getRange(Address addr)
{
	if (ranges.empty())
	{
		return nullptr;
	}

	auto pos = ranges.lower_bound(AddressRange(addr));

	if (pos == ranges.end())
	{
		auto last = ranges.rbegin();
		return (last->contains(addr)) ? (&(*last)) : (nullptr);
	}

	if (pos != ranges.begin() && pos->getStart() != addr)
	{
		pos--;
	}

	return (pos->contains(addr)) ? (&(*pos)) : (nullptr);
}

bool AddressRangeContainer::contains(Address addr)
{
	return getRange(addr) != nullptr;
}

bool AddressRangeContainer::containsExact(AddressRange r)
{
	auto* rr = getRange(r.getStart());
	return rr ? *rr == r : false;
}

void AddressRangeContainer::remove(const AddressRange &r)
{
	std::vector<AddressRangeContainer::iterator> inOld;

	auto pos = ranges.lower_bound(r);
	if (pos != ranges.begin())
	{
		--pos; // Move to previous no matter what.
	}
	while (pos != ranges.end() && pos->getStart() <= r.getEnd())
	{
		if (pos->contains(r.getStart())
				|| pos->contains(r.getEnd())
				|| r.contains(pos->getStart())
				|| r.contains(pos->getEnd()))
		{
			inOld.push_back(pos);
		}
		++pos;
	}

	if (inOld.empty())
	{
		return;
	}

	std::vector<AddressRange> newRanges;

	for (auto& it : inOld)
	{
		const AddressRange& old = *it;

		if (old.getStart() < r.getStart())
		{
			newRanges.push_back(AddressRange(old.getStart(), r.getStart() - 1));
		}
		if (old.getEnd() > r.getEnd())
		{
			newRanges.push_back(AddressRange(r.getEnd() + 1, old.getEnd()));
		}
	}

	// Remove all old -- container is set, we can not modify its elements.
	//
	auto last = inOld.back();
	ranges.erase(inOld.front(), ++last);

	for (auto& nr : newRanges)
	{
		insert(nr);
	}
}

void AddressRangeContainer::remove(const Address& s, const Address& e)
{
	return remove(AddressRange(s, e));
}

} // namespace utils
} // namespace retdec
