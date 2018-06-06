/**
 * @file include/retdec/utils/address.h
 * @brief Address, address pair and other derived class representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_ADDRESS_H
#define RETDEC_UTILS_ADDRESS_H

#include <cstddef>
#include <ostream>
#include <set>
#include <sstream>

#include "retdec/utils/range.h"

namespace retdec {
namespace utils {

class Address
{
	public:
		Address();
		Address(uint64_t a);
		explicit Address(const std::string &a);
		operator uint64_t() const;
		explicit operator bool() const;

		Address& operator++();
		Address operator++(int);
		Address& operator--();
		Address operator--(int);
		Address& operator+=(const Address& rhs);
		Address& operator-=(const Address& rhs);
		Address& operator|=(const Address& rhs);

		bool isUndefined() const;
		bool isDefined() const;

		uint64_t getValue() const;

		std::string toHexString() const;
		std::string toHexPrefixString() const;
		friend std::ostream& operator<< (std::ostream &out, const Address &a);

	public:
		static const uint64_t getUndef;

	private:
		uint64_t address;
};

/**
 * Range includes both start and end addresses (i.e <startAddress, endAddress>).
 */
class AddressRange : public Range<Address>
{
	public:
		AddressRange();
		explicit AddressRange(Address f);
		AddressRange(Address f, Address s);
		explicit AddressRange(const std::string &r);

		bool operator<(const AddressRange &o) const;
		bool operator==(const AddressRange &o) const;
		bool operator!=(const AddressRange &o) const;

		friend std::ostream& operator<<(
				std::ostream &out,
				const AddressRange &r);
};

/**
 * TODO: Merge with Marek's RangeContainer, use RangeContainer because it can
 * be used with any data type, not only Address.
 * Make sure the result merges 0x0-0x5 and 0x6-0x10 into 0x0-0x10.
 */
class AddressRangeContainer
{
	public:
		using iterator       = typename std::set<AddressRange>::iterator;
		using const_iterator = typename std::set<AddressRange>::const_iterator;

	public:
		iterator begin();
		const_iterator begin() const;
		iterator end();
		const_iterator end() const;
		std::size_t size() const;
		bool empty() const;
		void clear();

		bool operator==(const AddressRangeContainer &o) const;
		bool operator!=(const AddressRangeContainer &o) const;

		std::pair<iterator,bool> insert(const AddressRange &r);
		std::pair<iterator,bool> insert(const Address& s, const Address& e);

		void remove(const AddressRange &r);
		void remove(const Address& s, const Address& e);

		bool contains(Address addr) const;
		bool containsExact(AddressRange r) const;
		const AddressRange* getRange(Address addr) const;

		friend std::ostream& operator<<(
				std::ostream &out,
				const AddressRangeContainer &r);

	private:
		std::set<AddressRange> _ranges;
};

} // namespace utils
} // namespace retdec

#endif
