/**
 * @file include/retdec/common/storage.h
 * @brief Common object storage representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_STORAGE_H
#define RETDEC_COMMON_STORAGE_H

#include <string>
#include <optional>

#include "retdec/common/address.h"

namespace retdec {
namespace common {

/**
 * Represents possible storages of objects, function returns, etc.
 */
class Storage
{
	public:
		enum class eType
		{
			UNDEFINED = 0,
			GLOBAL,
			REGISTER,
			STACK
		};

	public:
		Storage();

		/// @name Storage named constructors.
		/// @{
		static Storage undefined();
		static Storage onStack(int offset);
		static Storage onStack(int offset, unsigned registerNumber);
		static Storage inMemory(const retdec::common::Address& address);
		static Storage inRegister(const std::string& registerName);
		static Storage inRegister(unsigned registerNumber);
		static Storage inRegister(
				const std::string& registerName,
				unsigned registerNumber);
		/// @}

		/// @name Storage query methods.
		/// @{
		bool isDefined() const;
		bool isUndefined() const;
		bool isMemory() const;
		bool isMemory(retdec::common::Address& globalAddress) const;
		bool isRegister() const;
		bool isRegister(std::string& registerName) const;
		bool isRegister(int& registerNumber) const;
		bool isStack() const;
		bool isStack(int& stackOffset) const;
		/// @}

		/// @name Storage get methods.
		/// @{
		retdec::common::Address getAddress() const;
		std::string getRegisterName() const;
		int getStackOffset() const;
		std::optional<unsigned> getRegisterNumber() const;
		/// @}

		/// @name Storage set methods.
		/// @{
		void setRegisterNumber(unsigned registerNumber);
		/// @}

	protected:
		const static int UNDEF_REG_NUM = -1;

	protected:
		eType type = eType::UNDEFINED;

		int _stackOffset = 0;
		std::string _registerName;
		retdec::common::Address _globalAddress;

		std::optional<unsigned> _registerNumber;
};

} // namespace common
} // namespace retdec

#endif
