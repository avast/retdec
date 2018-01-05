/**
 * @file include/retdec/config/storage.h
 * @brief Decompilation configuration manipulation: storage.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_STORAGE_H
#define RETDEC_CONFIG_STORAGE_H

#include <string>

#include "retdec/config/base.h"
#include "retdec/utils/value.h"

namespace retdec {
namespace config {

/**
 * Represents possible storages of objects, function returns, etc.
 */
class Storage
{
	public:
		Storage();

		Json::Value getJsonValue() const;
		void readJsonValue(const Json::Value& val);

		/// @name Storage named constructors.
		/// @{
		static Storage undefined();
		static Storage onStack(int offset);
		static Storage onStack(int offset, unsigned registerNumber);
		static Storage inMemory(const retdec::utils::Address& address);
		static Storage inRegister(const std::string& registerName);
		static Storage inRegister(unsigned registerNumber);
		static Storage inRegister(
				const std::string& registerName,
				unsigned registerNumber,
				const std::string& registerClass);
		static Storage fromJsonValue(const Json::Value& val);
		/// @}

		/// @name Storage query methods.
		/// @{
		bool isDefined() const;
		bool isUndefined() const;
		bool isMemory() const;
		bool isMemory(retdec::utils::Address& globalAddress) const;
		bool isRegister() const;
		bool isRegister(std::string& registerName) const;
		bool isRegister(int& registerNumber) const;
		bool isStack() const;
		bool isStack(int& stackOffset) const;
		/// @}

		/// @name Storage get methods.
		/// @{
		retdec::utils::Address getAddress() const;
		std::string getRegisterName() const;
		int getStackOffset() const;
		retdec::utils::Maybe<unsigned> getRegisterNumber() const;
		std::string getRegisterClass() const;
		/// @}

	protected:
		enum class eType
		{
			UNDEFINED = 0,
			GLOBAL,
			REGISTER,
			STACK
		};
		const static int UNDEF_REG_NUM = -1;

	protected:
		eType type = eType::UNDEFINED;

		int _stackOffset = 0;
		std::string _registerName;
		retdec::utils::Address _globalAddress;

		retdec::utils::Maybe<unsigned> _registerNumber;
		std::string _registerClass;
};

} // namespace config
} // namespace retdec

#endif
