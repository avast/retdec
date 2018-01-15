/**
 * @file include/retdec/config/functions.h
 * @brief Decompilation configuration manipulation: functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_FUNCTIONS_H
#define RETDEC_CONFIG_FUNCTIONS_H

#include <string>

#include "retdec/config/base.h"
#include "retdec/config/calling_convention.h"
#include "retdec/config/objects.h"
#include "retdec/config/storage.h"
#include "retdec/config/types.h"

namespace retdec {
namespace config {

using LineNumber = retdec::utils::Address;

/**
 * Represents function.
 *
 * Function's name is its unique ID. Function names in config must be the
 * same as in LLVM IR. Function names in IR must be unique, therefore
 * it is safe to demand unique names in config without loss of generality.
 *
 * Function address is not suitable unique ID. LLVM IR do not know
 * about functions' addresses. Some functions (syscalls) do not have
 * meaningful addresses.
 */
class Function : public retdec::utils::AddressRange
{
	public:
		explicit Function(const std::string& id);
		static Function fromJsonValue(const Json::Value& val);

		Json::Value getJsonValue() const;

		/// @name Function query methods.
		/// @{
		bool isUserDefined() const;
		bool isStaticallyLinked() const;
		bool isDynamicallyLinked() const;
		bool isSyscall() const;
		bool isIdiom() const;
		bool isFixed() const;
		bool isFromDebug() const;
		bool isWrapper() const;
		bool isConstructor() const;
		bool isDestructor() const;
		bool isVirtual() const;
		bool isExported() const;
		bool isVariadic() const;
		bool isThumb() const;
		/// @}

		/// @name Function set methods.
		/// @{
		void setName(const std::string& n);
		void setRealName(const std::string& n);
		void setDemangledName(const std::string& n);
		void setComment(const std::string& c);
		void addComment(const std::string& c);
		void setDeclarationString(const std::string& s);
		void setSourceFileName(const std::string& n);
		void setWrappedFunctionName(const std::string& n);
		void setStartLine(const retdec::utils::Address& l);
		void setEndLine(const retdec::utils::Address& l);
		void setIsUserDefined();
		void setIsStaticallyLinked();
		void setIsDynamicallyLinked();
		void setIsSyscall();
		void setIsIdiom();
		void setIsFixed(bool f);
		void setIsFromDebug(bool d);
		void setIsConstructor(bool f);
		void setIsDestructor(bool f);
		void setIsVirtual(bool f);
		void setIsExported(bool f);
		void setIsVariadic(bool f);
		void setIsThumb(bool f);
		/// @}

		/// @name Function get methods.
		/// @{
		const std::string& getId() const;
		const std::string& getName() const;
		const std::string& getRealName() const;
		std::string getDemangledName() const;
		std::string getComment() const;
		std::string getDeclarationString() const;
		std::string getSourceFileName() const;
		std::string getWrappedFunctionName() const;
		LineNumber getStartLine() const;
		LineNumber getEndLine() const;
		/// @}

		bool operator<(const Function& o) const;
		bool operator==(const Function& o) const;
		bool operator!=(const Function& o) const;

	public:
		CallingConvention callingConvention;
		Storage returnStorage;
		Storage frameBaseStorage; // TODO - serialization
		Type returnType;
		ObjectSequentialContainer parameters;
		ObjectSetContainer locals;
		std::set<std::string> usedCryptoConstants;

	private:
		enum eLinkType
		{
			USER_DEFINED = 0,
			STATICALLY_LINKED,
			DYNAMICALLY_LINKED,
			SYSCALL,
			IDIOM
		};

	private:
		std::string _name; ///< This is objects unique ID.
		std::string _realName;
		std::string _demangledName;
		std::string _comment;
		std::string _declarationString;
		std::string _sourceFileName;
		std::string _wrapperdFunctionName;
		eLinkType _linkType = USER_DEFINED;
		LineNumber _startLine;
		LineNumber _endLine;
		bool _fixed = false;
		bool _fromDebug = false;
		bool _constructor = false;
		bool _destructor = false;
		bool _virtualFunction = false;
		bool _exported = false;
		bool _variadic = false;
		bool _thumb = false;
};

/**
 * An associative container with functions' names as the key.
 * See Function class for details.
 */
class FunctionContainer : public BaseAssociativeContainer<std::string, Function>
{
	public:
		bool hasFunction(const std::string& name);
		Function* getFunctionByName(const std::string& name);
		const Function* getFunctionByName(const std::string& name) const;
		Function* getFunctionByStartAddress(const retdec::utils::Address& addr);
		Function* getFunctionByRealName(const std::string& name);
};

} // namespace config
} // namespace retdec

#endif
