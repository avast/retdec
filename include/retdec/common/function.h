/**
 * @file include/retdec/common/function.h
 * @brief Common function representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_FUNCTION_H
#define RETDEC_COMMON_FUNCTION_H

#include <set>
#include <string>

#include "retdec/common/calling_convention.h"
#include "retdec/common/basic_block.h"
#include "retdec/common/object.h"
#include "retdec/common/storage.h"
#include "retdec/common/type.h"

namespace retdec {
namespace common {

using LineNumber = retdec::common::Address;

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
class Function : public retdec::common::AddressRange
{
	public:
		/**
		 * Recognized types of a function that will determine
		 * how the decompiler will treat the specified function.
		 *
		 * When the type is DECOMPILER_DEFINED the decompiler is
		 * allowed to prefer info recieved from some heuristics,
		 * instead of info specified in the config.
		 *
		 * When the type is USER_DEFINED the info about the function
		 * (params, type) specified in a config file will be projected
		 * on the decompiler output and the decompiler should not do
		 * any heuristcs.
		 */
		enum eLinkType
		{
			DECOMPILER_DEFINED = 0,
			USER_DEFINED,
			STATICALLY_LINKED,
			DYNAMICALLY_LINKED,
			SYSCALL,
			IDIOM
		};

	public:
		Function(const std::string& name = std::string());
		Function(
			retdec::common::Address start,
			retdec::common::Address end,
			const std::string& name = std::string());

		/// @name Function query methods.
		/// @{
		bool isDecompilerDefined() const;
		bool isUserDefined() const;
		bool isStaticallyLinked() const;
		bool isDynamicallyLinked() const;
		bool isSyscall() const;
		bool isIdiom() const;
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
		void setStartLine(const retdec::common::Address& l);
		void setEndLine(const retdec::common::Address& l);
		void setIsDecompilerDefined();
		void setIsUserDefined();
		void setIsStaticallyLinked() const;
		void setIsDynamicallyLinked() const;
		void setIsSyscall();
		void setIsIdiom();
		void setIsFromDebug(bool d);
		void setIsConstructor(bool f);
		void setIsDestructor(bool f);
		void setIsVirtual(bool f);
		void setIsExported(bool f);
		void setIsVariadic(bool f);
		void setIsThumb(bool f);
		void setLinkType(eLinkType lt);
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
		eLinkType getLinkType() const;
		/// @}

		bool operator<(const Function& o) const;
		bool operator==(const Function& o) const;
		bool operator!=(const Function& o) const;

	public:
		common::CallingConvention callingConvention;
		common::Storage returnStorage;
		common::Storage frameBaseStorage;
		common::Type returnType;
		common::ObjectSequentialContainer parameters;
		common::ObjectSetContainer locals;
		std::set<std::string> usedCryptoConstants;
		std::set<common::BasicBlock> basicBlocks;
		/// Addresses of instructions which reference (use) this  function.
		std::set<common::Address> codeReferences;

	private:
		std::string _name; ///< This is objects unique ID.
		std::string _realName;
		std::string _demangledName;
		std::string _comment;
		std::string _declarationString;
		std::string _sourceFileName;
		std::string _wrapperdFunctionName;
		mutable eLinkType _linkType = DECOMPILER_DEFINED;
		LineNumber _startLine;
		LineNumber _endLine;
		bool _fromDebug = false;
		bool _constructor = false;
		bool _destructor = false;
		bool _virtualFunction = false;
		bool _exported = false;
		bool _variadic = false;
		bool _thumb = false;
};

struct FunctionNameCompare
{
	using is_transparent = void;

	bool operator()(const Function& f1, const Function& f2) const
	{
		return f1 < f2;
	}
	bool operator()(const std::string& id, Function const& f) const
	{
		return id < f.getName();
	}
	bool operator()(const Function& f, const std::string& id) const
	{
		return f.getName() < id;
	}
};

struct FunctionAddressCompare
{
	using is_transparent = void;

	bool operator()(const Function& f1, const Function& f2) const
	{
		return f1.getStart() < f2.getStart();
	}
	bool operator()(const retdec::common::Address& id, Function const& f) const
	{
		return id < f.getStart();
	}
	bool operator()(const Function& f, const retdec::common::Address& id) const
	{
		return f.getStart() < id;
	}
};

/**
 * An associative container with functions' names as the key.
 * See Function class for details.
 */
class FunctionContainer : public std::set<Function, FunctionNameCompare>
{
	public:
		bool hasFunction(const std::string& name);
		const Function* getFunctionByName(const std::string& name) const;
		const Function* getFunctionByStartAddress(
				const retdec::common::Address& addr) const;
		const Function* getFunctionByRealName(const std::string& name) const;
};

// TODO:
// Maybe we could use common::RangeContainer for this.
// It contains this functionality, but also some other mechanisms with
// potentially unwanted side effects.
// Also, because it does not take range as template argument, it is not ready
// to be used with common::Function.
class FunctionSet : public std::set<
		retdec::common::Function,
		retdec::common::FunctionAddressCompare>
{
	public:
		const retdec::common::Function* getRange(
				const retdec::common::Address& a) const;
};

} // namespace common
} // namespace retdec

#endif
