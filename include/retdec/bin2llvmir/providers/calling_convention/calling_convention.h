/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/calling_convention.h
 * @brief Calling convention information.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */


#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_CALL_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_CALL_CONV_H

#include <vector>

#include <llvm/IR/Module.h>

#include "retdec/config/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class Abi;

class CallingConvention
{
	// Typedefs.
	//
	public:
		typedef std::unique_ptr<CallingConvention> Ptr;
		typedef retdec::config::CallingConventionID ID;

		typedef Ptr (*ConstructorMethod)(const Abi*);
 
	// Constants.
	//
	public:
		static const bool RTL;
		static const bool LTR;

	// Ctors, dtors.
	//
	public:
		CallingConvention(const Abi* abi);
		virtual ~CallingConvention();
	
	// Registers.
	//
	public:
		std::vector<uint32_t> getParamRegisters() const;
		std::vector<uint32_t> getParamFPRegisters() const;
		std::vector<uint32_t> getParamDoubleRegisters() const;
		std::vector<uint32_t> getParamVectorRegisters() const;

		std::vector<uint32_t> getReturnRegisters() const;
		std::vector<uint32_t> getReturnFPRegisters() const;
		std::vector<uint32_t> getReturnDoubleRegisters() const;
		std::vector<uint32_t> getReturnVectorRegisters() const;

		bool usesFPRegistersForParameters() const;
		bool parameterRegistersOverlay() const;

		std::size_t getRegsNumPerParam() const;

	// Stacks.
	public:
		bool getStackParamOrder() const;
		bool usesStackForParameters() const;
		bool passesStructsOnStack() const;

		virtual std::size_t getMaxBytesPerStackParam() const;
	
	// Values.
	public:
		virtual bool valueCanBeParameter(const llvm::Value* val) const;
		virtual bool canHoldReturnValue(const llvm::Value* val) const;
	
	// Private data - misc.
	//
	protected:
		const Abi* _abi;
		CallingConvention::ID _ccType;
	
	// Private data - registers.
	//
	protected:
		std::vector<uint32_t> _paramRegs {};
		std::vector<uint32_t> _paramFPRegs {};
		std::vector<uint32_t> _paramDoubleRegs {};
		std::vector<uint32_t> _paramVectorRegs {};

		std::vector<uint32_t> _returnRegs {};
		std::vector<uint32_t> _returnFPRegs {};
		std::vector<uint32_t> _returnDoubleRegs {};
		std::vector<uint32_t> _returnVectorRegs {};
	
	// Private data - registers informational.
	//
	protected:
		bool _paramRegsOverlay = false;
		size_t _regNumPerParam = 1;

	// Private data - stacks informational.
	//
	protected:
		bool _paramStructsOnStack = false;
		bool _stackParamOrder = RTL;
		bool _passesOnStack = true;
};

class CallingConventionProvider
{
	// Private constructor.
	// 
	private:
		CallingConventionProvider();

	// Destructor, singleton method.
	public:
		~CallingConventionProvider();
		static CallingConventionProvider* getProvider();

	// Factory methods.
	public:
		void registerCC(
			const CallingConvention::ID& cc,
			const CallingConvention::ConstructorMethod& con);

		CallingConvention::Ptr createCallingConvention(
					const CallingConvention::ID& cc,
					const Abi* a) const;

	// Private data - constrctor methods.
	private:
		std::vector<CallingConvention::ConstructorMethod> _id2cc;
	
};

} // namespace bin2llvmir
} // namespace retdec

#endif
