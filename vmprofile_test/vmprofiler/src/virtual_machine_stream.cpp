#include<vmprofiler.hpp>

#include<algorithm>

namespace vm::virtual_machine_stream
{
	bool get(const zydis_routine_t& vm_entry,
		uint64_t& opstream_addr,
		uint32_t& key1,
		uint32_t& key2,
		uint64_t module_base)
	{

		uint64_t imm_value = 0;
		zydis_routine_t transform_esi;

		auto result = std::find_if(vm_entry.cbegin(), vm_entry.cend(), [](const zydis_instr_t& instr_data) {

			return ((instr_data.instr.mnemonic == ZYDIS_MNEMONIC_PUSH) &&(instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)) ;

			});

		if (result == vm_entry.cend())
			return false;

		auto instr = result->instr;
	
		imm_value = instr.operands[0].imm.value.u;
		
		
		result = std::find_if(vm_entry.cbegin(), vm_entry.cend(), [&imm_value](const zydis_instr_t& instr_data) {

			return ((instr_data.instr.mnemonic == ZYDIS_MNEMONIC_PUSH) && (instr_data.instr.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) && (instr_data.instr.operands[0].imm.value.u != imm_value));

			});

		if (result == vm_entry.cend())
			return false;

		instr = result->instr;

		//vm::util::print(instr);

		
		//获得key,key一般只使用低位4字节
		key1 = static_cast<uint32_t>(imm_value);
		key2 = static_cast<uint32_t>(instr.operands[0].imm.value.u);

		if (!key1 || !key2)
			return false;


		//获得这个vm-entry对应的指令流地址

		//mov     esi, [rsp+0A0h]   start   一般来说都是0xA0

		//...(decrypt esi)

		//mov     rax, 100000000h
		//add     rsi, [rbp+0]

		//mov     al, [rsi-1]		end

		
		result = std::find_if(vm_entry.cbegin(), vm_entry.cend(), [](const zydis_instr_t& instr_data) {

			return ((instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV)
				&& (instr_data.instr.operands[0].reg.value == ZYDIS_REGISTER_ESI)
				&& instr_data.instr.operands[1].mem.base == ZYDIS_REGISTER_RSP);

			});

		if (result == vm_entry.cend())
			return false;

		instr = result->instr;
		assert(instr.operands[1].mem.disp.value == 0xA0);

		result++; //排除mov     esi, [rsp+0A0h]这条指令

		while (result != vm_entry.cend())
		{
			//获得对esi的解密操作

			if (result->instr.operands[0].reg.value == ZYDIS_REGISTER_ESI &&
				result->instr.operands[0].actions & ZYDIS_OPERAND_ACTION_WRITE)
				transform_esi.push_back(*result);

			result++;
		}

		//vm::util::print(transform_esi);

		uint32_t transform_key1 = key1;
		for (const auto& insn : transform_esi) {
			//transform (esi)
			transform_key1 = vm::transform::apply(32, insn.instr.mnemonic, transform_key1, 
				insn.instr.operands[1].imm.value.u);
		}

		opstream_addr = static_cast<uint64_t>(transform_key1)+ 0x100000000 - 0x140000000 + module_base;
		return true;
	}






}