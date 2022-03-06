#include <vmprofiler.hpp>


namespace vm::handler::profile
{
	vm::handler::profile_t cpuid =
	{
		//mov     eax, [rbp+0]
		//cpuid
		//sub     rbp, 0Ch
		//mov     [rbp+0Ch], eax
		//mov     [rbp+8], ebx
		//mov     [rbp+4], ecx
		//mov     [rbp+0], edx
		"CPUID",
		CPUID,
		NULL,
		{

			//cpuid
			[](const zydis_decoded_instr_t& instr) -> bool {
				return instr.mnemonic == ZYDIS_MNEMONIC_CPUID;
			},

		//sub rsp,0Ch
		[](const zydis_decoded_instr_t& instr) -> bool {
			return	instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
				   instr.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				   instr.operands[0].reg.value == ZYDIS_REGISTER_RBP &&
				   instr.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
				   instr.operands[1].imm.value.u == 0xC;
		}
		}
	};
}