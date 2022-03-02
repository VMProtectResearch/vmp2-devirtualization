#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t vmexit = {
        // MOV RSP, RBP
        // RET
        "VMEXIT",
        VMEXIT,
        NULL,
        { { // MOV RSP, RBP
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RSP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_RBP;
            },
            // RET
            []( const zydis_decoded_instr_t &instr ) -> bool { return instr.mnemonic == ZYDIS_MNEMONIC_RET; } } } };
} // namespace vm::handler::profile