#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t lflagsq = {
        // PUSH [RBP]
        // ADD RBP, 0x8
        // POPFQ
        "LFLAGSQ",
        LFLAGSQ,
        NULL,
        { { // PUSH [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_PUSH && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // ADD RBP, 0x8
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x8;
            },
            // POPFQ
            []( const zydis_decoded_instr_t &instr ) -> bool { return instr.mnemonic == ZYDIS_MNEMONIC_POPFQ; } } } };
} // namespace vm::handler::profile