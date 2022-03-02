#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t popvspq = {
        // MOV RBP [RBP]
        "POPVSPQ",
        POPVSPQ,
        NULL,
        { { []( const zydis_decoded_instr_t &instr ) -> bool {
            return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                   instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
        } } } };

    vm::handler::profile_t popvspw = {
        // MOV BP [RBP]
        "POPVSPW",
        POPVSPW,
        NULL,
        { { []( const zydis_decoded_instr_t &instr ) -> bool {
            return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_BP &&
                   instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
        } } } };
} // namespace vm::handler::profile