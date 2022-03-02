#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t lregq = {
        // MOV RDX, [RAX+RDI]
        // SUB RBP, 8
        // MOV [RBP], RDX
        "LREGQ",
        LREGQ,
        8,
        { { // MOV RDX, [RAX+RDI] or MOV RDX, [RDI+RAX]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RDX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ( instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RDI ) &&
                       ( instr.operands[ 1 ].mem.index == ZYDIS_REGISTER_RDI ||
                         instr.operands[ 1 ].mem.index == ZYDIS_REGISTER_RAX );
            },
            // SUB RBP, 8
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x8;
            },
            // MOV [RBP], RDX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_RDX;
            } } } };

    vm::handler::profile_t lregdw = {
        // MOV RDX, [RAX + RDI]
        // SUB RBP, 0x4
        // MOV [RBP], EDX
        "LREGDW",
        LREGDW,
        8,
        { { // MOV RDX, [RAX + RDI] or MOV RDX, [RDI + RAX]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_EDX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ( instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RDI ) &&
                       ( instr.operands[ 1 ].mem.index == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 1 ].mem.index == ZYDIS_REGISTER_RDI );
            },
            // SUB RBP, 0x4
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x4;
            },
            // MOV [RBP], EDX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_EDX;
            } } } };
} // namespace vm::handler::profile