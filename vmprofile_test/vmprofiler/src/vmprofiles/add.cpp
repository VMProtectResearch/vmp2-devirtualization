#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t addq = {
        // MOV RAX, [RBP]
        // ADD [RBP+8], RAX
        // PUSHFQ
        // POP [RBP]
        "ADDQ",
        ADDQ,
        NULL,
        { { // MOV RAX, [RBP]  
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RAX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // ADD [RBP+8], RAX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 0 ].mem.disp.value == 0x8 &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_RAX;
            },
            // PUSHFQ
            []( const zydis_decoded_instr_t &instr ) -> bool { return instr.mnemonic == ZYDIS_MNEMONIC_PUSHFQ; },
            // POP [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_POP && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP;
            } } } };

    vm::handler::profile_t adddw = {
        // MOV EAX, [RBP]
        // SUB RBP, 0x4
        // ADD [RBP+8], EAX
        // PUSHFQ
        // POP [RBP]
        "ADDDW",
        ADDDW,
        NULL,
        { { // MOV EAX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_EAX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // SUB RBP, 0x4
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x4;
            },
            // ADD [RBP+8], EAX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 0 ].mem.disp.value == 0x8 &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_EAX;
            },
            // PUSHFQ
            []( const zydis_decoded_instr_t &instr ) -> bool { return instr.mnemonic == ZYDIS_MNEMONIC_PUSHFQ; },
            // POP [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_POP && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP;
            } } } };

    vm::handler::profile_t addw = {
        // MOV AX, [RBP]
        // SUB RBP, 0x6
        // ADD [RBP+8], AX
        // PUSHFQ
        // POP [RBP]
        "ADDW",
        ADDW,
        NULL,
        { { // MOV AX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_AX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // SUB RBP, 0x6
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x6;
            },
            // ADD [RBP+8], AX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 0 ].mem.disp.value == 0x8 &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_AX;
            },
            // PUSHFQ
            []( const zydis_decoded_instr_t &instr ) -> bool { return instr.mnemonic == ZYDIS_MNEMONIC_PUSHFQ; },
            // POP [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_POP && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP;
            } } } };

    vm::handler::profile_t addb = {
        // MOV AL, [RBP]
        // SUB RBP, 0x6
        // ADD [RBP+8], AL
        // PUSHFQ
        // POP [RBP]
        "ADDB",
        ADDB,
        NULL,
        { { // MOV AX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_AL &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // SUB RBP, 0x6
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SUB &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x6;
            },
            // ADD [RBP+8], AX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 0 ].mem.disp.value == 0x8 &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_AL;
            },
            // PUSHFQ
            []( const zydis_decoded_instr_t &instr ) -> bool { return instr.mnemonic == ZYDIS_MNEMONIC_PUSHFQ; },
            // POP [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_POP && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RBP;
            } } } };
} // namespace vm::handler::profile