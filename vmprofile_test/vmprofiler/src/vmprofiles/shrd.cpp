#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t shrdq = {
        // MOV RAX, [RBP]
        // MOV RDX, [RBP+0x8]
        // MOV CL, [RBP+0x8]
        // ADD RBP, 0x2
        // SHRD RAX, RDX, CL
        // MOV [RBP+0x8], RAX
        // PUSHFQ
        // POP [RBP]
        "SHRDQ",
        SHRDQ,
        NULL,
        { { // MOV RAX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RAX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // MOV RDX, [RBP+0x8]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RDX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP && instr.operands[ 1 ].mem.disp.value == 0x8;
            },
            // MOV CL, [RBP+0x10]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_CL &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP && instr.operands[ 1 ].mem.disp.value == 0x10;
            },
            // ADD RBP, 0x2
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x2;
            },
            // SHRD RAX, RDX, CL
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SHRD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RAX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_RDX &&
                       instr.operands[ 2 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 2 ].reg.value == ZYDIS_REGISTER_CL;
            },
            // MOV [RBP+0x8], RAX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
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

    vm::handler::profile_t shrddw = {
        // MOV EAX, [RBP]
        // MOV EDX, [RBP+0x4]
        // MOV CL, [RBP+0x8]
        // SHRD EAX, EDX, CL
        // MOV [RBP+0x8], EAX
        // PUSHFQ
        // POP [RBP]
        "SHRDDW",
        SHRDDW,
        NULL,
        { { // MOV EAX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_EAX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // MOV EDX, [RBP+0x4]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_EDX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP && instr.operands[ 1 ].mem.disp.value == 0x4;
            },
            // MOV CL, [RBP+0x8]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_CL &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP && instr.operands[ 1 ].mem.disp.value == 0x8;
            },
            // SHRD EAX, EDX, CL
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_SHRD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_EAX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_EDX &&
                       instr.operands[ 2 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 2 ].reg.value == ZYDIS_REGISTER_CL;
            },
            // MOV [RBP+0x8], EAX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
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
} // namespace vm::handler::profile