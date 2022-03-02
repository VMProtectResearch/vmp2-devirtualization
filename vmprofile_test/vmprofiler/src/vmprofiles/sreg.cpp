#include <vmprofiler.hpp>

namespace vm::handler::profile
{
    vm::handler::profile_t sregq = {
        // MOV RDX, [RBP]
        // ADD RBP, 8
        // MOV [RAX+RDI], RDX
        "SREGQ",
        SREGQ,
        8,
        { { // MOV RDX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RDX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // ADD RBP, 8
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && instr.operands[ 1 ].imm.value.u == 8;
            },
            // MOV [RAX+RDI], RDX or MOV [RDI+RAX], RDX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ( instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RDI ) &&
                       ( instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RDI ||
                         instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RAX ) &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_RDX;
            } } } };

    vm::handler::profile_t sregdw = {
        // MOV EDX, [RBP]
        // ADD RBP, 0x4
        // MOV [RAX+RDI], EDX
        "SREGDW",
        SREGDW,
        8,
        { { // MOV EDX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_EDX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // ADD RBP, 0x4
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x4;
            },
            // MOV [RAX+RDI], EDX or MOV [RDI+RAX], EDX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ( instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RDI ) &&
                       ( instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RDI ) &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_EDX;
            } } } };

    vm::handler::profile_t sregw = {
        // MOV DX, [RBP]
        // ADD RBP, 0x2
        // MOV [RAX+RDI], DX
        "SREGW",
        SREGW,
        8,
        { { // MOV DX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_DX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // ADD RBP, 0x2
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x2;
            },
            // MOV [RAX+RDI], DX or MOV [RDI+RAX], DX
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ( instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RDI ) &&
                       ( instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RDI ||
                         instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RAX ) &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_DX;
            } } } };

    vm::handler::profile_t sregb = {
        // MOV DX, [RBP]
        // ADD RBP, 0x2
        // MOV [RAX+RDI], DL
        "SREGB",
        SREGB,
        8,
        { { // MOV DX, [RBP]
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_DX &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RBP;
            },
            // ADD RBP, 0x2
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_ADD &&
                       instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RBP &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                       instr.operands[ 1 ].imm.value.u == 0x2;
            },
            // MOV [RAX+RDI], DL or MOV [RDI+RAX], DL
            []( const zydis_decoded_instr_t &instr ) -> bool {
                return instr.mnemonic == ZYDIS_MNEMONIC_MOV && instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ( instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RAX ||
                         instr.operands[ 0 ].mem.base == ZYDIS_REGISTER_RDI ) &&
                       ( instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RDI ||
                         instr.operands[ 0 ].mem.index == ZYDIS_REGISTER_RAX ) &&
                       instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       instr.operands[ 1 ].reg.value == ZYDIS_REGISTER_DL;
            } } } };
} // namespace vm::handler::profile