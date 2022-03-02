#pragma once
#include <transform.hpp>
#include <vmhandlers.hpp>
#define VMP_MAGIC '2PMV'

namespace vmp2
{
    enum class exec_type_t
    {
        forward,
        backward
    };

    enum class version_t
    {
        invalid,
        v1 = 0x101,
        v2 = 0x102,
        v3 = 0x103,
        v4 = 0x104
    };

    namespace v1
    {
        struct file_header
        {
            u32 magic; // VMP2
            u64 epoch_time;
            u64 module_base;
            exec_type_t advancement;
            version_t version;

            u32 entry_count;
            u32 entry_offset;
        };

        struct entry_t
        {
            u8 handler_idx;
            u64 decrypt_key;
            u64 vip;

            union
            {
                struct
                {
                    u64 r15;
                    u64 r14;
                    u64 r13;
                    u64 r12;
                    u64 r11;
                    u64 r10;
                    u64 r9;
                    u64 r8;
                    u64 rbp;
                    u64 rdi;
                    u64 rsi;
                    u64 rdx;
                    u64 rcx;
                    u64 rbx;
                    u64 rax;
                    u64 rflags;
                };
                u64 raw[ 16 ];
            } regs;

            union
            {
                u64 qword[ 0x28 ];
                u8 raw[ 0x140 ];
            } vregs;

            union
            {
                u64 qword[ 0x20 ];
                u8 raw[ 0x100 ];
            } vsp;
        };
    } // namespace v1

    namespace v2
    {
        struct file_header
        {
            u32 magic; // VMP2
            u64 epoch_time;
            version_t version;

            u64 module_base;
            u64 image_base;
            u64 vm_entry_rva;
            exec_type_t advancement;

            u32 module_offset;
            u32 module_size;

            u32 entry_count;
            u32 entry_offset;
        };

        struct entry_t
        {
            u8 handler_idx;
            u32 vm_handler_rva;
            u64 decrypt_key;
            u64 vip;

            union
            {
                struct
                {
                    u64 r15;
                    u64 r14;
                    u64 r13;
                    u64 r12;
                    u64 r11;
                    u64 r10;
                    u64 r9;
                    u64 r8;
                    u64 rbp;
                    u64 rdi;
                    u64 rsi;
                    u64 rdx;
                    u64 rcx;
                    u64 rbx;
                    u64 rax;
                    u64 rflags;
                };
                u64 raw[ 16 ];
            } regs;

            union
            {
                u64 qword[ 0x28 ];
                u8 raw[ 0x140 ];
            } vregs;

            union
            {
                u64 qword[ 0x20 ];
                u8 raw[ 0x100 ];
            } vsp;
        };
    } // namespace v2
} // namespace vmp2

namespace vm
{
    namespace instrs
    {
        struct virt_instr_t
        {
            vm::handler::mnemonic_t mnemonic_t;
            std::uint8_t opcode; // aka vm handler idx...

            // can be used to look at values on the stack...
            vmp2::v2::entry_t trace_data;

            struct
            {
                bool has_imm;
                struct
                {
                    std::uint8_t imm_size; // size in bits...
                    union
                    {
                        std::int64_t s;
                        std::uint64_t u;
                    };
                } imm;
            } operand;
        };

        enum class jcc_type
        {
            none,
            branching,
            absolute,
            switch_case
        };

        struct jcc_data
        {
            bool has_jcc;
            jcc_type type;
            std::vector< std::uintptr_t > block_addr;
        };

        struct code_block_t
        {
            std::uintptr_t vip_begin;
            jcc_data jcc;
            std::vector< virt_instr_t > vinstrs;
        };
    } // namespace instrs
} // namespace vm

namespace vmp2
{
    namespace v3
    {
        struct file_header
        {
            u32 magic; // VMP2
            u64 epoch_time;
            version_t version;

            u64 module_base;
            u64 image_base;
            u64 vm_entry_rva;

            u32 module_offset;
            u32 module_size;

            u32 code_block_offset;
            u32 code_block_count;
        };

        struct code_block_t
        {
            std::uintptr_t vip_begin;
            std::uintptr_t next_block_offset;
            vm::instrs::jcc_data jcc;

            // serialized from std::vector<virt_instr_t>...
            std::uint32_t vinstr_count;
            vm::instrs::virt_instr_t vinstr[];
        };
    } // namespace v3
} // namespace vmp2

#pragma pack( push, 1 )
namespace vmp2
{
    namespace v4
    {
        struct file_header
        {
            u32 magic; // VMP2
            u64 epoch_time;
            version_t version;

            u64 module_base;
            u64 image_base;
            u64 vm_entry_rva;

            u32 module_offset;
            u32 module_size;

            u32 rtn_count;
            u32 rtn_offset;
        };

        struct code_block_t
        {
            std::uintptr_t vip_begin;
            std::uintptr_t next_block_offset;
            std::uint32_t vinstr_count;

            bool has_jcc;
            vm::instrs::jcc_type jcc_type;
            std::uint32_t num_block_addrs;

            std::uintptr_t branch_addr[ 1 ];
            vm::instrs::virt_instr_t vinstr[ 1 ];
        };

        struct rtn_t
        {
            u32 size;
            u32 vm_enter_offset;
            u32 code_block_count;
            vmp2::v4::code_block_t code_blocks[ 1 ];
        };
    } // namespace v4
#pragma pack( pop )
} // namespace vmp2