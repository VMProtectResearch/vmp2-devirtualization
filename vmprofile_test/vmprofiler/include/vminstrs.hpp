#pragma once
#include <transform.hpp>
#include <vmctx.hpp>
#include <vmhandlers.hpp>
#include <vmp2.hpp>
#include <scn.hpp>

/// <summary>
/// contains all functions related to virtual instructions...
/// </summary>
namespace vm::instrs
{
    /// <summary>
    /// gets the native instructions that are used to decrypt the relative virtual address to virtual instructions
    /// located on the stack at RSP+0xA0... you can learn about this @link https://back.engineering/17/05/2021/#vm_entry
    /// </summary>
    /// <param name="vm_entry">pass by reference of the specific vm entry you want to get the decryption instructions
    /// from...</param> <param name="transform_instrs">pass by reference vector that will be filled with the decryption
    /// instructions...</param> <returns>returns true if the decryption instructions are extracted...</returns>
    bool get_rva_decrypt( const zydis_routine_t &vm_entry, std::vector< zydis_decoded_instr_t > &transform_instrs );

    /// <summary>
    /// decrypt virtual instruction operand given the decryption transformations... you can read about these
    /// transformations
    /// @link https://back.engineering/17/05/2021/#operand-decryption
    /// </summary>
    /// <param name="transforms">decryption transformations...</param>
    /// <param name="operand">encrypted virtual instruction operand...</param>
    /// <param name="rolling_key">the decryption key (RBX)...</param>
    /// <returns></returns>
    std::pair< std::uint64_t, std::uint64_t > decrypt_operand( transform::map_t &transforms, std::uint64_t operand,
                                                               std::uint64_t rolling_key );

    /// <summary>
    /// encrypt a virtual instructions operand given the transformations to decrypt the operand... the transformations
    /// are inversed by this functions so you dont need to worry about doing that.
    ///
    /// you can learn about transformations @link https://back.engineering/17/05/2021/#operand-decryption
    /// </summary>
    /// <param name="transforms">transformations to decrypt operand, these transformations are inversed by the
    /// function...</param> <param name="operand">operand to be encrypted...</param> <param
    /// name="rolling_key">encryption key... (RBX)...</param> <returns></returns>
    std::pair< std::uint64_t, std::uint64_t > encrypt_operand( transform::map_t &transforms, std::uint64_t operand,
                                                               std::uint64_t rolling_key );

    /// <summary>
    /// get virt_instr_t filled in with data given a vmp2 trace entry and vm context...
    /// </summary>
    /// <param name="ctx">current vm context</param>
    /// <param name="entry">vmp2 trace entry containing all of the native/virtual register/stack values...</param>
    /// <returns>returns a filled in virt_instr_t on success...</returns>
    std::optional< virt_instr_t > get( vm::ctx_t &ctx, vmp2::v2::entry_t &entry );

    /// <summary>
    /// gets the encrypted second operand (imm) given vip and vm::ctx_t...
    /// </summary>
    /// <param name="ctx">vm context</param>
    /// <param name="imm_size">immediate value size in bits...</param>
    /// <param name="vip">virtual instruction pointer, linear virtual address...</param>
    /// <returns>returns immediate value if imm_size is not 0...</returns>
    std::optional< std::uint64_t > get_imm( vm::ctx_t &ctx, std::uint8_t imm_size, std::uintptr_t vip );

    /// <summary>
    /// get jcc data out of a code block... this function will loop over the code block
    /// and look for the last LCONSTDW in the virtual instructions.
    ///
    /// it will then loop and look for all PUSHVSP's, checking each to see if the stack
    /// contains two encrypted rva's to each branch.. if there is not two encrypted rva's
    /// then the virtual jmp instruction only has one dest...
    /// </summary>
    /// <param name="ctx">vm context</param>
    /// <param name="code_block">code block that does not have its jcc_data yet</param>
    /// <returns>if last lconstdw is found, return filled in jcc_data structure...</returns>
    std::optional< jcc_data > get_jcc_data( vm::ctx_t &ctx, code_block_t &code_block );

    /// <summary>
    /// this algo is used to try and find a jmp tables address and all of its entries for a given code block...
    /// </summary>
    /// <param name="ctx">vm context</param>
    /// <param name="code_block">code block that has an absolute jmp... this routine is going to see if this code block
    /// actually is jmp table stub</param> <returns>if a jmp table is found then we decrypt all entries and return a
    /// vector of them..</returns>
    std::optional< std::vector< std::uint64_t > > get_switch_cases( vm::ctx_t &ctx, code_block_t &code_block );

    /// <summary>
    /// the top of the stack will contain the lower 32bits of the RVA to the virtual instructions
    /// that will be jumping too... the RVA is image based (not module based, but optional header image
    /// based)... this means the value ontop of the stack could be "40007fd8" with image base being
    /// 0x140000000... as you can see the 0x100000000 is missing... the below statement deals with this...
    /// </summary>
    /// <param name="ctx">vm context</param>
    /// <param name="entry">current trace entry for virtual JMP instruction</param>
    /// <returns>returns linear virtual address of the next code block...</returns>
    std::uintptr_t code_block_addr( const vm::ctx_t &ctx, const vmp2::v2::entry_t &entry );

    /// <summary>
    /// same routine as above except lower_32bits is passed directly and not extracted from the stack...
    /// </summary>
    /// <param name="ctx">vm context</param>
    /// <param name="lower_32bits">lower 32bits of the relative virtual address...</param>
    /// <returns>returns full linear virtual address of code block...</returns>
    std::uintptr_t code_block_addr( const vm::ctx_t &ctx, const std::uint32_t lower_32bits );
} // namespace vm::instrs