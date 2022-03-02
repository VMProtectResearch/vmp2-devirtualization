#pragma once
#include <transform.hpp>
#include <vmprofiles.hpp>

namespace vm::handler
{
    /// <summary>
    /// handler_t contains all the information for a vm handler such as its immidate value size (zero if there is no
    /// imm), the transformations applied to the imm to decrypt it (if any), a pointer to the profile (nullptr if
    /// there is none), and other meta data...
    /// </summary>
    struct handler_t
    {
        /// <summary>
        /// imm size in bits, zero if no imm...
        /// </summary>
        u8 imm_size;

        /// <summary>
        /// transformations to decrypt imm...
        /// </summary>
        vm::transform::map_t transforms;

        /// <summary>
        /// pointer to the profile, nullptr if none...
        /// </summary>
        vm::handler::profile_t *profile;

        /// <summary>
        /// native instructions of the vm handler... (calc_jmp/check_vsp is removed from this)...
        /// </summary>
        zydis_routine_t instrs;

        /// <summary>
        /// linear virtual address to the vm handler...
        /// </summary>
        std::uintptr_t address;
    };

    /// <summary>
    /// given a vm handler returns true if the vm handler decrypts an operand...
    /// </summary>
    /// <param name="vm_handler">const reference to a vm handler...</param>
    /// <returns>returns true if the vm handler decrypts an operand, else false...</returns>
    bool has_imm( const zydis_routine_t &vm_handler );

    /// <summary>
    /// gets the imm size of a vm handler...
    /// </summary>
    /// <param name="vm_handler">const reference to a vm handler...</param>
    /// <returns>returns the imm size, otherwise returns an empty optional value...</returns>
    std::optional< std::uint8_t > imm_size( const zydis_routine_t &vm_handler );

    /// <summary>
    /// gets a vm handler, puts all of the native instructions inside of the vm_handler param...
    /// </summary>
    ///  <param name="vm_handler">reference to a zydis_routine_t that will get filled with the
    /// native instructions of the vm handler...</param> <param name="handler_addr">linear virtual address to the
    /// first instruction of the vm handler...</param> <returns>returns true if the native instructions of the vm
    /// handler was extracted...</returns>
    bool get( zydis_routine_t &vm_handler, std::uintptr_t handler_addr );

    /// <summary>
    /// get all 256 vm handlers...
    /// </summary>
    /// <param name="module_base">linear virtual address of the module base...</param>
    /// <param name="image_base">image base from optional nt header... <a
    /// href="https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64">IMAGE_OPTIONAL_HEADER64</a>...</param>
    /// <param name="vm_entry">zydis_routine_t containing the deobfuscated and flattened vm entry native
    /// instructions...</param> <param name="vm_handler_table">linear virtual address to the vm handler
    /// table...</param> <param name="vm_handlers">vector of handler_t's that will be filled with the vm
    /// handlers...</param> <returns>returns true if all vm handlers were extracted, else false...</returns>
    bool get_all( std::uintptr_t module_base, std::uintptr_t image_base, zydis_routine_t &vm_entry,
                  std::uintptr_t *vm_handler_table, std::vector< handler_t > &vm_handlers );

    /// <summary>
    /// get operand decryption instructions given a vm handler...
    /// </summary>
    /// <param name="vm_handler">reference to a zydis_routine_t containing the deobfuscated and flattened vm handler
    /// native instructions...</param> <param name="transforms">reference to a transform::map_t that will get filled
    /// up with the transforms needed to decrypt operands...</param> <returns>returns true if the transformations
    /// were extracted successfully</returns>
    bool get_operand_transforms( zydis_routine_t &vm_handler, transform::map_t &transforms );

    /// <summary>
    /// get a vm handler profile given a handler_t...
    /// </summary>
    /// <param name="vm_handler">reference to a handler_t structure that contains all the information of a given vm
    /// handler...</param> <returns>returns a pointer to the vm profile, else a nullptr...</returns>
    vm::handler::profile_t *get_profile( handler_t &vm_handler );

    /// <summary>
    /// get a vm handler profile given the mnemonic of the vm handler...
    /// </summary>
    /// <param name="mnemonic">mnemonic of the vm handler...</param>
    /// <returns>returns a pointer to the profile if the given menmonic is implimented, else a nullptr...</returns>
    vm::handler::profile_t *get_profile( vm::handler::mnemonic_t mnemonic );

    namespace table
    {
        /// <summary>
        /// get the linear virtual address of the vm handler table give a deobfuscated, flattened, vm entry...
        /// </summary>
        /// <param name="vm_entry">deobfuscated, flattened, vm entry...</param>
        /// <returns>returns the linear virtual address of the vm handler table...</returns>
        std::uintptr_t *get( const zydis_routine_t &vm_entry );

        /// <summary>
        /// get the single native instruction used to decrypt vm handler entries...
        /// </summary>
        /// <param name="vm_entry">reference to the deobfuscated, flattened, vm entry...</param>
        /// <param name="transform_instr"></param>
        /// <returns></returns>
        bool get_transform( const zydis_routine_t &vm_entry, zydis_decoded_instr_t *transform_instr );

        /// <summary>
        /// encrypt a linear virtual address given the transformation that is used to decrypt the vm handler table
        /// entry... this function will apply the inverse of the transformation so you dont need to get the inverse
        /// yourself...
        /// </summary>
        /// <param name="transform_instr">reference to the transformation native instruction...</param>
        /// <param name="val">value to be encrypted (linear virtual address)</param>
        /// <returns>returns the encrypted value...</returns>
        std::uint64_t encrypt( zydis_decoded_instr_t &transform_instr, std::uint64_t val );

        /// <summary>
        /// decrypts a vm handler table entry...
        /// </summary>
        /// <param name="transform_instr">transformation extracted from vm_entry that decrypts vm handler table
        /// entries...</param> <param name="val">encrypted value to be decrypted...</param> <returns>returns the
        /// decrypted value...</returns>
        std::uint64_t decrypt( zydis_decoded_instr_t &transform_instr, std::uint64_t val );
    } // namespace table
} // namespace vm::handler