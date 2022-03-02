#include <vmprofiler.hpp>

namespace vm::instrs
{
    std::pair< std::uint64_t, std::uint64_t > decrypt_operand( transform::map_t &transforms, std::uint64_t operand,
                                                               std::uint64_t rolling_key )
    {
        const auto &generic_decrypt_0 = transforms[ transform::type::generic0 ];
        const auto &key_decrypt = transforms[ transform::type::rolling_key ];
        const auto &generic_decrypt_1 = transforms[ transform::type::generic1 ];
        const auto &generic_decrypt_2 = transforms[ transform::type::generic2 ];
        const auto &generic_decrypt_3 = transforms[ transform::type::generic3 ];
        const auto &update_key = transforms[ transform::type::update_key ];

        if ( generic_decrypt_0.mnemonic != ZYDIS_MNEMONIC_INVALID )
        {
            operand = transform::apply(
                /* this is a hot patch for generic0 transformations which bswap 16bit operands... (they xchg)... */
                generic_decrypt_0.mnemonic == ZYDIS_MNEMONIC_XCHG ? 16 : generic_decrypt_0.operands[ 0 ].size,
                generic_decrypt_0.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_0 ) ? generic_decrypt_0.operands[ 1 ].imm.value.u : 0 );
        }

        // apply transformation with rolling decrypt key...
        operand = transform::apply( key_decrypt.operands[ 0 ].size, key_decrypt.mnemonic, operand, rolling_key );

        // apply three generic transformations...
        {
            operand = transform::apply(
                generic_decrypt_1.operands[ 0 ].size, generic_decrypt_1.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_1 ) ? generic_decrypt_1.operands[ 1 ].imm.value.u : 0 );

            operand = transform::apply(
                generic_decrypt_2.operands[ 0 ].size, generic_decrypt_2.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_2 ) ? generic_decrypt_2.operands[ 1 ].imm.value.u : 0 );

            operand = transform::apply(
                generic_decrypt_3.operands[ 0 ].size, generic_decrypt_3.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_3 ) ? generic_decrypt_3.operands[ 1 ].imm.value.u : 0 );
        }

        // update rolling key...
        auto result = transform::apply( update_key.operands[ 0 ].size, update_key.mnemonic, rolling_key, operand );

        // update decryption key correctly...
        switch ( update_key.operands[ 0 ].size )
        {
        case 8:
            rolling_key = ( rolling_key & ~std::numeric_limits< u8 >::max() ) + result;
            break;
        case 16:
            rolling_key = ( rolling_key & ~std::numeric_limits< u16 >::max() ) + result;
            break;
        default:
            rolling_key = result;
            break;
        }

        return { operand, rolling_key };
    }

    std::pair< std::uint64_t, std::uint64_t > encrypt_operand( transform::map_t &transforms, std::uint64_t operand,
                                                               std::uint64_t rolling_key )
    {
        transform::map_t inverse;
        inverse_transforms( transforms, inverse );
        const auto apply_key = rolling_key;

        const auto &generic_decrypt_0 = inverse[ transform::type::generic0 ];
        const auto &key_decrypt = inverse[ transform::type::rolling_key ];
        const auto &generic_decrypt_1 = inverse[ transform::type::generic1 ];
        const auto &generic_decrypt_2 = inverse[ transform::type::generic2 ];
        const auto &generic_decrypt_3 = inverse[ transform::type::generic3 ];
        const auto &update_key = transforms[ transform::type::update_key ];

        auto result = transform::apply( update_key.operands[ 0 ].size, update_key.mnemonic, rolling_key, operand );

        // mov rax, al does not clear the top bits...
        // mov rax, ax does not clear the top bits...
        // mov rax, eax does clear the top bits...
        switch ( update_key.operands[ 0 ].size )
        {
        case 8:
            rolling_key = ( rolling_key & ~std::numeric_limits< u8 >::max() ) + result;
            break;
        case 16:
            rolling_key = ( rolling_key & ~std::numeric_limits< u16 >::max() ) + result;
            break;
        default:
            rolling_key = result;
            break;
        }

        {
            operand = transform::apply(
                generic_decrypt_3.operands[ 0 ].size, generic_decrypt_3.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_3 ) ? generic_decrypt_3.operands[ 1 ].imm.value.u : 0 );

            operand = transform::apply(
                generic_decrypt_2.operands[ 0 ].size, generic_decrypt_2.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_2 ) ? generic_decrypt_2.operands[ 1 ].imm.value.u : 0 );

            operand = transform::apply(
                generic_decrypt_1.operands[ 0 ].size, generic_decrypt_1.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_1 ) ? generic_decrypt_1.operands[ 1 ].imm.value.u : 0 );
        }

        operand = transform::apply( key_decrypt.operands[ 0 ].size, key_decrypt.mnemonic, operand, apply_key );

        if ( generic_decrypt_0.mnemonic != ZYDIS_MNEMONIC_INVALID )
        {
            operand = transform::apply(
                /* this is a hot patch for generic0 transformations which bswap 16bit operands... (they xchg)... */
                generic_decrypt_0.mnemonic == ZYDIS_MNEMONIC_XCHG ? 16 : generic_decrypt_0.operands[ 0 ].size,
                generic_decrypt_0.mnemonic, operand,
                // check to see if this instruction has an IMM...
                transform::has_imm( &generic_decrypt_0 ) ? generic_decrypt_0.operands[ 1 ].imm.value.u : 0 );
        }

        return { operand, rolling_key };
    }

    bool get_rva_decrypt( const zydis_routine_t &vm_entry, std::vector< zydis_decoded_instr_t > &transform_instrs )
    {
        // find mov esi, [rsp+0xA0]
        auto result = std::find_if( vm_entry.begin(), vm_entry.end(), []( const zydis_instr_t &instr_data ) -> bool {
            return instr_data.instr.mnemonic == ZYDIS_MNEMONIC_MOV &&
                   instr_data.instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   instr_data.instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_ESI &&
                   instr_data.instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   instr_data.instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RSP &&
                   instr_data.instr.operands[ 1 ].mem.disp.value == 0xA0;
        } );

        if ( result == vm_entry.end() )
            return false;

        // find the next three instructions with ESI as
        // the first operand... and make sure actions & writes...
        for ( auto idx = 0u; idx < 3; ++idx )
        {
            result = std::find_if( ++result, vm_entry.end(), []( const zydis_instr_t &instr_data ) -> bool {
                return vm::transform::valid( instr_data.instr.mnemonic ) &&
                       instr_data.instr.operands[ 0 ].actions & ZYDIS_OPERAND_ACTION_WRITE &&
                       instr_data.instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_ESI;
            } );

            if ( result == vm_entry.end() )
                return false;

            transform_instrs.push_back( result->instr );
        }

        return true;
    }

    std::optional< std::uint64_t > get_imm( vm::ctx_t &ctx, std::uint8_t imm_size, std::uintptr_t vip )
    {
        if ( !imm_size )
            return {};

        auto result = 0ull;
        ctx.exec_type == vmp2::exec_type_t::forward
            ? std::memcpy( &result, reinterpret_cast< void * >( vip ), imm_size / 8 )
            : std::memcpy( &result, reinterpret_cast< void * >( vip - ( imm_size / 8 ) ), imm_size / 8 );

        return result;
    }

    std::optional< virt_instr_t > get( vm::ctx_t &ctx, vmp2::v2::entry_t &entry )
    {
        virt_instr_t result;
        auto &vm_handler = ctx.vm_handlers[ entry.handler_idx ];
        const auto profile = vm_handler.profile;

        result.mnemonic_t = profile ? profile->mnemonic : vm::handler::INVALID;
        result.opcode = entry.handler_idx;
        result.trace_data = entry;
        result.operand.has_imm = false;

        if ( vm_handler.imm_size )
        {
            result.operand.has_imm = true;
            result.operand.imm.imm_size = vm_handler.imm_size;
            const auto imm_val = get_imm( ctx, vm_handler.imm_size, entry.vip );

            if ( !imm_val.has_value() )
                return {};

            result.operand.imm.u =
                vm::instrs::decrypt_operand( vm_handler.transforms, imm_val.value(), entry.decrypt_key ).first;
        }

        if ( profile && vm_handler.imm_size && profile->extention == vm::handler::extention_t::sign_extend )
        {
            if ( result.operand.imm.u >> ( vm_handler.imm_size - 1 ) )
            {
                result.operand.imm.u =
                    ( ( std::numeric_limits< std::uint64_t >::max() >> vm_handler.imm_size ) << vm_handler.imm_size ) +
                    result.operand.imm.u;
            }
        }

        return result;
    }

    std::optional< std::vector< std::uint64_t > > get_switch_cases( vm::ctx_t &ctx, code_block_t &code_block )
    {
        // find the last LCONSTDW in this code block... it is the XOR decryption key...
        auto lconstdw_xor_key = std::find_if( code_block.vinstrs.rbegin(), code_block.vinstrs.rend(),
                                              []( const vm::instrs::virt_instr_t &vinstr ) -> bool {
                                                  auto profile = vm::handler::get_profile( vinstr.mnemonic_t );
                                                  return profile && profile->mnemonic == vm::handler::LCONSTDW;
                                              } );

        if ( lconstdw_xor_key == code_block.vinstrs.rend() )
            return {};

        // extract the address in which we are jmp'ing too, this gets compared lower in the algo...
        auto jmp_addr = code_block.vinstrs.back().trace_data.vsp.qword[ 0 ];

        // find the SREGDW that sets a virtual register to the encrypted rva we are jmping too...
        auto sregdw_jmp_addr = std::find_if( lconstdw_xor_key, code_block.vinstrs.rend(),
                                             [ & ]( const vm::instrs::virt_instr_t &vinstr ) -> bool {
                                                 if ( vinstr.mnemonic_t == vm::handler::SREGDW )
                                                 {
                                                     if ( ( ( ( std::uint32_t )vinstr.trace_data.vsp.qword[ 0 ] ) ^
                                                            lconstdw_xor_key->operand.imm.u ) == jmp_addr )
                                                     {
                                                         return true;
                                                     }
                                                 }
                                                 return false;
                                             } );

        if ( sregdw_jmp_addr == code_block.vinstrs.rend() )
            return {};

        // find the last READDW (the one above SREGDW...)
        auto readdw_jmp_tbl = std::find_if( sregdw_jmp_addr, code_block.vinstrs.rend(),
                                            [ & ]( const vm::instrs::virt_instr_t &vinstr ) -> bool {
                                                return vinstr.mnemonic_t == vm::handler::READDW;
                                            } );

        if ( readdw_jmp_tbl == code_block.vinstrs.rend() )
            return {};

        // find the last ADDQ which when computed results in the READDW address found above...
        auto addq_jmp_tbl_addr = std::find_if(
            readdw_jmp_tbl, code_block.vinstrs.rend(), [ & ]( const vm::instrs::virt_instr_t &vinstr ) -> bool {
                return vinstr.mnemonic_t == vm::handler::ADDQ &&
                       vinstr.trace_data.vsp.qword[ 0 ] + vinstr.trace_data.vsp.qword[ 1 ] ==
                           readdw_jmp_tbl->trace_data.vsp.qword[ 0 ];
            } );

        if ( addq_jmp_tbl_addr == code_block.vinstrs.rend() )
            return {};

        // sanity check...
        if ( !scn::executable( ctx.module_base, ctx.module_base + addq_jmp_tbl_addr->trace_data.vsp.qword[ 1 ] ) )
            return {};

        auto jmp_table =
            reinterpret_cast< std::uint32_t * >( ctx.module_base + addq_jmp_tbl_addr->trace_data.vsp.qword[ 1 ] );

        std::vector< std::uint64_t > result;
        for ( auto idx = 0u;; ++idx )
        {
            auto code_addr = code_block_addr( ctx, jmp_table[ idx ] ^ lconstdw_xor_key->operand.imm.u );

            // keep decrypting entries until we decrypt a value that doesnt land inside of an executable section... if
            // this allows too many cases we will need to check to see if the first virtual instruction of this block is
            // an SREGQ...
            if ( scn::executable( ctx.module_base, code_addr ) )
                result.push_back( code_addr );
            else // we finished decrypting the table...
                break;
        }
        return result;
    }

    std::optional< jcc_data > get_jcc_data( vm::ctx_t &vmctx, code_block_t &code_block )
    {
        // there is no branch for this as this is a vmexit...
        if ( code_block.vinstrs.back().mnemonic_t == vm::handler::VMEXIT )
            return jcc_data{ false, jcc_type::none };

        // find the last LCONSTDW... the imm value is the JMP xor decrypt key...
        // we loop backwards here (using rbegin and rend)...
        auto result = std::find_if( code_block.vinstrs.rbegin(), code_block.vinstrs.rend(),
                                    []( const vm::instrs::virt_instr_t &vinstr ) -> bool {
                                        auto profile = vm::handler::get_profile( vinstr.mnemonic_t );
                                        return profile && profile->mnemonic == vm::handler::LCONSTDW;
                                    } );

        if ( result == code_block.vinstrs.rend() )
            return jcc_data{ false, jcc_type::none };

        const auto xor_key = static_cast< std::uint32_t >( result->operand.imm.u );
        const auto &last_trace = code_block.vinstrs.back().trace_data;

        result = std::find_if(
            code_block.vinstrs.rbegin(), code_block.vinstrs.rend(),
            [ & ]( const vm::instrs::virt_instr_t &vinstr ) -> bool {
                if ( auto profile = vm::handler::get_profile( vinstr.mnemonic_t );
                     profile && profile->mnemonic == vm::handler::PUSHVSPQ )
                {
                    const auto possible_block_1 = code_block_addr( vmctx, vinstr.trace_data.vsp.qword[ 0 ] ^ xor_key ),
                               possible_block_2 = code_block_addr( vmctx, vinstr.trace_data.vsp.qword[ 1 ] ^ xor_key );

                    return scn::executable( vmctx.module_base, possible_block_1 ) &&
                           scn::executable( vmctx.module_base, possible_block_2 );
                }
                return false;
            } );

        // if there is not two branches...
        if ( result == code_block.vinstrs.rend() )
        {
            // see if this code block is actually a jmp table for a switch case....
            auto result = get_switch_cases( vmctx, code_block );
            if ( result.has_value() )
            {
                auto vec = result.value();
                jcc_data jcc;
                jcc.has_jcc = true;
                jcc.type = jcc_type::switch_case;
                jcc.block_addr = vec;
                return jcc;
            }
            else
            {
                jcc_data jcc;
                jcc.block_addr.push_back( code_block_addr( vmctx, last_trace ) );
                jcc.has_jcc = true;
                jcc.type = jcc_type::absolute;
                return jcc;
            }
        }

        jcc_data jcc;
        jcc.block_addr.push_back( code_block_addr( vmctx, result->trace_data.vsp.qword[ 0 ] ^ xor_key ) );
        jcc.block_addr.push_back( code_block_addr( vmctx, result->trace_data.vsp.qword[ 1 ] ^ xor_key ) );
        jcc.has_jcc = true;
        jcc.type = jcc_type::branching;
        return jcc;
    }

    std::uintptr_t code_block_addr( const vm::ctx_t &ctx, const vmp2::v2::entry_t &entry )
    {
        return ( ( entry.vsp.qword[ 0 ] & std::numeric_limits< u32 >::max() ) -
                 ( ctx.image_base & std::numeric_limits< u32 >::max() ) ) +
               ctx.module_base;
    }

    std::uintptr_t code_block_addr( const vm::ctx_t &ctx, const std::uint32_t lower_32bits )
    {
        return ( lower_32bits - ( ctx.image_base & std::numeric_limits< u32 >::max() ) ) + ctx.module_base;
    }
} // namespace vm::instrs