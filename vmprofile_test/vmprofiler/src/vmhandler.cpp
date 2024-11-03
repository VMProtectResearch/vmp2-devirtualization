#include <vmprofiler.hpp>

namespace vm::handler
{
    bool get( zydis_routine_t &vm_handler, std::uintptr_t handler_addr )
    {
        if ( !vm::util::flatten( vm_handler, handler_addr ) )
            return false;
        LOG(DEBUG) << "handler at " << std::hex << handler_addr;
        vm::util::print(vm_handler);

        LOG(DEBUG) << "after deobfuscate";
        vm::util::deobfuscate( vm_handler );
        vm::util::print(vm_handler);


        // find LEA RAX, [RDI+0xE0], else determine if the instruction is inside of calc_jmp...
        auto result = std::find_if( vm_handler.begin(), vm_handler.end(), []( const zydis_instr_t &instr ) -> bool {
            return instr.instr.mnemonic == ZYDIS_MNEMONIC_LEA &&
                   instr.instr.operands[ 0 ].reg.value == ZYDIS_REGISTER_RAX &&
                   instr.instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RDI &&
                   instr.instr.operands[ 1 ].mem.disp.value == 0xE0;
        } );

        // remove calc_jmp from the vm handler vector...
        if ( result != vm_handler.end() )
            vm_handler.erase( result, vm_handler.end() );
        else // locate the last mov al, [rsi],
             // then remove all instructions after that...
        {
            auto last = std::find_if( vm_handler.rbegin(), vm_handler.rend(), []( const zydis_instr_t &instr ) -> bool {
                return instr.instr.operand_count > 1 &&
                       ( instr.instr.mnemonic == ZYDIS_MNEMONIC_MOV || instr.instr.mnemonic == ZYDIS_MNEMONIC_MOVSX ||
                         instr.instr.mnemonic == ZYDIS_MNEMONIC_MOVZX ) &&
                       instr.instr.operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                       vm::util::reg::to64( instr.instr.operands[ 0 ].reg.value ) == ZYDIS_REGISTER_RAX &&
                       instr.instr.operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       instr.instr.operands[ 1 ].mem.base == ZYDIS_REGISTER_RSI;
            } );

            if ( last != vm_handler.rend() )
                vm_handler.erase( std::next( last ).base(), vm_handler.end() );
        }

        return true;
    }

    bool get_all( std::uintptr_t module_base, std::uintptr_t image_base, zydis_routine_t &vm_entry,
                  std::uintptr_t *vm_handler_table, std::vector< vm::handler::handler_t > &vm_handlers )
    {
        zydis_decoded_instr_t instr;
        if ( !vm::handler::table::get_transform( vm_entry, &instr ) )
            return false;

        LOG(INFO) << "Try get all handles";
        for ( auto idx = 0u; idx < 256; ++idx )
        {
            handler_t vm_handler;
            vm::transform::map_t transforms;
            // 提取handler的指令
            zydis_routine_t vm_handler_instrs;

            const auto decrypt_val = vm::handler::table::decrypt( instr, vm_handler_table[ idx ] );
            
            if ( !vm::handler::get( vm_handler_instrs, ( decrypt_val - image_base ) + module_base ) )
                return false;

            const auto has_imm = vm::handler::has_imm( vm_handler_instrs );
            const auto imm_size = vm::handler::imm_size( vm_handler_instrs );

            if (has_imm) {
              if(!vm::handler::get_operand_transforms(vm_handler_instrs,
                                                       transforms)) {
                LOG(ERROR) << "has_imm , but no transforms";
                return false;
              }
            }

            vm_handler.address = ( decrypt_val - image_base ) + module_base;
            vm_handler.instrs = vm_handler_instrs;
            vm_handler.imm_size = imm_size.has_value() ? imm_size.value() : 0u;
            vm_handler.transforms = transforms;
            vm_handler.profile = vm::handler::get_profile( vm_handler );  // 这个地方不判空,真正用到了再判断
            if (vm_handler.profile &&
                vm_handler.profile->imm_size != vm_handler.imm_size) { 
              // 基本上VM Handler识别错了
              return false;
            }
            vm_handlers.push_back( vm_handler );
        }

        return true;
    }

    bool has_imm( const zydis_routine_t &vm_handler )
    {
        zydis_instr_t instr_data;
        return vm::util::get_fetch_operand( vm_handler, instr_data );
    }

    std::optional< std::uint8_t > imm_size( const zydis_routine_t &vm_handler )
    {
        zydis_instr_t instr_data;
        if ( !vm::util::get_fetch_operand( vm_handler, instr_data ) )
            return {};

        return instr_data.instr.operands[ 1 ].size;
    }

    bool get_operand_transforms( zydis_routine_t &vm_handler, transform::map_t &transforms )
    {
        auto imm_fetch = vm::util::get_fetch_operand( vm_handler );

        if ( !imm_fetch.has_value() )
            return false;

        // this finds the first transformation which looks like:
        // transform rax, rbx <--- note these registers can be smaller so we to64 them...
        // 从取出Operand那条指令往下扫描
        auto transform_instr =
            std::find_if( imm_fetch.value(), vm_handler.end(), []( const zydis_instr_t &instr_data ) -> bool {
                return vm::transform::valid( instr_data.instr.mnemonic ) &&   // 在支持变换的列表中
                       (instr_data.instr.operands[ 0 ].actions & ZYDIS_OPERAND_ACTION_WRITE &&  // 写寄存器
                       util::reg::compare( instr_data.instr.operands[ 0 ].reg.value, ZYDIS_REGISTER_RAX ) &&    
                       util::reg::compare( instr_data.instr.operands[ 1 ].reg.value, ZYDIS_REGISTER_RBX ));
            } );

        if (transform_instr == vm_handler.end()) {
          return false;
        }

        // look for a primer/instruction that alters RAX prior to the 5 transformations...
        auto generic0 =
            std::find_if( imm_fetch.value(), transform_instr, []( const zydis_instr_t &instr_data ) -> bool {
                return vm::transform::valid( instr_data.instr.mnemonic ) &&
                       instr_data.instr.operands[ 0 ].actions & ZYDIS_OPERAND_ACTION_WRITE &&
                       util::reg::compare( instr_data.instr.operands[ 0 ].reg.value, ZYDIS_REGISTER_RAX ) &&
                       !util::reg::compare( instr_data.instr.operands[ 1 ].reg.value, ZYDIS_REGISTER_RBX );
            } );

        zydis_decoded_instr_t nogeneric0;
        nogeneric0.mnemonic = ZYDIS_MNEMONIC_INVALID;
        transforms[ transform::type::generic0 ] = generic0 != transform_instr ? generic0->instr : nogeneric0;

        // last transformation is the same as the first except src and dest are swwapped...
        transforms[ transform::type::rolling_key ] = transform_instr->instr;
        auto instr_copy = transform_instr->instr;
        instr_copy.operands[ 0 ].reg.value = transform_instr->instr.operands[ 1 ].reg.value;
        instr_copy.operands[ 1 ].reg.value = transform_instr->instr.operands[ 0 ].reg.value;
        transforms[ transform::type::update_key ] = instr_copy;

        // three generic transformations...
        for ( auto idx = static_cast< unsigned >( vm::transform::type::generic1 );
              idx < static_cast< unsigned >( vm::transform::type::update_key ); ++idx )
        {
            transform_instr =
                std::find_if( ++transform_instr, vm_handler.end(), []( const zydis_instr_t &instr_data ) -> bool {
                    return vm::transform::valid( instr_data.instr.mnemonic ) &&
                           instr_data.instr.operands[ 0 ].actions & ZYDIS_OPERAND_ACTION_WRITE &&
                           util::reg::compare( instr_data.instr.operands[ 0 ].reg.value, ZYDIS_REGISTER_RAX );
                } );

            if ( transform_instr == vm_handler.end() )
                return false;

            transforms[ static_cast< vm::transform::type >( idx ) ] = transform_instr->instr;
        }

        // 删除不合法的指令
        for (auto it = transforms.begin(); it != transforms.end();
             it++)  // erase the instrution that is invaild
        {
          if (it->second.mnemonic == ZYDIS_MNEMONIC_INVALID)
            it = transforms.erase(it);
        }
        return true;
    }

    vm::handler::profile_t *get_profile( handler_t &vm_handler )
    {
        static const auto vcontains = []( vm::handler::profile_t *vprofile, handler_t *vm_handler ) -> bool {

            zydis_routine_t::iterator contains = vm_handler->instrs.begin();
            for ( auto &instr : vprofile->signature )
            {
                contains =
                    std::find_if( contains, vm_handler->instrs.end(),
                                  [ & ]( zydis_instr_t &instr_data ) -> bool { return instr( instr_data.instr ); } );

                if ( contains == vm_handler->instrs.end() )
                    return false;
            }

            return true;
        };

        for ( auto profile : vm::handler::profile::all ) // 从内置的profile里找
            if ( vcontains( profile, &vm_handler ) )
                return profile;

        LOG(ERROR)
            << "Cant find correspond vm profile , need to implement it -> "
            << vm_handler.address;
        return nullptr;
    }

    vm::handler::profile_t *get_profile( vm::handler::mnemonic_t mnemonic )
    {
        auto result =
            std::find_if( vm::handler::profile::all.begin(), vm::handler::profile::all.end(),
                          [ & ]( vm::handler::profile_t *profile ) -> bool { return profile->mnemonic == mnemonic; } );

        return result != vm::handler::profile::all.end() ? *result : nullptr;
    }

    namespace table
    {
        std::uintptr_t *get( const zydis_routine_t &vm_entry )
        {
            const auto result =
                std::find_if( vm_entry.begin(), vm_entry.end(), []( const zydis_instr_t &instr_data ) -> bool {
                    const auto instr = &instr_data.instr;
                    // lea r12, vm_handlers... (always r12)...
                    return instr->mnemonic == ZYDIS_MNEMONIC_LEA &&
                           instr->operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                           instr->operands[ 0 ].reg.value == ZYDIS_REGISTER_R12 &&
                           !instr->raw.sib.base; // no register used for the sib base...
                } );

            if ( result == vm_entry.end() )
                return nullptr;

            ZyanU64 ptr = 0ull;
            ZydisCalcAbsoluteAddress( &result->instr, &result->instr.operands[ 1 ], result->addr, &ptr );
            LOG(INFO) << "Find Handle table " << std::hex << (void*)ptr;
            return reinterpret_cast< std::uintptr_t * >( ptr );
        }


        // 寻找解密handler的变换,下面的算法只支持一条指令的变换
        bool get_transform( const zydis_routine_t &vm_entry, zydis_decoded_instr_t *transform_instr )
        {
            auto handler_fetch =
                std::find_if( vm_entry.begin(), vm_entry.end(), [ & ]( const zydis_instr_t &instr_data ) -> bool {
                    const auto instr = &instr_data.instr;
                    
                    //example : mov     rdx, [r12+rax*8]
                    return instr->mnemonic == ZYDIS_MNEMONIC_MOV && instr->operand_count == 2 &&
                           instr->operands[ 1 ].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                           instr->operands[ 1 ].mem.base == ZYDIS_REGISTER_R12 &&
                           instr->operands[ 1 ].mem.index == ZYDIS_REGISTER_RAX &&
                           instr->operands[ 1 ].mem.scale == 8 &&
                           instr->operands[ 0 ].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                           ( instr->operands[ 0 ].reg.value == ZYDIS_REGISTER_RDX ||
                             instr->operands[ 0 ].reg.value == ZYDIS_REGISTER_RCX );
                } );

            // check to see if we found the fetch instruction and if the next instruction
            // is not the end of the vector...
            if ( handler_fetch == vm_entry.end() ||
                 // must be RCX or RDX... else something went wrong...
                 ( handler_fetch->instr.operands[ 0 ].reg.value != ZYDIS_REGISTER_RCX &&
                   handler_fetch->instr.operands[ 0 ].reg.value != ZYDIS_REGISTER_RDX ) )
                return false;

            //
            //从取handler到jmp到handler中间的指令中搜索
            //
            
            // find the next instruction that writes to RCX or RDX...
            // the register is determined by the vm handler fetch above...
            auto handler_transform =
                std::find_if( handler_fetch, vm_entry.end(), [ & ]( const zydis_instr_t &instr_data ) -> bool {
                    return vm::transform::valid( instr_data.instr.mnemonic ) &&
                           instr_data.instr.operands[ 0 ].reg.value == handler_fetch->instr.operands[ 0 ].reg.value &&
                           instr_data.instr.operands[ 0 ].actions & ZYDIS_OPERAND_ACTION_WRITE;
                } );

            if ( handler_transform == vm_entry.end() )
                return false;

            *transform_instr = handler_transform->instr;
            
            LOG(INFO) << "Find handler transform_instr";  // handler的地址是加密的,由一条指令解密出来
            vm::util::print(reinterpret_cast<zydis_decoded_instr_t&>(*transform_instr));

            return true;
        }

        std::uint64_t encrypt( zydis_decoded_instr_t &transform_instr, std::uint64_t val )
        {
            assert( transform_instr.operands[ 0 ].size == 64 );
            const auto operation = vm::transform::inverse[ transform_instr.mnemonic ];
            const auto bitsize = transform_instr.operands[ 0 ].size;
            const auto imm =
                vm::transform::has_imm( &transform_instr ) ? transform_instr.operands[ 1 ].imm.value.u : 0u;

            return vm::transform::apply( bitsize, operation, val, imm );
        }

        std::uint64_t decrypt( zydis_decoded_instr_t &transform_instr, std::uint64_t val )
        {
            assert( transform_instr.operands[ 0 ].size == 64 );
            const auto operation = transform_instr.mnemonic;
            const auto bitsize = transform_instr.operands[ 0 ].size;
            const auto imm =
                vm::transform::has_imm( &transform_instr ) ? transform_instr.operands[ 1 ].imm.value.u : 0u;

            return vm::transform::apply( bitsize, operation, val, imm );
        }
    } // namespace table
} // namespace vm::handler