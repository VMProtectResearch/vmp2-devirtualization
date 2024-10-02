//vmprofile doc
//https://docs.back.engineering/vmprofiler/index.html
//

#include <iostream>
#include <windows.h>

#include <vmprofiler.hpp>
#include <xtils.hpp>
#include <cli-parser.hpp>

using namespace std;

int main(int argc,const char* argv[])
{
    argparse::argument_parser_t parser("devirt", "");
    parser.add_argument().name("--bin").required(true).description("path to .vmp2 file...");
    parser.add_argument().name("--rva").required(true).description("rva based on module base...");

    auto err = parser.parse(argc, argv);
    if (err)
    {
        std::cout << err << std::endl;
        return -1;
    }


    

    const auto module_base = reinterpret_cast<std::uintptr_t>(
        LoadLibraryExA(parser.get<std::string>("bin").c_str(),
            NULL, DONT_RESOLVE_DLL_REFERENCES));

    if (!module_base)
    {
        std::printf("[!] --bin param error\n");
        return 0;
    }

    const auto vm_entry_rva = stoll(parser.get<std::string>("rva"),0,16);


    const auto image_size = NT_HEADER(module_base)->OptionalHeader.SizeOfImage;
    const auto image_base = 0x140000000; //must 0x140000000   bugbug?

    if (NT_HEADER(module_base)->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::printf("[!] dont support x86!\n");
        return -1;
    }

    vm::ctx_t vmctx(module_base, image_base, image_size, vm_entry_rva);

    if (!vmctx.init(true))
    {
        return -1;
    }

$start:
    //mov     al, [rsi-1]
    //lea     rsi, [rsi-1]
    uint8_t* vip = (uint8_t*)vmctx.opcode_stream - 1;
    //uint64_t rbx = vmctx.opcode_stream; //mov     rbx, rsi
    //uint8_t bl = static_cast<uint8_t>(rbx); //rolling key
    vm::util::Reg rbx(vmctx.opcode_stream - module_base + 0x140000000);
    uint64_t _rax; //for handlers to output info
    for (;;)
    {

//calc_jmp
        uint8_t op = *vip;

        for (auto& insn : vmctx.update_opcode) {
            if(!vm::transform::has_imm(&insn.instr)) //sub al,bl
                op = vm::transform::apply(8, insn.instr.mnemonic, op, rbx.r_8());
            else
                op = vm::transform::apply(8, insn.instr.mnemonic, op, insn.instr.operands[1].imm.value.u);
        }

        for (auto& insn : vmctx.update_rolling_key) {
            auto r = static_cast<uint64_t>(vm::transform::apply(8, insn.instr.mnemonic, rbx.r_8(), op));
            rbx.w_8(static_cast<uint8_t>(r));   //sub     bl, al
        }


        //get opcode correspond handler  ptr = handler address
        auto ptr = vmctx.vm_handlers.at(op);
//cacl_jmp



        vm::transform::map_t trans{};
        vm::handler::get_operand_transforms(ptr.instrs, trans);
        for (auto it = trans.begin(); it != trans.end(); it++) //erase the instrution that is invaild
        {
            if (it->second.mnemonic == ZYDIS_MNEMONIC_INVALID)
                it = trans.erase(it);
        }

        //apply the handle's transform to al(ax\eax\rax) and bl(bx\ebx\rbx)
        switch (ptr.imm_size)
        {
        case 8:
        {
            uint8_t al; //temp var
            vm::util::get_operand((uint8_t*)(vip + ((vmctx.exec_type == vmp2::exec_type_t::forward ? 1 : -1) * ptr.imm_size / 8)), ptr.imm_size, &al);

            for (const auto& insn : trans) {
                if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_AL)
                {
                    if (!vm::transform::has_imm(&insn.second)) //al bl
                        al = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, al, rbx.r_8());
                    else//al imm
                        al = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, al, insn.second.operands[1].imm.value.u);
                }
                else if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_BL)
                {
                    auto r = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, rbx.r_8(), al);
                    rbx.w_8(static_cast<uint8_t>(r));
                }
                else
                {
                    DebugBreak();
                }
            }


            _rax = (uint64_t)al;
        }
            break;
        case 16:
        {
            uint16_t ax; //temp var
            vm::util::get_operand((uint8_t*)(vip + ((vmctx.exec_type == vmp2::exec_type_t::forward ? 1 : -1) * ptr.imm_size / 8)), ptr.imm_size, &ax);

            for (const auto& insn : trans) {
                if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_AX)
                {
                    if (!vm::transform::has_imm(&insn.second))//ax bx
                        ax = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, ax, rbx.r_16());
                    else//ax imm
                        ax = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, ax, insn.second.operands[1].imm.value.u);
                }
                else if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_BX)
                {
                    auto r = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, rbx.r_16(), ax);
                    rbx.w_16(static_cast<uint16_t>(r));
                }
                else if ((insn.second.operands[0].reg.value == ZYDIS_REGISTER_AL && insn.second.operands[1].reg.value == ZYDIS_REGISTER_AH) || (insn.second.operands[0].reg.value == ZYDIS_REGISTER_AH && insn.second.operands[1].reg.value == ZYDIS_REGISTER_AL))//xchg al,ah  xchg ah,al
                {
                    ax = vm::transform::apply(16, insn.second.mnemonic, ax, 0); //
                }
                else
                    DebugBreak();
            }

            _rax = (uint64_t)ax;
        }
            break;
        case 32:
        {
            uint32_t eax; //temp var
            vm::util::get_operand((uint8_t*)(vip + ((vmctx.exec_type == vmp2::exec_type_t::forward ? 1 : -1) * ptr.imm_size / 8)), ptr.imm_size, &eax);

            //print handler's transform
            //for (const auto& insn : trans)
                //vm::util::print(insn.second);

            for (const auto& insn : trans) {
                if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_EAX)
                {
                    if (!vm::transform::has_imm(&insn.second))
                        eax = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, eax, rbx.r_32());
                    else
                        eax = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, eax, insn.second.operands[1].imm.value.u);
                }
                else if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_EBX)
                {
                    auto r = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, rbx.r_32(), eax);
                    rbx.w_32(static_cast<uint32_t>(r));
                }
                else
                {
                    DebugBreak();
                }
            }
        
            _rax = (uint64_t)eax;
        }
        break;
        case 64:
        {
            uint64_t rax; //temp var
            vm::util::get_operand((uint8_t*)(vip + ((vmctx.exec_type == vmp2::exec_type_t::forward ? 1 : -1) * ptr.imm_size / 8)), ptr.imm_size, &rax);

            for (const auto& insn : trans) {
                if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_RAX)
                {
                    if (!vm::transform::has_imm(&insn.second))
                        rax = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, rax, rbx.r_64());
                    else
                        rax = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, rax, insn.second.operands[1].imm.value.u);
                }
                else if (insn.second.operands[0].reg.value == ZYDIS_REGISTER_RBX)
                {
                    auto r = vm::transform::apply(ptr.imm_size, insn.second.mnemonic, rbx.r_64(), rax);
                    rbx.w_64(static_cast<uint64_t>(r));
                }
                else
                {
                    DebugBreak();
                }
            }

            _rax = (uint64_t)rax;
        }
        break;
        default:break;
        }//switch end

        printf("[vip %p][0x%p %s] ", vip, ptr.address, ptr.profile ? ptr.profile->name : "UNKNOW");
        if (ptr.profile && ptr.profile->rax_info)
            ptr.profile->rax_info(_rax);
        printf("\n");

        if (ptr.profile && ptr.profile->mnemonic == vm::handler::JMP) //vJcc(Change RSI Register)
        {
            //we need new rsi
            printf(">> find vJcc,need new rsi : ");
            uint64_t rsi;
            cin >>  hex >> rsi;
            vip = (uint8_t*)rsi;
            rbx = (uint64_t)vip + 1;         //mov     rbx, rsi   change rolling key again

            if (!vip || cin.fail())
                return 0;
        }
        else if (ptr.profile && ptr.profile->mnemonic == vm::handler::VMEXIT)
        {
            
            printf(">> find vm-exit,need new vm-entry(rva) : ");

            uint64_t new_rva;
            cin >> hex >> new_rva;

            //Re-entry has the potential to change vip(RSI)
            if (!new_rva || cin.fail())
                return 0;

            vmctx.update(new_rva);
            goto $start;   //reparse
        }
        else { 
                  // forward vip
            if (vmctx.exec_type == vmp2::exec_type_t::forward)
                vip = vip + 1 + ptr.imm_size / 8;
            else  //backward vip
                vip = vip - 1 - ptr.imm_size / 8;
        }
    }
    return 0;
}

