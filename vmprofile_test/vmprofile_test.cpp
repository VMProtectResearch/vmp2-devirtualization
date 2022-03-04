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

    if (!vmctx.init())
    {
        return -1;
    }

    //mov     al, [rsi-1]
    //lea     rsi, [rsi-1]   
    uint8_t* vip = (uint8_t*)vmctx.opcode_stream - 1 ;
    uint64_t rbx = vmctx.opcode_stream; //mov     rbx, rsi
    uint8_t bl = static_cast<uint8_t>(rbx); //rolling key
    for (;;)
    {
        uint8_t al = *vip;

        for (auto& insn : vmctx.update_opcode) {
            if(!vm::transform::has_imm(&insn.instr)) //sub al,bl
                al = vm::transform::apply(8, insn.instr.mnemonic, al, bl);
            else
            al = vm::transform::apply(8, insn.instr.mnemonic, al, insn.instr.operands[1].imm.value.u);
        }

        for (auto& insn : vmctx.update_rolling_key) {
            bl = static_cast<uint64_t>(vm::transform::apply(8, insn.instr.mnemonic, rbx, al));
        }


        //get opcode correspond handler
        auto ptr = vmctx.vm_handlers[al];


        printf("[opcode %x] [handler at 0x%llx %s]\n", al, ptr.address,ptr.profile->name);

        vm::transform::map_t trans{};
        vm::handler::get_operand_transforms(ptr.instrs, trans);

        //apply the handle's transform to al(ax\eax\rax) and bl(bx\ebx\rbx)
        
        vm::util::get_operand<ptr.imm_size>



        if (vmctx.exec_type == vmp2::exec_type_t::forward)
            vip = vip + 1 + ptr.imm_size / 8;
        else
            vip = vip - 1 - ptr.imm_size / 8;

    }

    







    return 0;
}

