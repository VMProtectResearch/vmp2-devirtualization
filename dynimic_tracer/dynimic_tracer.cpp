#include <iostream>
#include <string>

#include <lifters.hpp>  //put llvm headers ahead triton

#include <triton/api.hpp>
#include <triton/ast.hpp>
#include <triton/x86Specifications.hpp>
#include <parse.hpp>
#include <windows.h>
#include <linuxpe>
#include <vmprofiler.hpp>
#include <triton_utils.hpp>


#pragma comment(linker, "/STACK:1073741824") //1M

#define debug printf

std::unordered_multimap<uint64_t, vm::handler::handler_t> map_handlers;

int main(int argc,char* argv[])
{
    std::string bin_path = cmd::parse(argc, argv, "-bin");
    uint32_t rva = std::stol(cmd::parse(argc, argv,"-rva"), 0, 16);

    auto module_base = (uint64_t)LoadLibraryA(bin_path.c_str());
    if (!module_base)
    {
        debug("[-]error bin path\n");
        return -1;
    }


    win::image_t<1>* image = (win::image_t<1>*)module_base;

    vm::ctx_t vmctx((uint64_t)module_base,0x140000000,image->get_nt_headers()->optional_header.size_image,rva);

    //make sure rva is valid
    if (!rva || !vmctx.init(true))
    {
        debug("[-]must give a vm-entry rva(make sure the 'push -> call 'format)\n");
        return -1;
    }
    
    std::transform(vmctx.vm_handlers.begin(), vmctx.vm_handlers.end(), std::inserter(map_handlers,map_handlers.end()), [](vm::handler::handler_t &a) {
        return std::make_pair((uint64_t)a.address, a);
        });

    debug("[-]ideally image base %p,current image base%p size:%x\n", image->get_nt_headers()->optional_header.image_base, module_base, image->get_nt_headers()->optional_header.size_image);

    //init llvm
    llvm::LLVMContext context;
    llvm::IRBuilder<> builder(context);

    lifters::_cvmp2 vmp2(context, builder, new llvm::Module("vmp2.cpp", context),vmctx);

    triton::API _triton;
    _triton.setArchitecture(triton::arch::ARCH_X86_64);

    auto vmexit_iter = std::find_if(map_handlers.begin(), map_handlers.end(), [](const std::pair<uint64_t,vm::handler::handler_t> h) {
        if (!strcmp(h.second.profile->name, "VMEXIT"))
            return true;
        else
            return false; });


    uint64_t pc = (uint64_t)module_base + rva;  //一开始的rip
    
    //
    //模拟执行直到出现vm-exit
    //

    //将pe文件全部映射进去
    std::vector<uint8_t> v_im_data((uint8_t*)(module_base), (uint8_t*)(module_base+ image->get_nt_headers()->optional_header.size_image));
    _triton.setConcreteMemoryAreaValue((uint64_t)module_base, v_im_data);

    
    //随便初始一下堆栈
    _triton.setConcreteRegisterValue(_triton.getRegister("rsp"), 0x14FF28);
    _triton.setConcreteMemoryAreaValue(0x140000, std::vector<uint8_t>(8000, 0));

    //初始化rflags
    _triton.setConcreteRegisterValue(_triton.getRegister("eflags"), 0x200);

    triton::arch::Instruction inst;
    while (true)
    {
        inst.setOpcode((uint8_t*)pc, 16);
        inst.setAddress(pc);

        if (!_triton.processing(inst))
        {
            debug("[-]not support this inst\n");
            return -1;
        }
        
        pc = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rip"));
        if(pc == vmexit_iter->second.address)
        {
            debug("[-]emit the vm-exit\n");

            auto lifter = lifters::_h_map.find(vmexit_iter->second.profile->mnemonic);
            if (lifter != lifters::_h_map.end() && lifter->second.hf)
            {
                lifter->second.hf(vmp2, (uint32_t)0);
            }

            break;
        }
        else //match other handler
        {
            auto handler_iter = std::find_if(vmctx.vm_handlers.begin(), vmctx.vm_handlers.end(), [&](vm::handler::handler_t h) {
                if (pc == h.address)
                    return true;
                else
                    return false; });

            if (handler_iter != vmctx.vm_handlers.end())
            {
                uint64_t rsi = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rsi"));
                debug("[vip %llx]%s\n", rsi, handler_iter->profile->name);

                auto lifter = lifters::_h_map.find(handler_iter->profile->mnemonic);
                if (lifter != lifters::_h_map.end() && lifter->second.hf)
                {
                    //
                    //读出rbp寄存器的值
                    //
                    uint64_t reg_rbp = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rbp"));

                    //当前的virtual ip
                    uint64_t reg_rsi = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rsi"));



                    if (handler_iter->profile->mnemonic == vm::handler::SREGQ || handler_iter->profile->mnemonic == vm::handler::LREGQ || handler_iter->profile->mnemonic == vm::handler::SREGDW || handler_iter->profile->mnemonic == vm::handler::LREGDW) //需要一个idx作为参数
                    {
                        uint64_t value_to_be_stored = ttutils::to_qword(_triton.getConcreteMemoryAreaValue((uint64_t)reg_rbp, 8));

                        assert(handler_iter->imm_size == 8); //1byte

                        uint8_t al = 0;
                        uint64_t rbx = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rbx"));

                        auto t = reg_rsi + (uint8_t)vmctx.exec_type * 1;
                        al = _triton.getConcreteMemoryValue(reg_rsi + (int)vmctx.exec_type * 1);

                        vm::transform::map_t trans{};
                        vm::handler::get_operand_transforms(handler_iter->instrs, trans);

                        std::pair<uint64_t, uint64_t> new_op;
                        auto [new_rax, new_rbx] = vm::instrs::decrypt_operand(trans, al, rbx);

                        //获得栈顶的值
                        //uint64_t rbp_0 = ttutils::to_qword(_triton.getConcreteMemoryAreaValue(reg_rbp, 8));

                        //将参数传给lifter,交给llvm
                        lifter->second.hf(vmp2, (uint8_t)new_rax);
                    }
                    else if (handler_iter->profile->mnemonic == vm::handler::LCONSTQ) //需要一个8字节常数作为参数
                    {
                        assert(handler_iter->imm_size == 64);
                        //uint64_t rbp_0 = ttutils::to_qword(_triton.getConcreteMemoryAreaValue(reg_rbp, 8));

                        uint64_t rsi_reg = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rsi"));
                        uint64_t encrypt_value = ttutils::to_qword(_triton.getConcreteMemoryAreaValue((uint64_t)rsi_reg+ (int)vmctx.exec_type * 8, 8));

                        uint64_t rax = encrypt_value;
                        uint64_t rbx = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rbx"));

                        vm::transform::map_t trans{};
                        vm::handler::get_operand_transforms(handler_iter->instrs, trans);

                        std::pair<uint64_t, uint64_t> new_op;
                        auto [new_rax, new_rbx] = vm::instrs::decrypt_operand(trans, rax, rbx);

                        //将参数传给lifter,交给llvm
                        lifter->second.hf(vmp2, (uint64_t)new_rax);
                    }
                    else if (handler_iter->profile->mnemonic == vm::handler::LCONSTDW || handler_iter->profile->mnemonic == vm::handler::LCONSTWSXDW || handler_iter->profile->mnemonic == vm::handler::LCONSTBSXDW)
                    {
                        uint32_t rbp_0 = ttutils::to_dword(_triton.getConcreteMemoryAreaValue(reg_rbp, 4));
                        lifter->second.hf(vmp2, (uint32_t)rbp_0);
                    }
                    else //不需要参数的lift
                    {
                        lifter->second.hf(vmp2, (uint64_t)0);
                    }
                }



            }
            else
                ;

        }
    }

    vmp2.llvm_module->print(outs(), nullptr);
    vmp2.complie();

    return 0;
}

