#include <iostream>

#include <triton/api.hpp>
#include <triton/ast.hpp>
#include <triton/x86Specifications.hpp>
#include <parse.hpp>
#include <windows.h>
#include <linuxpe>
#include <vmprofiler.hpp>

#pragma comment(linker, "/STACK:36777216")

#define debug printf

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

    debug("[-]ideally image base %p,current image base%p size:%x\n", image->get_nt_headers()->optional_header.image_base, module_base, image->get_nt_headers()->optional_header.size_image);

    triton::API _triton;
    _triton.setArchitecture(triton::arch::ARCH_X86_64);


    auto vmexit_iter = std::find_if(vmctx.vm_handlers.begin(), vmctx.vm_handlers.end(), [](vm::handler::handler_t h) {
        if (!strcmp(h.profile->name, "VMEXIT"))
            return true;
        else
            return false; });

    if (vmexit_iter == vmctx.vm_handlers.end())
    {
        debug("cant find vm-exit handler\n");
        return -1;
    }

    uint64_t pc = (uint64_t)module_base + rva;  //一开始的rip
    
    //
    //模拟执行直到出现vm-exit
    //

    //将pe文件全部映射进去
    std::vector<uint8_t> v_im_data((uint8_t*)(module_base), (uint8_t*)(module_base+ image->get_nt_headers()->optional_header.size_image));
    _triton.setConcreteMemoryAreaValue((uint64_t)module_base, v_im_data);


    //初始化堆栈
    //_triton.setConcreteRegisterValue(_triton.getRegister("rsp"), 0x1000);

    while (true)
    {
        triton::arch::Instruction inst;
        inst.setOpcode((uint8_t*)pc, 16);
        inst.setAddress(pc);

        if (!_triton.processing(inst))
        {
            debug("[-]not support this inst\n");
            return -1;
        }
        
        pc = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rip"));
        if (pc == vmexit_iter->address)
        {
            debug("[-]emit the vm-exit\n");
            


            char c;
            while ((c = getchar()))
            {
                if (c == 'q')
                    return -1;
                else if (c == 'g')
                    break;
            }

        }
        else //匹配其他handler
        {
            auto handler_iter = std::find_if(vmctx.vm_handlers.begin(), vmctx.vm_handlers.end(), [&](vm::handler::handler_t h) {
                if (pc == h.address)
                    return true;
                else
                    return false; });

            if (handler_iter != vmctx.vm_handlers.end())
            {
                uint64_t rsi = (uint64_t)_triton.getConcreteRegisterValue(_triton.getRegister("rsi"));
                debug("[vip %llx]%s\n",rsi ,handler_iter->profile->name);
            }
        }

        //debug("%llx : %s\n", inst.getAddress(), inst.getDisassembly().c_str());
    }





    return 0;
}

