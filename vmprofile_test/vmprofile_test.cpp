//vmprofile doc
//https://docs.back.engineering/vmprofiler/index.html
//

#include <iostream>
#include <windows.h>

#include <vmprofiler.hpp>
#include <xtils.hpp>



using namespace std;

int main()
{
    
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        LoadLibraryExA("packed_demo.vmp.exe",
            NULL, DONT_RESOLVE_DLL_REFERENCES));

    if (!module_base)
    {
        std::printf("[!] please choose a excutable file\n");
        return 0;
    }

    const auto vm_entry_rva = 0x1076;   //offset base module_base
    const auto image_base = 0x140000000; //fixed base at 0x140000000
    const auto image_size = NT_HEADER(module_base)->OptionalHeader.SizeOfImage;
    vm::ctx_t vmctx(module_base, image_base, image_size, vm_entry_rva);

    if (!vmctx.init())
    {
        //error
        return -1;
    }




    





    return 0;
}

