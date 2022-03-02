#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <filesystem>
#include "xtils.hpp"

int __cdecl main(int argc, const char** argv)
{
	auto utils = xtils::um_t::get_instance();
	const auto explorer_pid = 
		utils->get_pid(L"explorer.exe");

	const auto explorer_module_base = 
		utils->get_process_base(utils->get_handle(explorer_pid).get());

	std::printf("> explorer pid = 0x%x, module base = 0x%p\n", 
		explorer_pid, explorer_module_base);

	std::map<std::wstring, std::uintptr_t> modules;
	if (!utils->get_modules(explorer_pid, modules))
	{
		std::printf("[!] failed to get modules...\n");
		return -1;
	}

	std::printf("> user32.dll base = 0x%p\n", 
		modules[L"user32.dll"]);

	const auto [notepad_handle, notepad_pid, notepad_base] = 
		utils->start_exec("C:\\Windows\\System32\\notepad.exe");

	std::printf("> notepad handle = 0x%x, notepad pid = 0x%x, notepad_base = 0x%p\n", 
		notepad_handle, notepad_pid, notepad_base);

	const auto module_base = utils->load_lib(notepad_handle,
		(std::filesystem::current_path()
			.string() + "\\hello-world-x64.dll").c_str());

	std::printf("> module base = 0x%p\n", module_base);
	auto km_utils = xtils::km_t::get_instance();

	km_utils->each_module(
		[](PRTL_PROCESS_MODULE_INFORMATION kmodule_info, const char* module_name) -> bool 
		{
			std::printf("> module name = %s, module base = 0x%p\n",
				module_name, kmodule_info->ImageBase);

			return true;
		}
	);

	std::printf("> ntoskrnl base = 0x%p\n", km_utils->get_base("ntoskrnl.exe"));
}