#include<vmprofiler.hpp>



namespace vm::virtual_machine_stream
{
	
	bool get(const zydis_routine_t& vm_entry, uint64_t& opstream_addr)
	{

		//mov     esi, [rsp+0A0h]   start

		//...(decrypt esi)

		//mov     rax, 100000000h
		//add     rsi, [rbp+0]
		
		//mov     al, [rsi-1]		end




		return true;
	}






}