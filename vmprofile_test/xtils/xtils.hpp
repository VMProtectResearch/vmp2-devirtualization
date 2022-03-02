#pragma once
#define _CRT_SECURE_NO_WARNINGS
#pragma comment( lib, "ntdll.lib" )

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>

#include <Windows.h>
#include <ntstatus.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#define LOG_SIG "[xtils]"
#define LOG( ... )                                                                                                     \
    {                                                                                                                  \
        char buff[ 256 ];                                                                                              \
        snprintf( buff, sizeof buff, LOG_SIG##__VA_ARGS__ );                                                           \
        OutputDebugStringA( buff );                                                                                    \
    }

#define NT_HEADER( x )                                                                                                 \
    reinterpret_cast< PIMAGE_NT_HEADERS >( uint64_t( x ) + reinterpret_cast< PIMAGE_DOS_HEADER >( x )->e_lfanew )

#define PAGE_4K 0x1000
#define PAGE_2MB PAGE_4K * 512
#define PAGE_1GB PAGE_2MB * 512

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

namespace xtils
{
    using uq_handle = std::unique_ptr< void, decltype( &CloseHandle ) >;

    class um_t
    {
        using module_callback_t = std::function< bool( std::wstring, std::uintptr_t ) >;
        using module_map_t = std::map< std::wstring, std::uintptr_t >;

      public:
        static auto get_instance() -> um_t *
        {
            static um_t obj;
            return &obj;
        }

        auto open_binary_file( const std::string &file, std::vector< uint8_t > &data ) -> bool
        {
            auto file_size = std::filesystem::file_size( std::filesystem::path( file ) );

            if ( !file_size )
                return false;

            OFSTRUCT of;
            auto hfile = OpenFile( file.c_str(), &of, NULL );

            if ( ( HANDLE )hfile == INVALID_HANDLE_VALUE )
                return false;

            DWORD bytes_read;
            data.resize( file_size );
            return ReadFile( ( HANDLE )hfile, data.data(), file_size, &bytes_read, nullptr );
        }

        auto image_base( const char *image_path ) -> std::uintptr_t
        {
            char image_header[ PAGE_4K ];
            std::ifstream file( image_path, std::ios::binary );
            file.read( image_header, PAGE_4K );
            file.close();

            return NT_HEADER( image_header )->OptionalHeader.ImageBase;
        }

        auto image_size( const char *image_path ) -> std::uintptr_t
        {
            char image_header[ PAGE_4K ];
            std::ifstream file( image_path, std::ios::binary );
            file.read( image_header, PAGE_4K );
            file.close();

            return NT_HEADER( image_header )->OptionalHeader.SizeOfImage;
        }

        auto sigscan( void *base, std::uint32_t size, const char *pattern, const char *mask ) -> void *
        {
            static const auto check_mask = [ & ]( const char *base, const char *pattern, const char *mask ) -> bool {
                for ( ; *mask; ++base, ++pattern, ++mask )
                    if ( *mask == 'x' && *base != *pattern )
                        return false;
                return true;
            };

            size -= strlen( mask );
            for ( auto i = 0; i <= size; ++i )
            {
                void *addr = ( void * )&( ( ( char * )base )[ i ] );
                if ( check_mask( ( char * )addr, pattern, mask ) )
                    return addr;
            }

            return nullptr;
        }

        auto get_modules( std::uint32_t pid, module_map_t &module_map ) -> bool
        {
            uq_handle snapshot = { CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid ), &CloseHandle };

            if ( snapshot.get() == INVALID_HANDLE_VALUE )
                return false;

            MODULEENTRY32 module_info = { sizeof MODULEENTRY32 };
            Module32First( snapshot.get(), &module_info );

            // lowercase the module name...
            std::for_each( module_info.szModule, module_info.szModule + wcslen( module_info.szModule ) * 2,
                           []( wchar_t &c ) { c = ::towlower( c ); } );

            module_map[ module_info.szModule ] = reinterpret_cast< std::uintptr_t >( module_info.modBaseAddr );

            for ( Module32First( snapshot.get(), &module_info ); Module32Next( snapshot.get(), &module_info ); )
            {
                // lowercase the module name...
                std::for_each( module_info.szModule, module_info.szModule + wcslen( module_info.szModule ) * 2,
                               []( wchar_t &c ) { c = ::towlower( c ); } );

                module_map[ module_info.szModule ] = reinterpret_cast< std::uintptr_t >( module_info.modBaseAddr );
            }

            return true;
        }

        void each_module( std::uint32_t pid, module_callback_t callback )
        {
            module_map_t module_map;
            if ( !get_modules( pid, module_map ) )
                return;

            for ( auto &[ module_name, module_base ] : module_map )
                if ( !callback( module_name, module_base ) )
                    break;
        }

        // https://github.com/PierreCiholas/GetBaseAddress/blob/master/main.cpp#L7
        auto get_process_base( HANDLE proc_handle ) -> std::uintptr_t
        {
            HMODULE lph_modules[ 1024 ];
            DWORD needed = 0u;

            if ( !EnumProcessModules( proc_handle, lph_modules, sizeof( lph_modules ), &needed ) )
                return {};

            TCHAR mod_name[ MAX_PATH ];
            if ( !GetModuleFileNameEx( proc_handle, lph_modules[ 0 ], mod_name, sizeof( mod_name ) / sizeof( TCHAR ) ) )
                return {};

            return reinterpret_cast< std::uintptr_t >( lph_modules[ 0 ] );
        }

        auto get_pid( const wchar_t *proc_name ) -> std::uint32_t
        {
            uq_handle snapshot = { CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL ), &CloseHandle };

            if ( snapshot.get() == INVALID_HANDLE_VALUE )
                return {};

            PROCESSENTRY32W process_entry{ sizeof( PROCESSENTRY32W ) };
            Process32FirstW( snapshot.get(), &process_entry );
            if ( !std::wcscmp( proc_name, process_entry.szExeFile ) )
                return process_entry.th32ProcessID;

            for ( Process32FirstW( snapshot.get(), &process_entry ); Process32NextW( snapshot.get(), &process_entry ); )
                if ( !std::wcscmp( proc_name, process_entry.szExeFile ) )
                    return process_entry.th32ProcessID;

            return {};
        }

        auto get_handle( const wchar_t *proc_name, DWORD access = PROCESS_ALL_ACCESS ) -> uq_handle
        {
            std::uint32_t pid = 0u;
            if ( !( pid = get_pid( proc_name ) ) )
                return { NULL, &CloseHandle };

            return { OpenProcess( access, FALSE, pid ), &CloseHandle };
        }

        auto get_handle( std::uint32_t pid, DWORD access = PROCESS_ALL_ACCESS ) -> uq_handle
        {
            if ( !pid )
                return { NULL, &CloseHandle };
            return { OpenProcess( access, FALSE, pid ), &CloseHandle };
        }

        auto load_lib( HANDLE proc_handle, const char *dll_path ) -> std::uintptr_t
        {
            const auto dll_path_page =
                VirtualAllocEx( proc_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

            if ( !dll_path_page )
                return {};

            SIZE_T handled_bytes;
            if ( !WriteProcessMemory( proc_handle, dll_path_page, dll_path, strlen( dll_path ), &handled_bytes ) )
                return {};

            // +6 for string address
            // +16 for LoadLibrary address...
            unsigned char jmp_code[] = {
                0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 0x28
                0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rcx, &dllpath
                0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // mov rax, &LoadLibraryA
                0xFF, 0xD0,                                                 // call rax
                0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 0x28
                0x48, 0x89, 0x05, 0x01, 0x00, 0x00, 0x00,                   // mov [rip+1], rax
                0xC3                                                        // ret
            };

            *reinterpret_cast< std::uintptr_t * >( &jmp_code[ 6 ] ) =
                reinterpret_cast< std::uintptr_t >( dll_path_page );

            *reinterpret_cast< std::uintptr_t * >( &jmp_code[ 16 ] ) =
                reinterpret_cast< std::uintptr_t >( &LoadLibraryA );

            const auto jmp_code_page =
                VirtualAllocEx( proc_handle, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

            if ( !jmp_code_page )
                return {};

            if ( !WriteProcessMemory( proc_handle, jmp_code_page, jmp_code, sizeof jmp_code, &handled_bytes ) )
                return {};

            DWORD tid = 0u;
            auto thandle = CreateRemoteThread( proc_handle, nullptr, NULL, ( LPTHREAD_START_ROUTINE )jmp_code_page,
                                               nullptr, NULL, &tid );

            if ( thandle == INVALID_HANDLE_VALUE )
                return {};

            WaitForSingleObject( thandle, INFINITE );

            // read the base address out of the shellcode...
            std::uintptr_t module_base = 0u;
            if ( !ReadProcessMemory( proc_handle,
                                     reinterpret_cast< void * >( reinterpret_cast< std::uintptr_t >( jmp_code_page ) +
                                                                 sizeof jmp_code ),
                                     &module_base, sizeof module_base, &handled_bytes ) )
                return {};

            return module_base;
        }

        auto start_exec( const char *image_path, char *cmdline = nullptr, bool suspend = false )
            -> std::tuple< HANDLE, std::uint32_t, std::uintptr_t >
        {
            STARTUPINFOA info = { sizeof info };
            PROCESS_INFORMATION proc_info;

            if ( !CreateProcessA( image_path, cmdline, nullptr, nullptr, false,
                                  suspend ? CREATE_SUSPENDED | CREATE_NEW_CONSOLE : CREATE_NEW_CONSOLE, nullptr,
                                  nullptr, &info, &proc_info ) )
                return { {}, {}, {} };

            Sleep( 1 ); // sleep just for a tiny amount of time so that get_process_base works...
            return { proc_info.hProcess, proc_info.dwProcessId, get_process_base( proc_info.hProcess ) };
        }

        std::uintptr_t scan( std::uintptr_t base, std::uint32_t size, const char *pattern, const char *mask )
        {
            static const auto check_mask = [ & ]( const char *base, const char *pattern, const char *mask ) -> bool {
                for ( ; *mask; ++base, ++pattern, ++mask )
                    if ( *mask == 'x' && *base != *pattern )
                        return false;
                return true;
            };

            size -= strlen( mask );
            for ( auto i = 0; i <= size; ++i )
            {
                void *addr = ( void * )&( ( ( char * )base )[ i ] );
                if ( check_mask( ( char * )addr, pattern, mask ) )
                    return reinterpret_cast< std::uintptr_t >( addr );
            }
            return {};
        }

      private:
        explicit um_t()
        {
        }
    };

    class km_t
    {
        using kmodule_callback_t = std::function< bool( PRTL_PROCESS_MODULE_INFORMATION, const char * ) >;

      public:
        static auto get_instance() -> km_t *
        {
            static km_t obj;
            return &obj;
        };
        auto get_base( const char *drv_name ) -> std::uintptr_t
        {
            void *buffer = nullptr;
            DWORD buffer_size = NULL;

            auto status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 0xB ), buffer, buffer_size,
                                                    &buffer_size );

            while ( status == STATUS_INFO_LENGTH_MISMATCH )
            {
                VirtualFree( buffer, NULL, MEM_RELEASE );
                buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 0xB ), buffer, buffer_size,
                                                   &buffer_size );
            }

            if ( !NT_SUCCESS( status ) )
            {
                VirtualFree( buffer, NULL, MEM_RELEASE );
                return NULL;
            }

            const auto modules = static_cast< PRTL_PROCESS_MODULES >( buffer );
            for ( auto idx = 0u; idx < modules->NumberOfModules; ++idx )
            {
                const auto current_module_name =
                    std::string( reinterpret_cast< char * >( modules->Modules[ idx ].FullPathName ) +
                                 modules->Modules[ idx ].OffsetToFileName );

                if ( !_stricmp( current_module_name.c_str(), drv_name ) )
                {
                    const auto result = reinterpret_cast< std::uint64_t >( modules->Modules[ idx ].ImageBase );

                    VirtualFree( buffer, NULL, MEM_RELEASE );
                    return result;
                }
            }

            VirtualFree( buffer, NULL, MEM_RELEASE );
            return NULL;
        }

        void each_module( kmodule_callback_t callback )
        {
            void *buffer = nullptr;
            DWORD buffer_size = NULL;

            auto status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 0xB ), buffer, buffer_size,
                                                    &buffer_size );

            while ( status == STATUS_INFO_LENGTH_MISMATCH )
            {
                VirtualFree( buffer, NULL, MEM_RELEASE );
                buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 0xB ), buffer, buffer_size,
                                                   &buffer_size );
            }

            if ( !NT_SUCCESS( status ) )
            {
                VirtualFree( buffer, NULL, MEM_RELEASE );
                return;
            }

            const auto modules = static_cast< PRTL_PROCESS_MODULES >( buffer );
            for ( auto idx = 0u; idx < modules->NumberOfModules; ++idx )
            {
                auto full_path = std::string( reinterpret_cast< char * >( modules->Modules[ idx ].FullPathName ) );

                if ( full_path.find( "\\SystemRoot\\" ) != std::string::npos )
                    full_path.replace( full_path.find( "\\SystemRoot\\" ), sizeof( "\\SystemRoot\\" ) - 1,
                                       std::string( getenv( "SYSTEMROOT" ) ).append( "\\" ) );

                else if ( full_path.find( "\\??\\" ) != std::string::npos )
                    full_path.replace( full_path.find( "\\??\\" ), sizeof( "\\??\\" ) - 1, "" );

                if ( !callback( &modules->Modules[ idx ], full_path.c_str() ) )
                {
                    VirtualFree( buffer, NULL, MEM_RELEASE );
                    return;
                }
            }

            VirtualFree( buffer, NULL, MEM_RELEASE );
            return;
        }

        auto get_export( const char *drv_name, const char *export_name ) -> std::uintptr_t
        {
            void *buffer = nullptr;
            DWORD buffer_size = NULL;

            NTSTATUS status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 0xB ), buffer,
                                                        buffer_size, &buffer_size );

            while ( status == STATUS_INFO_LENGTH_MISMATCH )
            {
                VirtualFree( buffer, 0, MEM_RELEASE );
                buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                status = NtQuerySystemInformation( static_cast< SYSTEM_INFORMATION_CLASS >( 0xB ), buffer, buffer_size,
                                                   &buffer_size );
            }

            if ( !NT_SUCCESS( status ) )
            {
                VirtualFree( buffer, 0, MEM_RELEASE );
                return NULL;
            }

            const auto modules = static_cast< PRTL_PROCESS_MODULES >( buffer );
            for ( auto idx = 0u; idx < modules->NumberOfModules; ++idx )
            {
                // find module and then load library it
                const std::string current_module_name =
                    std::string( reinterpret_cast< char * >( modules->Modules[ idx ].FullPathName ) +
                                 modules->Modules[ idx ].OffsetToFileName );

                if ( !_stricmp( current_module_name.c_str(), drv_name ) )
                {
                    auto full_path = std::string( reinterpret_cast< char * >( modules->Modules[ idx ].FullPathName ) );

                    full_path.replace( full_path.find( "\\SystemRoot\\" ), sizeof( "\\SystemRoot\\" ) - 1,
                                       std::string( getenv( "SYSTEMROOT" ) ).append( "\\" ) );

                    const auto module_base = LoadLibraryExA( full_path.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES );

                    const auto image_base = reinterpret_cast< std::uintptr_t >( modules->Modules[ idx ].ImageBase );

                    // free the RTL_PROCESS_MODULES buffer...
                    VirtualFree( buffer, NULL, MEM_RELEASE );

                    const auto rva = reinterpret_cast< std::uintptr_t >( GetProcAddress( module_base, export_name ) ) -
                                     reinterpret_cast< std::uintptr_t >( module_base );

                    return image_base + rva;
                }
            }

            VirtualFree( buffer, NULL, MEM_RELEASE );
            return NULL;
        }

      private:
        explicit km_t()
        {
        }
    };

    class pe_t
    {
        using section_callback_t = std::function< bool( PIMAGE_SECTION_HEADER, std::uintptr_t ) >;

      public:
        static auto get_instance() -> pe_t *
        {
            static pe_t obj;
            return &obj;
        }

        // returns an std::vector containing all of the bytes of the section
        // and also the RVA from the image base to the beginning of the section...
        auto get_section( std::uintptr_t module_base, const char *section_name )
            -> std::pair< std::vector< std::uint8_t >, std::uint32_t >
        {
            const auto nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >(
                reinterpret_cast< PIMAGE_DOS_HEADER >( module_base )->e_lfanew + module_base );

            const auto section_header = reinterpret_cast< PIMAGE_SECTION_HEADER >(
                reinterpret_cast< std::uintptr_t >( nt_headers ) + sizeof( DWORD ) + sizeof( IMAGE_FILE_HEADER ) +
                nt_headers->FileHeader.SizeOfOptionalHeader );

            for ( auto idx = 0u; idx < nt_headers->FileHeader.NumberOfSections; ++idx )
            {
                const auto _section_name = reinterpret_cast< char * >( section_header[ idx ].Name );

                // sometimes section names are not null terminated...
                if ( !strncmp( _section_name, section_name, strlen( section_name ) - 1 ) )
                {
                    const auto section_base =
                        reinterpret_cast< std::uint8_t * >( module_base + section_header[ idx ].VirtualAddress );

                    const auto section_end =
                        reinterpret_cast< std::uint8_t * >( section_base + section_header[ idx ].Misc.VirtualSize );

                    std::vector< std::uint8_t > section_bin( section_base, section_end );
                    return { section_bin, section_header[ idx ].VirtualAddress };
                }
            }

            return { {}, {} };
        }

        void each_section( section_callback_t callback, std::uintptr_t module_base )
        {
            if ( !module_base )
                return;

            const auto nt_headers = reinterpret_cast< PIMAGE_NT_HEADERS >(
                reinterpret_cast< PIMAGE_DOS_HEADER >( module_base )->e_lfanew + module_base );

            const auto section_header = reinterpret_cast< PIMAGE_SECTION_HEADER >(
                reinterpret_cast< std::uintptr_t >( nt_headers ) + sizeof( DWORD ) + sizeof( IMAGE_FILE_HEADER ) +
                nt_headers->FileHeader.SizeOfOptionalHeader );

            for ( auto idx = 0u; idx < nt_headers->FileHeader.NumberOfSections; ++idx )
            {
                const auto _section_name = reinterpret_cast< char * >( section_header[ idx ].Name );

                // keep looping until the callback returns false...
                if ( !callback( &section_header[ idx ], module_base ) )
                    return;
            }
        }

      private:
        explicit pe_t(){};
    };
} // namespace xtils