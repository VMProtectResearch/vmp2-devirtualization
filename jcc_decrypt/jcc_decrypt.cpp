// jcc_decrypt.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>

#define FIRST_CONSTANT 0x9fbb4e4
#define SECOND_CONSTANT 0xf6044b1b

unsigned int jcc_decrypt( unsigned int encrypted_rva )
{
    unsigned int result = ~encrypted_rva & ~encrypted_rva;
    result = ~result & ~FIRST_CONSTANT;
    result = ~( ~encrypted_rva & ~SECOND_CONSTANT ) & ~result;
    return result;
}

int main()
{
    std::cout << "jcc decrypted value " << std::hex << jcc_decrypt( 0xB604E9F3 );
}