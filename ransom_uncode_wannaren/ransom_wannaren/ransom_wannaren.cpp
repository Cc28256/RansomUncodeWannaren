// ransom_wannaren.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "fstream" 
#include <Windows.h>
#include <openssl/rsa.h>
#include <openssl/rc4.h>
#include "openssl/pem.h"
#include "openssl/err.h"
#include "string.h"
#include "resource.h"
extern "C" {
#include "openssl/applink.c"
};
using namespace std;
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")


#define OPENSSLKEY "test.key"
#define RELESE(P) if (P){delete P;P = NULL;}
#define RELESE_ARRAY(P) if (P){delete[] P;P = NULL;}


FILE * pFile;
long lSize;
char * buffer;
size_t result;


// 释放资源文件
bool FreeResFile(DWORD dwResName, LPCSTR lpResType, LPCSTR lpFilePathName)
{
	HMODULE hInstance = ::GetModuleHandle(NULL);//得到自身实例句柄  
	
	HRSRC hResID = ::FindResource(hInstance, MAKEINTRESOURCE(dwResName), lpResType);//查找资源  
	HGLOBAL hRes = ::LoadResource(hInstance, hResID);//加载资源  
	LPVOID pRes = ::LockResource(hRes);//锁定资源  

	if (pRes == NULL)//锁定失败  
	{
		return FALSE;
	}
	int dwResSize = ::SizeofResource(hInstance, hResID);//得到待释放资源文件大小  
	HANDLE hResFile = CreateFile(lpFilePathName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);//创建文件  

	if (INVALID_HANDLE_VALUE == hResFile)
	{
		//创建文件失败  
		return FALSE;
	}

	int dwWritten = 0;//写入文件的大小     
	WriteFile(hResFile, pRes, dwResSize, (LPDWORD)&dwWritten, NULL);//写入文件  
	CloseHandle(hResFile);//关闭文件句柄  

	return (dwResSize == dwWritten);//若写入大小等于文件大小，返回成功，否则失败  
}

//RSA解密CR4密钥
char *my_decrypt(char *str, char *path_key) {
	char *p_de;
	RSA *p_rsa;
	FILE *file;
	int rsa_len;

	if ((file = fopen(path_key, "r")) == NULL) {

		perror("open key file error");

		return NULL;
	}

	if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {


		ERR_print_errors_fp(stdout);

		return NULL;
	}

	rsa_len = RSA_size(p_rsa);

	p_de = (char *)malloc(rsa_len + 1);

	memset(p_de, 0, rsa_len + 1);

	if (RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned
		char*)p_de, p_rsa, RSA_PKCS1_PADDING) < 0) {

		return NULL;
	}

	RSA_free(p_rsa);

	fclose(file);
	return p_de;
}

// 使用rc4解密到内存  
char *  TestRc4DecryptFile(char* file_data, int data_size,
	const char *rc4_dencrypt_key, int encrypt_chunk_size = 16)
{
	char * out_data_all = NULL;
	if ((out_data_all = (char*)malloc(data_size)) == NULL)
	{
		printf("no enough memory!\n");
		return 0;
	}
	memset(out_data_all, 0, data_size);
	
	//用指定密钥对一段内存进行加密，结果放在outbuffer中  
	char code[64] = { 0 };
	int codelen = sizeof(code);
	RC4_KEY rc4_key;
	RC4_set_key(&rc4_key, strlen(rc4_dencrypt_key), (unsigned char *)rc4_dencrypt_key);

	char *in_data = new char[encrypt_chunk_size + 1];
	char *out_data = new char[encrypt_chunk_size + 1];

	int i = 0;
	//循环解密
	while (i < data_size)
	{
		encrypt_chunk_size = (data_size - i) / 16 > 0 ? 16 : data_size % 16;
		memcpy(in_data, (file_data + i), encrypt_chunk_size);
		RC4(&rc4_key, encrypt_chunk_size, (unsigned char *)in_data, (unsigned char *)out_data);
		memcpy(out_data_all+i, out_data, encrypt_chunk_size);
		i += encrypt_chunk_size;
	};

	//解密后的数据文件仍然有标记wannaren，所以需要再处理一下
	char* restore_file_data = NULL;
	if ((restore_file_data = (char*)malloc(data_size - 0x12)) == NULL)
	{
		printf("no enough memory!\n");
		return 0;
	}
	memset(restore_file_data, 0, data_size - 0x12);
	memcpy(restore_file_data, out_data_all + 0x9, data_size - 0x12);

	RELESE_ARRAY(in_data);
	RELESE_ARRAY(out_data);
	RELESE_ARRAY(out_data_all);
	return restore_file_data;
}

void out_help()
{
	printf("	\nThis is a WannaRen decryption program\n\n");
	printf("	/h		--See how to use it\n\n");
	printf("	/u [filename]	--encryption a file name is original file name\n\n");
	printf("	--Files are only allowed to be WannaRen encryption file--\n");
	printf("	");

}


bool loadfile(char *loadFileName)
{
	// 一个不漏地读入整个文件，只能采用二进制方式打开
	pFile = fopen(loadFileName, "rb");
	if (pFile == NULL)
	{
		fputs("File error", stderr);
		printf("open file fail");
		return false;
	}

	// 获取文件大小 
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	// 分配内存存储整个文件
	buffer = (char*)malloc(sizeof(char)*lSize);
	if (buffer == NULL)
	{
		fputs("Memory error", stderr);
		printf("Memory alloc falil");
		return false;
	}

	// 将文件拷贝到buffer中 
	result = fread(buffer, 1, lSize, pFile);
	if (result != lSize)
	{
		fputs("Reading error", stderr);
		printf("Load file to memory falil");
		return false;
	}
	return true;
}


char* GetRC4key()
{
	char file_key[256] = { 0 };
	memcpy(file_key, (BYTE *)(buffer + 0xB), 0x100);
	FreeResFile(IDR_KEY3, "KEY", OPENSSLKEY);
	return my_decrypt(file_key, OPENSSLKEY);
}

int DecryptData(char *loadFileName)
{
	char* rc4Key = GetRC4key();
	char* file_data = NULL;//RC4加密的指针
	
	//计算数据位置，来分割获取数据
	if ((file_data = (char*)malloc(lSize - 0x11F)) == NULL)
	{
		printf("no enough memory!\n");
		return -1;
	}
	memset(file_data, 0, lSize - 0x11F );
	memcpy(file_data, (BYTE *)(buffer + 0x116), lSize - 0x11F);

	//调用RC4解密数据块，返回解密数据
	file_data = TestRc4DecryptFile(file_data, lSize - 0x11F, rc4Key);
	
	
	//保存到文件
	FILE *p2file;
	char outFile[MAX_PATH];
	memset(outFile, 0, sizeof(outFile));
	memcpy(outFile, loadFileName, strlen(loadFileName));
	//截断后缀
	char * set = strrchr(outFile, (char)0x2E);
	*set = 0x00;

	p2file = fopen(outFile, "wb");
	int a = fwrite(file_data, lSize - 0x11F-0x12, 1, p2file);
	fclose(p2file);
	/* 打印结果，并释放内存 */
	
	printf("succeed");
	RELESE_ARRAY(file_data);
	return 0;
}


int main(int argc, char * argv[]) {

	switch (argc)
	{
	case 1:
		out_help();
		break;
	case 2:
		if (!strcmp(argv[1], "/h"))
		{
			out_help();
		}
		else
		{
			printf("	\n**Error parameter**\n");
			out_help();
		}
		break;

	case 3:
		if (!strcmp(argv[1], "/u"))
		{
			printf("uncompress data ");
			if (loadfile(argv[2]));
				DecryptData(argv[2]);
		}
		else
		{
			out_help();
		}
		break;
	default:
		printf("	\n**Error parameter**\n");
		out_help();
		break;
	}
	return 0;
}

