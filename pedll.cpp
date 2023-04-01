// hoxrif :)
// Mustafa TERZI ~ 02.04.2023
// mustafaterzii@yandex.com
#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include "pedll.h"

//#define DEBUG

namespace pedll
{
	std::vector<uint8_t> open_file(const std::string & path)
	{
		std::ifstream file(path, std::ios::in | std::ios::ate | std::ios::binary);
		if (!file)
			return {};

		const auto sz = file.tellg();
		std::vector<uint8_t> buf(sz);
		file.seekg(0, std::ios::beg);

		file.read((char*)buf.data(), sz);
		file.close();
		return buf;
	}
	template<typename T>
	T GetNtHeaders(const uint8_t * lpBase)
	{
		const auto dos_header = (PIMAGE_DOS_HEADER)lpBase;
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;
		const auto nt_header = (T)(lpBase + dos_header->e_lfanew);
		return nt_header;
	}
	ARCHITECTURE IsFileCorrect(const uint8_t * lpBase)
	{
		const auto nt_headers = GetNtHeaders<PIMAGE_NT_HEADERS64>(lpBase);
		/* it doesnt matter -> PIMAGE_NT_HEADERS64 or PIMAGE_NT_HEADERS32
		   the variable "Signature" is DWORD both struct
		   and
		   "FileHeader" struct is same both of types so..
		   we can use cast operator or typename PIMAGE_NT_HEADERS64 or PIMAGE_NT_HEADERS32

		*/

		if (nt_headers == nullptr || nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return ARCHITECTURE::_UKNOW;
		if (nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			return ARCHITECTURE::_X64;
		if (nt_headers->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
			return ARCHITECTURE::_X86;

		return ARCHITECTURE::_UKNOW;

	}
	template<typename T>
	T* rva_to_va(const uint8_t * pBuf, const uint32_t relative_virtual_addr, ARCHITECTURE type)
	{
		
		if (type == ARCHITECTURE::_X86)
		{
			const auto nt_headers = GetNtHeaders<PIMAGE_NT_HEADERS32>(pBuf);
			const auto sections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)(nt_headers)+FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + (nt_headers)->FileHeader.SizeOfOptionalHeader);
			for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
			{
				const auto & section = sections[i];
				if (relative_virtual_addr >= section.VirtualAddress && relative_virtual_addr < section.VirtualAddress + section.SizeOfRawData)
					return (T*)(pBuf + (relative_virtual_addr - section.VirtualAddress + section.PointerToRawData));

			}
			return (T*)(pBuf + relative_virtual_addr);
		}
		else if (type == ARCHITECTURE::_X64)
		{
			const auto nt_headers = GetNtHeaders<PIMAGE_NT_HEADERS64>(pBuf);
			const auto sections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)(nt_headers)+FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) + (nt_headers)->FileHeader.SizeOfOptionalHeader);
			for (size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
			{
				const auto & section = sections[i];
				if (relative_virtual_addr >= section.VirtualAddress && relative_virtual_addr < section.VirtualAddress + section.SizeOfRawData)
					return (T*)(pBuf + (relative_virtual_addr - section.VirtualAddress + section.PointerToRawData));

			}
			return (T*)(pBuf + relative_virtual_addr);
		}
		else
		{
			return nullptr;
		}
	}
	PE_ERROR_TYPE get_exported_functions(IN const std::string & path,OUT PEDLL_OUT_TYPE & outList,OUT ARCHITECTURE & arc)
	{
		const auto buffer = open_file(path);
		const auto lpBase = buffer.data();
		auto filearc = IsFileCorrect(lpBase);
		//size_t c = 0;
		if (filearc == ARCHITECTURE::_UKNOW)
		{
#ifdef DEBUG
			std::cout << "file format is incorrect !" << std::endl;
#endif
			return PE_ERROR_TYPE::UNKNOW_FILE_TYPE;
		}
		else if (filearc == ARCHITECTURE::_X64)
		{
#ifdef DEBUG
			std::cout << "file architecture: x64" << std::endl;
#endif
			arc = ARCHITECTURE::_X64;
			auto ntHeaders = GetNtHeaders<PIMAGE_NT_HEADERS64>(lpBase);
			const auto exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!exportDir.Size || !exportDir.VirtualAddress)
			{
#ifdef DEBUG
				std::cout << "could not found export table of file" << std::endl;
#endif
				//return -2;
				return PE_ERROR_TYPE::NOT_FOUND_EXPORT_TABLE;
			}
#ifdef DEBUG
			std::cout << "function name(s);" << std::endl;
#endif
			auto exportDescriptor = rva_to_va<IMAGE_EXPORT_DIRECTORY>(lpBase, exportDir.VirtualAddress, filearc);
			for (DWORD i = 0; i < exportDescriptor->NumberOfNames; i++)
			{
				auto functionName = rva_to_va<const char>(lpBase, *rva_to_va<const uint32_t>(lpBase, exportDescriptor->AddressOfNames + i * 4, filearc), filearc);
                auto offset = *rva_to_va<uint32_t>(lpBase, exportDescriptor->AddressOfFunctions + i * 4, filearc);
				if (std::strlen(functionName))
				{
					outList.push_back(EXPORTED_FUNCTION_TYPE(functionName, offset));
				}
			}
		}
		else
		{
#ifdef DEBUG
			std::cout << "file architecture: x32" << std::endl;
#endif
			arc = ARCHITECTURE::_X86;
			auto ntHeaders = GetNtHeaders<PIMAGE_NT_HEADERS32>(lpBase);
			const auto exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!exportDir.Size || !exportDir.VirtualAddress)
			{
#ifdef DEBUG
				std::cout << "could not found export table of file" << std::endl;
#endif
				return PE_ERROR_TYPE::NOT_FOUND_EXPORT_TABLE;
			}
#ifdef DEBUG
			std::cout << "function name(s);" << std::endl;
#endif
			auto exportDescriptor = rva_to_va<IMAGE_EXPORT_DIRECTORY>(lpBase, exportDir.VirtualAddress, filearc);
			for (DWORD i = 0; i < exportDescriptor->NumberOfNames; i++)
			{
				auto functionName = rva_to_va<const char>(lpBase, *rva_to_va<const uint32_t>(lpBase, exportDescriptor->AddressOfNames + i * 4, filearc), filearc);
				auto offset = *rva_to_va<uint32_t>(lpBase, exportDescriptor->AddressOfFunctions + i * 4, filearc);//*file_rva_to_va<const uint32_t>(base, export_descriptor->AddressOfNameOrdinals + i * 4));
				if (std::strlen(functionName))
				{
					outList.push_back(EXPORTED_FUNCTION_TYPE(functionName, offset));
				}
			}
		}
		return PE_ERROR_TYPE::_DONE;
	}

};



