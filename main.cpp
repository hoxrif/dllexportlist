#include "pedll.h"
#include <vector>
#include <iostream>

using namespace pedll;

int main(int argc, char** argv) 
{
    if (argc < 2)
    {
        std::cout << "invalid parameter" << std::endl;
        return -1;
    }

    const std::string path = argv[1];

    PEDLL_OUT_TYPE outList;
	ARCHITECTURE arch;
	
	PE_ERROR_TYPE result;
    
	if ((result = get_exported_functions(path, outList, arch)) == PE_ERROR_TYPE::_DONE)
	{
		std::cout << "file type is:" << (arch == ARCHITECTURE::_X86 ? "x86" : "x64") << std::endl;
		std::cout << "function name(s)" << "\t\t" << "offset(s)" << std::endl;
		for (PEDLL_OUT_TYPE::iterator func = outList.begin(); func != outList.end(); func++)
		{
            
			auto funcname = func->first.c_str();
			auto offset = func->second;
			std::cout << funcname << "\t\t" << "0x" << std::hex << offset << std::endl;
            
		}
	}
	else
	{
		if (result == PE_ERROR_TYPE::UNKNOW_FILE_TYPE)
		{
			std::cout << "unknow file type" << std::endl;
		}
		else if (result == PE_ERROR_TYPE::NOT_FOUND_EXPORT_TABLE)
		{
			std::cout << "not found export table" << std::endl;
		}
		else
		{
			std::cout << "unknow error" << std::endl;
		}

	}
	

	
	//std::cin.get();




    return 1;



}
