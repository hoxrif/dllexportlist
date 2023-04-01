#pragma once
#ifndef PEDLL
#define PEDLL
#include <vector>
#include <iostream>
#ifndef OUT
#define OUT
#endif
#ifndef IN
#define IN
#endif


namespace pedll
{

	
	typedef std::pair<std::string, uint32_t> EXPORTED_FUNCTION_TYPE;
	typedef std::vector<EXPORTED_FUNCTION_TYPE> PEDLL_OUT_TYPE;

	typedef enum _PE_ERROR_TYPE
	{
		_DONE = 0,
		UNKNOW_FILE_TYPE,
		NOT_FOUND_EXPORT_TABLE
	}PE_ERROR_TYPE;

	typedef enum _ARCHITECTURE
	{
		_X86 = 0,
		_X64,
		_UKNOW
	}ARCHITECTURE;
	
	PE_ERROR_TYPE get_exported_functions(IN const std::string&, OUT PEDLL_OUT_TYPE&, OUT ARCHITECTURE&);


};



#endif 
