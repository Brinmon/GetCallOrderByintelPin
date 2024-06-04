#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;//C++标准库中用于输出错误信息的标准错误流
using std::endl;//用于输出换行符并刷新流的操作符。
using std::string;

std::ostream* out = &cerr;

//使用命名行时可以添加-o
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

ADDRINT baseAddress;
std::vector<ADDRINT> addresses;
const int SIZE = 7;
std::string array[SIZE];
int idx = 0;


// 回调函数，在二进制映像加载时被调用
VOID ImageLoad(IMG img, VOID* v)
{
    // 获取第一个加载的模块的基地址
    if (baseAddress == 0)
    {
        baseAddress = IMG_LowAddress(img);

        const ADDRINT address1 = baseAddress + 0x12C30; // UEH_1  //A82D94 UEH_end
        const ADDRINT address2 = baseAddress + 0x12FCD; // SET_UEH
        const ADDRINT address3 = baseAddress + 0x12EA0; // SEH_1 
        const ADDRINT address4 = baseAddress + 0x13440; // SET_SEH
        const ADDRINT address5 = baseAddress + 0x13433; // 调用hook
        const ADDRINT address6 = baseAddress + 0x12BFF; // SET_VEH
        const ADDRINT address7 = baseAddress + 0x12F40; // 调用VEH_1,
        addresses.push_back(address1);
        addresses.push_back(address2);
        addresses.push_back(address3);
        addresses.push_back(address4);
        addresses.push_back(address5);
        addresses.push_back(address6);
        addresses.push_back(address7);
    }
}


// 回调函数
VOID InstructionCallback(ADDRINT address)
{
    if (address == addresses[0])
    {
        *out << "调用UEH_1." << std::endl;
        array[idx] = "调用UEH_1.";
    }
    else if (address == addresses[1])
    {
        *out << "设置SET_UEH函数." << std::endl;
        array[idx] = "设置SET_UEH函数.";
    }
    else if (address == addresses[2])
    {
        *out << "调用SEH_1." << std::endl;
        array[idx] = "调用SEH_1.";
    }
    else if (address == addresses[3])
    {
        *out << "设置SET_SEH函数." << std::endl;
        array[idx] = "设置SET_SEH函数.";
    }
    else if (address == addresses[4])
    {
        *out << "调用被hook的MessgaeBoxW" << std::endl;
        array[idx] = "调用被hook的MessgaeBoxW";
    }
    else if (address == addresses[5])
    {
        *out << "设置SET_VEH函数" << std::endl;
        array[idx] = "设置SET_VEH函数";
    }
    else if (address == addresses[6])
    {
        *out << "调用VEH_1" << std::endl;
        array[idx] = "调用VEH_1";
    }
    idx += 1;

}

// 插桩逻辑
VOID InstrumentInstruction(INS ins, VOID* v)
{
    ADDRINT address = INS_Address(ins);
    if (address == addresses[0] || address == addresses[1] || address == addresses[2] || address == addresses[3] || address == addresses[4] || address == addresses[5] || address == addresses[6])
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)InstructionCallback, IARG_ADDRINT, address, IARG_END);
    }
}

VOID Fini(INT32 code, VOID* v)
{
    cerr << "===============================================" << endl;
    // 打印数组中的值
    for (int i = 0; i < SIZE; ++i)
    {
        cerr << "array[" << i << "] = " << array[i] << std::endl;
    }
    cerr << "===============================================" << endl;
}

int main(int argc, char* argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    PIN_Init(argc, argv);

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }

    // 注册二进制映像加载时的回调函数
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // 在指令级别插入回调函数
    INS_AddInstrumentFunction(InstrumentInstruction, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}