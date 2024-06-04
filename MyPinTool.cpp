#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;//C++��׼�����������������Ϣ�ı�׼������
using std::endl;//����������з���ˢ�����Ĳ�������
using std::string;

std::ostream* out = &cerr;

//ʹ��������ʱ�������-o
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

ADDRINT baseAddress;
std::vector<ADDRINT> addresses;
const int SIZE = 7;
std::string array[SIZE];
int idx = 0;


// �ص��������ڶ�����ӳ�����ʱ������
VOID ImageLoad(IMG img, VOID* v)
{
    // ��ȡ��һ�����ص�ģ��Ļ���ַ
    if (baseAddress == 0)
    {
        baseAddress = IMG_LowAddress(img);

        const ADDRINT address1 = baseAddress + 0x12C30; // UEH_1  //A82D94 UEH_end
        const ADDRINT address2 = baseAddress + 0x12FCD; // SET_UEH
        const ADDRINT address3 = baseAddress + 0x12EA0; // SEH_1 
        const ADDRINT address4 = baseAddress + 0x13440; // SET_SEH
        const ADDRINT address5 = baseAddress + 0x13433; // ����hook
        const ADDRINT address6 = baseAddress + 0x12BFF; // SET_VEH
        const ADDRINT address7 = baseAddress + 0x12F40; // ����VEH_1,
        addresses.push_back(address1);
        addresses.push_back(address2);
        addresses.push_back(address3);
        addresses.push_back(address4);
        addresses.push_back(address5);
        addresses.push_back(address6);
        addresses.push_back(address7);
    }
}


// �ص�����
VOID InstructionCallback(ADDRINT address)
{
    if (address == addresses[0])
    {
        *out << "����UEH_1." << std::endl;
        array[idx] = "����UEH_1.";
    }
    else if (address == addresses[1])
    {
        *out << "����SET_UEH����." << std::endl;
        array[idx] = "����SET_UEH����.";
    }
    else if (address == addresses[2])
    {
        *out << "����SEH_1." << std::endl;
        array[idx] = "����SEH_1.";
    }
    else if (address == addresses[3])
    {
        *out << "����SET_SEH����." << std::endl;
        array[idx] = "����SET_SEH����.";
    }
    else if (address == addresses[4])
    {
        *out << "���ñ�hook��MessgaeBoxW" << std::endl;
        array[idx] = "���ñ�hook��MessgaeBoxW";
    }
    else if (address == addresses[5])
    {
        *out << "����SET_VEH����" << std::endl;
        array[idx] = "����SET_VEH����";
    }
    else if (address == addresses[6])
    {
        *out << "����VEH_1" << std::endl;
        array[idx] = "����VEH_1";
    }
    idx += 1;

}

// ��׮�߼�
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
    // ��ӡ�����е�ֵ
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

    // ע�������ӳ�����ʱ�Ļص�����
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // ��ָ������ص�����
    INS_AddInstrumentFunction(InstrumentInstruction, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}