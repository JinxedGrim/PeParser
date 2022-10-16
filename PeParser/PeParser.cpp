#include "PeParser.h"

void CustomErrorCallBack(std::string Message)
{
    MessageBoxA(0, Message.c_str(), "CallBack", MB_OK);
}

int main()
{
    system("Title PE Parser");
    std::cout << "PE Parser By JinxedGrim\n" << std::endl;

    uintptr_t IMPORTVA = 0;
    std::string Path = "C:\\Users\\griff\\Desktop\\win32k.sys";

    //std::cout << "Enter PE Path: ";

    //std::getline(std::cin, Path);

    PeParser PeParse = PeParser(Path, CustomErrorCallBack);

    if (PeParse.InitHeaders())
    {
        std::cout << std::endl << "PE Is Valid" << std::endl;
    }
    else
    {
        std::cout << std::endl << "PE Is Not Valid" << std::endl;
        return 0;
    }

    std::cout << "PE Has: " << PeParse.NtHeader->FileHeader.NumberOfSections << " Sections" << std::endl << std::endl;

    PeParse.PrintAllSections();

    std::cout << std::endl;

    IMPORTVA = PeParse.GetOptionalDataDirectoryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT);

    if (!IMPORTVA)
    {
        std::cout << "[!] Failed To Find Import Directory" << std::endl;
        return 0;
    }

    std::cout << "Import Directory was found at RVA: " << std::hex << IMPORTVA << std::endl << "Imports: " << std::endl << "{" << std::endl;

    PeParse.PrintAllDllImports(IMPORTVA, true);

    std::cout << "}" << std::endl << std::endl << "All Imports Listed" << std::endl << std::endl;

    std::cout << "Scanning PE For Specific Imports" << std::endl << "{" << std::endl;

    PeParse.ScanImports({}, {"ZwMapViewOfSection", "MmMapIoSpace"}, IMPORTVA);

    std::cout << "}" << std::endl << std::endl << "Finished Scanning Imports" << std::endl << std::endl;

    PeParse.PrintSectionBytes(PeParse.GetSection(".text"));

    char Pattern[] = "\xEC\x28\x48\x8B\x05\xED\x28\x06\x00\x48\x85\xC0\x74\x06";
    char Mask[] = "xxxxxxxxxxxxxxxx";

    uintptr_t Addr = PeParse.FindPatternImage(Pattern, Mask);

    std::cout << "\nAddress Of Pattern: 0x" << std::hex << Addr - PeParse.PeAddress << std::endl;

    PeParse.UnmapFileFromMemory();

    system("pause");
    return 0;
}
