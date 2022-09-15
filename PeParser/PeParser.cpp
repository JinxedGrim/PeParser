#include "PeParser.h"

int main()
{
    system("Title PE Parser");
    std::cout << "PE Parser By JinxedGrim\n" << std::endl;

    uintptr_t IMPORTVA = 0;
    std::string Path = "";

    std::cout << "Enter PE Path: ";

    std::getline(std::cin, Path);

    PeParser PeParse = PeParser(Path);

    if (PeParse.InitHeaders())
    {
        std::cout << std::endl << "PE Is Valid" << std::endl;
    }
    else
    {
        std::cout << std::endl << "PE Is Not Valid" << std::endl;
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

    PeParse.CloseHandles();
    system("pause");
    return 0;
}
