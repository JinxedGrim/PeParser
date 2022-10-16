#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <string>

//#pragma warning(disable : 6387)
//#pragma warning(disable : 6011)

void LogError(std::string ErrMessage)
{
    std::cout << ErrMessage << std::endl;
}

class PeParser
{
private:
    void (*ErrorCallBack)(std::string) = LogError;
    HANDLE FileHnd = INVALID_HANDLE_VALUE;
    HANDLE FileMapHandle = INVALID_HANDLE_VALUE;
    bool IsFile = false;

    bool CheckPattern(PCHAR SectionAddress, PCHAR Pattern, PCHAR Mask)
    {
        for (; *Mask != 0; ++SectionAddress, ++Pattern, ++Mask) // Iterate through SectionBase bytes && Pttern Characters && Mask Characters
        {
            if (*Mask == 'x' && *SectionAddress != *Pattern) // If Mask == 'x' we must have the same byte as Pattern in SectionBase
            {
                return true; // If the above isnt true pattern isnt here
            }
        }
        return true;
    }

    uintptr_t RVA2FileOffset(uintptr_t RVA, PIMAGE_NT_HEADERS NtHeader)
    {
        if (this->IsFile == false)
        {
            return RVA;
        }

        if (RVA)
        {
            PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
            int Sections = NtHeader->FileHeader.NumberOfSections;
           
            for (int i = 0; i <= Sections; i++, SectionHeader++)
            {
                if (SectionHeader->VirtualAddress <= RVA)
                {
                    if (((uintptr_t)SectionHeader->VirtualAddress + (uintptr_t)SectionHeader->Misc.VirtualSize) > RVA)
                    {
                        RVA -= SectionHeader->VirtualAddress;
                        RVA += SectionHeader->PointerToRawData;
                        //std::cout << "Found RVA In Section: [" << i << "/" << Sections << "] " << SectionHeader->Name << std::endl;
                        return RVA;
                    }
                }
            }
        }
        else
        {
            ErrorCallBack("[!] Invalid Pointer");
        }

        ErrorCallBack("[!] Unable To Find RVA");
        
        return NULL;
    }

    uintptr_t FileOffsetRva(uintptr_t FileOffset, PIMAGE_NT_HEADERS NtHeader)
    {
        if (FileOffset)
        {
            PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);
            int Sections = NtHeader->FileHeader.NumberOfSections;
        
            for (int i = 0; i <= Sections; i++, SectionHeader++)
            {
                if (SectionHeader->PointerToRawData <= FileOffset)
                {
                    if (((uintptr_t)SectionHeader->PointerToRawData + (uintptr_t)SectionHeader->SizeOfRawData) > FileOffset)
                    {
                        FileOffset -= SectionHeader->PointerToRawData;
                        FileOffset += SectionHeader->VirtualAddress;
                        return FileOffset;
                    }
                }
            }
        }
        else
        {
            ErrorCallBack("[!] Invalid Pointer");
        }

        ErrorCallBack("[!] Unable To Find RVA");
 
        return NULL;
    }

public:

    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_NT_HEADERS NtHeader = NULL;
    PIMAGE_SECTION_HEADER SectionHeader = NULL;
    uintptr_t PeAddress = 0;

    PeParser()
    {

    }

    // Functionality: Calls MapFileToMemory and SetErrorCallBack
    // Parameters: Path (std::string), <optional>ErrorCallBack (void)(*)(std::string)
    // Other: If no callback is specified errors are logged to the console window
    PeParser(std::string Path, void(*ErrorCallBack)(std::string) = LogError)
    {
        this->ErrorCallBack = ErrorCallBack;

        if (this->MapFileToMemory(Path, false, true))
        {
            std::cout << "Successfully Mapped: " << Path << " To Memory" << std::endl;
        }
        else
        {
            ErrorCallBack("[!] Failed To Map: " + Path + " To Memory");
        }
    }

    // Functionality: Initializes PeAddress and sets ErrorCallBack 
    // Parameters: Path (std::string), <optional>ErrorCallBack (void)(*)(std::string)
    // Other: If no callback is specified errors are logged to the console window
    PeParser(uintptr_t Adder, void(*ErrorCallBack)(std::string) = LogError)
    {
        this->PeAddress = Adder;
        this->IsFile = false;
        this->SetErrorCallBack(ErrorCallBack);
    }

    ~PeParser()
    {
        if (this->IsFile)
            this->UnmapFileFromMemory();
    }

    // Functionality: Initializes the ErrorCallBack to use
    // Parameters: Pointer a callback of type void (*)(std::string)
    void SetErrorCallBack(void (*CallBackPointer)(std::string))
    {
        this->ErrorCallBack = CallBackPointer;
    }

    // Functionality: Maps a file to memory
    // Parameters: Path to file (std::string), <Optional>LogSuccess (bool), <optional>LogError (bool)
    // Return: True if successful
    bool MapFileToMemory(std::string Path, bool LogSuccess = false, bool LogError = true)
    {
        this->FileHnd = CreateFileA(Path.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
       
        if (this->FileHnd == INVALID_HANDLE_VALUE)
        {
            if (LogError)
            {
                ErrorCallBack("[!] Unable To Open: " + Path + " GetLastError(): " + std::to_string(GetLastError()));      
            }
           
            CloseHandle(this->FileHnd);

            return false;
        }

        if (LogSuccess)
        {
            std::cout << "Successfully opened handle to File: " << Path << " : " << FileHnd << std::endl;
        }

        DWORD FileSz = GetFileSize(this->FileHnd, 0);

        if (!FileSz)
        {
            if (!LogError)
            {
                ErrorCallBack("[!] Failed To Get File Size Error: " + GetLastError());
            }

            if (!CloseHandle(this->FileHnd))
            {
                ErrorCallBack("[!] Failed To Close Handle");
            }
          
            return false;
        }

        if (LogSuccess)
        {
            std::cout << "File Size: " << FileSz << " Bytes" << std::endl;
        }

        this->FileMapHandle = CreateFileMapping(this->FileHnd, NULL, PAGE_READWRITE, 0, FileSz, NULL);

        if (this->FileMapHandle == INVALID_HANDLE_VALUE)
        {
            if (LogError)
                ErrorCallBack("[!] Unable To Create File Mapping Error: " + GetLastError());

            if (!CloseHandle(this->FileHnd))
                ErrorCallBack("[!] Failed To Close Handle");

            if (!CloseHandle(this->FileMapHandle))
                ErrorCallBack("[!] Failed To Close Handle");

            return false;
        }
        else
        {
            if (LogSuccess)
                std::cout << "Successfully Created A File Mapping: " << this->FileMapHandle << std::endl;
        }

        #pragma warning(disable : 6387) // value is checked before function call yet warning still appears
        this->PeAddress = (uintptr_t)MapViewOfFile(this->FileMapHandle, FILE_MAP_ALL_ACCESS, NULL, NULL, FileSz);
        #pragma warning(default : 6387)

        if (!this->PeAddress)
        {
            if (LogError)
                ErrorCallBack("[!] Failed To Map View Of File Error: " + GetLastError());

            if(!UnmapViewOfFile((LPCVOID)this->PeAddress))
                ErrorCallBack("[!] Failed To Unmap File");

            if(!CloseHandle(this->FileHnd))
                ErrorCallBack("[!] Failed To Close Handle");

            if (!CloseHandle(this->FileMapHandle))
            {
                ErrorCallBack("[!] Failed To Close Handle");
            }

            return false;
        }
        else
        {
            if (LogSuccess)
                std::cout << "Successfully Mapped View Of File" << std::endl;
        }

        this->IsFile = true;
       
        return true;
    }

    // Functionality: Unmaps file from memory and closes handles
    // Return: True if successful (also return true if a file wasnt mapped)
    bool UnmapFileFromMemory()
    {
        if (!this->IsFile)
            return true;

        if(!UnmapViewOfFile((LPCVOID)this->PeAddress))
        {
            ErrorCallBack("[!] Failed To Unmap File");
            return false;
        }

        if (!CloseHandle(this->FileMapHandle))
        {
            ErrorCallBack("[!] Failed Close Hnadle");
            return false;
        }
        if (!CloseHandle(this->FileHnd))
        {
            ErrorCallBack("[!] Failed Close Hnadle");
            return false;
        }

        return true;
    }

    // Functionality: Initializes NT and DOS headers.
    // Return: True if successful and Pe is valid.
    // Other: Unmaps File from memory.
    bool InitHeaders()
    {
        if (!this->PeAddress)
        {
            ErrorCallBack("[!] Failed To Init Headers");
            return false;
        }

        this->DosHeader = (PIMAGE_DOS_HEADER)this->PeAddress;
        this->NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)(this->PeAddress + DosHeader->e_lfanew));

        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE && NtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            ErrorCallBack("[!] Not A Valid PE File");

            this->UnmapFileFromMemory();

            return false;
        }
        else
        {
            return true;
        }

        return false;
    }

    // Functionality: Calculates a section's base address.
    // Parameters: Pointer to a section header (PIMAGE_SECTION_HEADER).
    // Return: A pointer to the sections base.
    uintptr_t GetSectionBase(PIMAGE_SECTION_HEADER SectionHeader)
    {
        if (!SectionHeader)
        {
            ErrorCallBack("[!] Invalid Section Header");
            return 0;
        }

        return (uintptr_t)(this->PeAddress + SectionHeader->VirtualAddress);
    }

    // Functionality: Calculates a pointer to a image data directory.
    // Parameters: Data type (IMAGE_DIRECTORY_ENTRY).
    // Return: A pointer to the data directory.
    uintptr_t GetOptionalDataDirectoryRVA(int DataType)
    {
        if (!this->NtHeader)
        {
            ErrorCallBack("[!] NtHeaders Must Be Initialized Before Calling GetOptionalDataDirectoryRVA()");
            return NULL;
        }

        if (this->NtHeader->OptionalHeader.DataDirectory[DataType].Size != 0)
            return this->NtHeader->OptionalHeader.DataDirectory[DataType].VirtualAddress;
        else
        {
            ErrorCallBack("[!] Failed To Get Data Directory: " + DataType);
            return NULL;
        }
    }

    // Functionality: Calculates a pointer to the first import descriptor in the import list.
    // Parameters: Pointer to the import directory.
    // Return: A pointer to the first import descriptor in the import list.
    PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(uintptr_t ImportRVA)
    {
        if (!ImportRVA)
        {
            ErrorCallBack("[!] Invalid Pointer");
            return NULL;
        }

        uintptr_t Offset = RVA2FileOffset(ImportRVA, this->NtHeader);

        if (!Offset)
        {
            ErrorCallBack("[!] Failed To Get Import Descriptor");
            return NULL;
        }
        return ((PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)this->PeAddress + Offset));
    }

    PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptorByName(std::string DllName, uintptr_t ImportRVA)
    {

        PIMAGE_IMPORT_DESCRIPTOR PImport = this->GetImportDescriptor(ImportRVA);

        if (!PImport || PImport->Name == NULL)
        {
            ErrorCallBack("[!] Failed To Instantiate Import Descriptor");
            return NULL;
        }

        while (PImport->Name != NULL)
        {
            if (this->GetImportNameFromDescriptor(PImport) == DllName)
            {
                return PImport;
            }
            PImport++;
        }
        return NULL;
    }

    PIMAGE_THUNK_DATA GetImportINTThunkData(PIMAGE_IMPORT_DESCRIPTOR Dll)
    {
        if (!Dll)
        {
            ErrorCallBack("[!] Invalid Import Descriptor Passed To: GetImportINTThunkData");
            return NULL;
        }

        uintptr_t Offset = RVA2FileOffset(Dll->OriginalFirstThunk, this->NtHeader);

        return (PIMAGE_THUNK_DATA)((uintptr_t)this->PeAddress + Offset);
    }

    PIMAGE_THUNK_DATA GetImportIATThunkData(PIMAGE_IMPORT_DESCRIPTOR Dll)
    {
        if (!Dll)
        {
            ErrorCallBack("[!] Invalid Import Descriptor Passed To: GetImportINTThunkData");
            return NULL;
        }

        uintptr_t Offset = RVA2FileOffset(Dll->FirstThunk, this->NtHeader);

        return (PIMAGE_THUNK_DATA)((uintptr_t)this->PeAddress + Offset);
    }

    PIMAGE_IMPORT_BY_NAME GetImageINTFromThunk(PIMAGE_THUNK_DATA INTEntry)
    {
        if (!INTEntry)
        {
            ErrorCallBack("[!] Invalid Thunk Data Passed To: GetImageINTFromThunk");
            return NULL;
        }

        uintptr_t Offset = RVA2FileOffset(INTEntry->u1.AddressOfData, this->NtHeader);

        if ((!Offset) || (INTEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG))
        {
            ErrorCallBack("[!] Failed To Resolve Function Name");
            return NULL;
        }

        return (PIMAGE_IMPORT_BY_NAME)((uintptr_t)this->PeAddress + Offset);
    }

    std::string GetImportNameFromDescriptor(PIMAGE_IMPORT_DESCRIPTOR PImportDescriptor)
    {
        if (!PImportDescriptor)
        {
            ErrorCallBack("[!] Invalid Import Descriptor Passed To : GetImportNameFromDescriptor");
            return "";
        }

        uintptr_t NameOffset = RVA2FileOffset(PImportDescriptor->Name, this->NtHeader);

        if (!NameOffset)
        {
            ErrorCallBack("[!] Failed To Get Offset Of Dll Name");
        }
        return (char*)(this->PeAddress + NameOffset);
    }

    PIMAGE_THUNK_DATA GetFunctionThunkByName(PIMAGE_IMPORT_DESCRIPTOR Dll, std::string Function, bool Original = true)
    {
        PIMAGE_THUNK_DATA FirstINTEntry = GetImportINTThunkData(Dll);
        PIMAGE_THUNK_DATA FirstIATEntry = GetImportIATThunkData(Dll);

        while (FirstINTEntry->u1.Function != NULL)
        {
            PIMAGE_IMPORT_BY_NAME PImport = this->GetImageINTFromThunk(FirstINTEntry);

            if ((FirstINTEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                FirstIATEntry++;
                FirstINTEntry++;

                continue;
            }

            if (!PImport)
            {
                FirstIATEntry++;
                FirstINTEntry++;

                continue;
            }

            std::string Name = PSTR(PImport->Name);

            if (Name == Function)
            {
                if (Original)
                {
                    return FirstINTEntry;
                }
                else
                {
                    return FirstIATEntry;
                }
            }

            FirstINTEntry++;
            FirstIATEntry++;
        }
        return NULL;
    }

    PIMAGE_SECTION_HEADER GetSection(std::string SectionName)
    {
        if (!this->NtHeader)
        {
            ErrorCallBack("[!] NtHeader Not Initialized");
            return NULL;
        }

        this->SectionHeader = IMAGE_FIRST_SECTION(this->NtHeader);

        for (int i = 0; i < this->NtHeader->FileHeader.NumberOfSections; this->SectionHeader++, i++)
        {
            std::string SecName = PSTR(this->SectionHeader->Name);

            if (SecName == SectionName)
            {
                return this->SectionHeader;
            }
        }

        return NULL;
    }

    void PrintAllSections()
    {
        if (!this->NtHeader)
        {
            ErrorCallBack("[!] NtHeader Not Initialized");
        }

        #pragma warning(disable : 6011)
        this->SectionHeader = IMAGE_FIRST_SECTION(this->NtHeader);
        #pragma warning(default : 6011)

        std::cout << "Sections: ";
        for (int i = 0; i < this->NtHeader->FileHeader.NumberOfSections; this->SectionHeader++, i++)
        {
            std::cout << SectionHeader->Name << ", ";
        }

        std::cout << std::endl;
    }

    void PrintFunctionNames(PIMAGE_IMPORT_DESCRIPTOR Dll)
    {
        PIMAGE_THUNK_DATA FirstINTEntry = GetImportINTThunkData(Dll);

        while (FirstINTEntry->u1.Function != NULL)
        {
            if ((FirstINTEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                FirstINTEntry++;
              
                continue;
            }

            PIMAGE_IMPORT_BY_NAME PImport = this->GetImageINTFromThunk(FirstINTEntry);

            if (!PImport)
            {
                FirstINTEntry++;
               
                continue;
            }

            std::cout << "        Imported Function: [" << PImport->Hint << "] " << PSTR(PImport->Name) << " (0x" << std::hex << (uintptr_t)(FirstINTEntry->u1.Function) << ")" << std::endl;
           
            FirstINTEntry++;
        }
    }

    void PrintAllDllImports(uintptr_t ImportRVA, bool PrintFunctionNames = true)
    {
        PIMAGE_IMPORT_DESCRIPTOR PImportDescriptor = this->GetImportDescriptor(ImportRVA);
      
        if (!PImportDescriptor)
        {
            ErrorCallBack("[!] Failed To Instantiate Import Descriptor");
            return;
        }

        while (PImportDescriptor->Name != NULL)
        {
            std::cout << "    Import: " << this->GetImportNameFromDescriptor(PImportDescriptor) << std::endl;

            if (PrintFunctionNames)
                this->PrintFunctionNames(PImportDescriptor);

            PImportDescriptor++;
        }
    }

    void ScanImports(std::vector<std::string> ModulesToScan, std::vector<std::string> FunctionsToScan, uintptr_t ImportRVA)
    {
        PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = this->GetImportDescriptor(ImportRVA);

        while (ImportDescriptor->Name != NULL)
        {
            std::string ModName = this->GetImportNameFromDescriptor(ImportDescriptor);

            for (int i = 0; i < ModulesToScan.size(); i++)
            {
                if (ModName == ModulesToScan[i])
                {
                    std::cout << "    Scanning Module: " << ModName << std::endl;

                    PIMAGE_THUNK_DATA INTEntry = this->GetImportINTThunkData(ImportDescriptor);

                    while (INTEntry->u1.Function != NULL)
                    {
                        if ((INTEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                        {
                            INTEntry++;
                            continue;
                        }

                        PIMAGE_IMPORT_BY_NAME PImport = this->GetImageINTFromThunk(INTEntry);
                      
                        if ((!PImport))
                        {
                            INTEntry++;
                            continue;
                        }

                        std::string Import = std::string((PSTR)(PImport->Name));

                        if (!FunctionsToScan.empty())
                        {
                            for (int x = 0; x < FunctionsToScan.size(); x++)
                            {
                                if (FunctionsToScan[x] == Import)
                                {
                                    std::cout << "        Found Import: " << Import << std::endl;
                                }
                            }
                        }

                        INTEntry++;
                    }
                }
            }

            if (ModulesToScan.empty())
            {
                std::cout << "    Scanning Module: " << ModName << std::endl;

                PIMAGE_THUNK_DATA INTEntry = this->GetImportINTThunkData(ImportDescriptor);

                while (INTEntry->u1.Function != NULL)
                {
                    if ((INTEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                    {
                        INTEntry++;
                        continue;
                    }

                    PIMAGE_IMPORT_BY_NAME PImport = this->GetImageINTFromThunk(INTEntry);

                    if ((!PImport))
                    {
                        INTEntry++;
                        continue;
                    }

                    std::string Import = std::string((PSTR)(PImport->Name));

                    if (!FunctionsToScan.empty())
                    {
                        for (int x = 0; x < FunctionsToScan.size(); x++)
                        {
                            if (FunctionsToScan[x] == Import)
                            {
                                std::cout << "    Found Import: " << Import << std::endl;
                            }
                        }
                    }
                    INTEntry++;
                }
            }
            ImportDescriptor++;
        }
    }

    void PrintSectionBytes(PIMAGE_SECTION_HEADER SectionHead)
    {
        if (!SectionHead)
        {
            ErrorCallBack("[!] Invalid Section Header Passed");
            return;
        }

        uintptr_t SectionBase = this->GetSectionBase(SectionHead);
        uintptr_t SectionLength = SectionHead->Misc.VirtualSize;
        int LineCount = 0;

        if (!SectionBase || !SectionLength)
        {
            ErrorCallBack("[!] Invalid Section Header Passed");
            return;
        }

        std::cout << "Reading " << std::dec << SectionLength << " Bytes" << std::endl << std::endl;

        printf("0x%IX: ", SectionBase - this->PeAddress);

        for (uintptr_t i = 0; i < SectionLength; i++, LineCount++, SectionBase += 1)
        {
            if (LineCount == 32)
            {
                printf("\n0x%IX: ", SectionBase - this->PeAddress);
                LineCount = 0;
            }

            printf("%02X ", *(unsigned char*)SectionBase); // unsigned because signed chars are the normal -127 to +127 ascii characters while unsigned gives range of 0 to 255
        }

        std::cout << std::endl;
    }

    uintptr_t FindPatternInSection(PBYTE SectionBase, DWORD SectionLength, PCHAR Pattern, PCHAR Mask)
    {
        SectionLength -= (DWORD)strlen(Mask);

        for (DWORD i = 0; i < SectionLength; i++)
        {
            PCHAR Addr = (PCHAR)(SectionBase + i);

            if (CheckPattern(Addr, Pattern, Mask))
            {
                return (uintptr_t)Addr;
            }
        }

        return 0;
    }

    uintptr_t FindPatternImage(PCHAR Pattern, PCHAR Mask)
    {
        PIMAGE_SECTION_HEADER TextSection = this->GetSection(".text");
        PIMAGE_SECTION_HEADER PageSection = this->GetSection("PAGE");

        uintptr_t Result = 0x0;

        if (TextSection)
        {
            Result = FindPatternInSection((PBYTE)(this->PeAddress + TextSection->VirtualAddress), TextSection->Misc.VirtualSize, Pattern, Mask);

            if (Result)
            {
                return Result;
            }
        }

        PageSection = GetSection("PAGE");

        if (PageSection && Result)
        {
            std::cout << "Scanning Section: " << PageSection << std::endl;

            Result = FindPatternInSection((PBYTE)(this->PeAddress + PageSection->VirtualAddress), PageSection->Misc.VirtualSize, Pattern, Mask);

            if (Result)
            {
                return Result;
            }
        }

        ErrorCallBack("[!] Failed To Find Pattern");

        return 0;
    }
};
