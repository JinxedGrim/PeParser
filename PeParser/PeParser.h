#pragma once
#include <iostream>
#include <windows.h>
#include <vector>
#include <string>

//#pragma warning(disable : 6387)
//#pragma warning(disable : 6011)

class PeParser
{
public:
    PeParser()
    {

    }

    PeParser(std::string Path)
    {
        if (this->MapFileToMemory(Path, false, true))
        {
            std::cout << "Successfully Mapped: " << Path << " To Memory" << std::endl;
            this->IsFile = true;
        }
        else
        {
            std::cout << "[!] Failed To Map: " << Path << " To Memory" << std::endl;
        }
    }

    PeParser(uintptr_t Adder)
    {
        this->FileBytes = Adder;
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
            std::cout << "[!] Invalid Pointer" << std::endl;
        }
        std::cout << "[!] Unable To Find RVA" << std::endl;
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
                        //std::cout << "Found RVA In Section: [" << i << "/" << Sections << "] " << SectionHeader->Name << std::endl;
                        return FileOffset;
                    }
                }
            }
        }
        else
        {
            std::cout << "[!] Invalid Pointer" << std::endl;
        }
        std::cout << "[!] Unable To Find RVA" << std::endl;
        return NULL;
    }

    void CloseHandles()
    {
        if (this->IsFile == true)
        {
            if (this->FileBytes)
            {
                FlushViewOfFile((LPBYTE)this->FileBytes, 0);
                UnmapViewOfFile((LPBYTE)this->FileBytes);
            }

            if (this->FileHnd != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(this->FileHnd, this->FileSz, NULL, FILE_BEGIN);
                SetEndOfFile(this->FileHnd);
                CloseHandle(this->FileHnd);
            }

            if (this->FileMapHandle)
                CloseHandle(this->FileMapHandle);
        }
    }

    bool MapFileToMemory(std::string Path, bool LogSuccess = false, bool LogError = true)
    {
        this->FileHnd = CreateFileA(Path.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (FileHnd == INVALID_HANDLE_VALUE)
        {
            if (LogError)
            {
                std::cout << "[!] Unable To Open: " << Path << " GetLastError(): " << GetLastError() << std::endl;
            }
            CloseHandle(this->FileHnd);
            return false;
        }

        if (LogSuccess)
        {
            std::cout << "Successfully opened handle to File: " << Path << " : " << FileHnd << std::endl;
        }

        this->FileSz = GetFileSize(this->FileHnd, 0);

        if (!this->FileSz)
        {
            if (!LogError)
            {
                std::cout << "[!] Failed To Get File Size: GetLastError(): " << GetLastError() << std::endl;
            }
            CloseHandle(this->FileHnd);
            return false;
        }

        if (LogSuccess)
        {
            std::cout << "File Size: " << FileSz << " Bytes" << std::endl;
        }

        this->FileMapHandle = CreateFileMapping(this->FileHnd, NULL, PAGE_READWRITE, 0, this->FileSz, NULL);

        if (this->FileMapHandle == INVALID_HANDLE_VALUE)
        {
            if (LogError)
                std::cout << "[!] Unable To Create File Mapping: " << " GetLastError(): " << GetLastError() << std::endl;

            this->CloseHandles();

            return false;
        }
        else
        {
            if (LogSuccess)
                std::cout << "Successfully Created A File Mapping: " << this->FileMapHandle << std::endl;
        }

        #pragma warning(disable : 6387) // value is checked before function call yet warning still appears
        this->FileBytes = (uintptr_t)MapViewOfFile(this->FileMapHandle, FILE_MAP_ALL_ACCESS, NULL, NULL, this->FileSz);
        #pragma warning(default : 6387)

        if (!this->FileBytes)
        {
            if (LogError)
                std::cout << "[!] Failed To Map View Of File: GetLastError():" << GetLastError() << std::endl;

            this->CloseHandles();

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

    bool InitHeaders() // returns true if DOS and NT headers are initialized and PE is valid
    {
        if (!this->FileBytes)
        {
            std::cout << "[!] Failed To Init Headers" << std::endl;
            return false;
        }
        this->DosHeader = (PIMAGE_DOS_HEADER)this->FileBytes;
        this->NtHeader = (PIMAGE_NT_HEADERS)((BYTE*)(this->FileBytes + DosHeader->e_lfanew));
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE && NtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            std::cout << "[!] Not A Valid PE File" << std::endl;
            this->CloseHandles();
            return false;
        }
        else
        {
            return true;
        }

        return false;
    }

    uintptr_t GetSectionBase(PIMAGE_SECTION_HEADER SectionHeader)
    {
        if (!SectionHeader)
        {
            std::cout << "[!] Invalid Section Header" << std::endl;
            return 0;
        }

        return (uintptr_t)(this->FileBytes + SectionHeader->VirtualAddress);
    }

    uintptr_t GetOptionalDataDirectoryRVA(int DataType)
    {
        if (!this->NtHeader)
        {
            std::cout << "[!] NtHeaders Must Be Initialized Before Calling GetOptionalDataDirectoryRVA()" << std::endl;
            return NULL;
        }

        if (this->NtHeader->OptionalHeader.DataDirectory[DataType].Size != 0)
            return this->NtHeader->OptionalHeader.DataDirectory[DataType].VirtualAddress;
        else
        {
            std::cout << "[!] Failed To Get Data Directory " << std::endl;
            return NULL;
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(uintptr_t ImportRVA)
    {
        if (!ImportRVA)
        {
            std::cout << "[!] Invalid Pointer" << std::endl;
            return NULL;
        }
        uintptr_t Offset = RVA2FileOffset(ImportRVA, this->NtHeader);
        if (!Offset)
        {
            std::cout << "[!] Failed To Get Import Descriptor" << std::endl;
            return NULL;
        }
        return ((PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)this->FileBytes + Offset));
    }

    PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptorByName(std::string DllName, uintptr_t ImportRVA)
    {

        PIMAGE_IMPORT_DESCRIPTOR PImport = this->GetImportDescriptor(ImportRVA);

        if (!PImport || PImport->Name == NULL)
        {
            std::cout << "[!] Failed To Instantiate Import Descriptor" << std::endl;
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
            std::cout << "[!] Invalid Import Descriptor Passed To: GetImportINTThunkData" << std::endl;
            return NULL;
        }
        uintptr_t Offset = RVA2FileOffset(Dll->OriginalFirstThunk, this->NtHeader);
        return (PIMAGE_THUNK_DATA)((uintptr_t)this->FileBytes + Offset);
    }

    PIMAGE_THUNK_DATA GetImportIATThunkData(PIMAGE_IMPORT_DESCRIPTOR Dll)
    {
        if (!Dll)
        {
            std::cout << "[!] Invalid Import Descriptor Passed To: GetImportINTThunkData" << std::endl;
            return NULL;
        }
        uintptr_t Offset = RVA2FileOffset(Dll->FirstThunk, this->NtHeader);
        return (PIMAGE_THUNK_DATA)((uintptr_t)this->FileBytes + Offset);
    }

    PIMAGE_IMPORT_BY_NAME GetImageINTFromThunk(PIMAGE_THUNK_DATA INTEntry)
    {
        if (!INTEntry)
        {
            std::cout << "[!] Invalid Thunk Data Passed To: GetImageINTFromThunk" << std::endl;
            return NULL;
        }

        uintptr_t Offset = RVA2FileOffset(INTEntry->u1.AddressOfData, this->NtHeader);

        if ((!Offset) || (INTEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG))
        {
            std::cout << "[!] Failed To Resolve Function Name" << std::endl;
            return NULL;
        }

        return (PIMAGE_IMPORT_BY_NAME)((uintptr_t)this->FileBytes + Offset);
    }

    std::string GetImportNameFromDescriptor(PIMAGE_IMPORT_DESCRIPTOR PImportDescriptor)
    {
        if (!PImportDescriptor)
        {
            std::cout << "[!] Invalid Import Descriptor Passed To: GetImportNameFromDescriptor" << std::endl;
            return "";
        }

        uintptr_t NameOffset = RVA2FileOffset(PImportDescriptor->Name, this->NtHeader);

        if (!NameOffset)
        {
            std::cout << "[!] Failed To Get Offset Of Dll Name" << std::endl;
        }
        return (char*)(this->FileBytes + NameOffset);
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
            std::cout << "[!] NtHeader Not Initialized" << std::endl;
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
            std::cout << "[!] NtHeader Not Initialized" << std::endl;
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
            std::cout << "[!] Failed To Instantiate Import Descriptor" << std::endl;
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
            std::cout << "[!] Invalid Section Header Passed" << std::endl;
            return;
        }

        uintptr_t SectionBase = this->GetSectionBase(SectionHead);
        uintptr_t SectionLength = SectionHead->Misc.VirtualSize;
        int LineCount = 0;

        if (!SectionBase || !SectionLength)
        {
            std::cout << "[!] Invalid Section Header Passed" << std::endl;
            return;
        }

        std::cout << "Reading " << std::dec << SectionLength << " Bytes" << std::endl << std::endl;

        printf("0x%IX: ", SectionBase - this->FileBytes);

        for (uintptr_t i = 0; i < SectionLength; i++, LineCount++, SectionBase += 1)
        {
            if (LineCount == 32)
            {
                printf("\n0x%IX: ", SectionBase - this->FileBytes);
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
            Result = FindPatternInSection((PBYTE)(this->FileBytes + TextSection->VirtualAddress), TextSection->Misc.VirtualSize, Pattern, Mask);

            if (Result)
            {
                return Result;
            }
        }

        PageSection = GetSection("PAGE");

        if (PageSection && Result)
        {
            std::cout << "Scanning Section: " << PageSection << std::endl;

            Result = FindPatternInSection((PBYTE)(this->FileBytes + PageSection->VirtualAddress), PageSection->Misc.VirtualSize, Pattern, Mask);

            if (Result)
            {
                return Result;
            }
        }

        std::cout << "[!] Failed To Find Pattern" << std::endl;
        return 0;
    }

    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_NT_HEADERS NtHeader = NULL;
    PIMAGE_SECTION_HEADER SectionHeader = NULL;
    uintptr_t FileBytes = 0;
    DWORD FileSz = 0;
private:
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
};
