#pragma once
#include <Windows.h>
#include <fstream>
#include <vector>

// declare
namespace PE
{
	struct Base
	{
		char* file = nullptr;
		size_t fileSize = 0;

		IMAGE_DOS_HEADER* dosHeader = nullptr;
		IMAGE_NT_HEADERS* ntHeaders = nullptr;
		IMAGE_SECTION_HEADER* sectionHeaders = nullptr;
		IMAGE_DATA_DIRECTORY* dataDirectories; // IMAGE_NUMBEROF_DIRECTORY_ENTRIES

		Base(char* file, size_t fileSize);
		Base(std::string fileName);

	private:
		void init(char* file, size_t fileSize);
	public:

		std::string getSectionName(size_t sectionIndex);
		size_t getFileAddress(size_t RVA, size_t* sectionIndex = nullptr);

		void printInfo();
	};
}

// Base
namespace PE
{
	Base::Base(char* file, size_t fileSize)
	{
		this->init(file, fileSize);
	}
	Base::Base(std::string fileName)
	{
		std::ifstream file(fileName, std::ios::binary);
		file.seekg(0, std::ios::end);
		size_t fileSize = (size_t)file.tellg();
		file.seekg(0);
		file.clear();

		char* fileData = (char*)malloc(fileSize);
		file.read(fileData, fileSize);
		file.close();

		this->init(fileData, fileSize);
	}

	void Base::init(char* file, size_t fileSize)
	{
		this->file = file;
		this->fileSize = fileSize;

		this->dosHeader = (IMAGE_DOS_HEADER*)this->file;
		this->ntHeaders = (IMAGE_NT_HEADERS*)(this->file + this->dosHeader->e_lfanew);
		this->sectionHeaders = (IMAGE_SECTION_HEADER*)(this->ntHeaders + 1);
		this->dataDirectories = this->ntHeaders->OptionalHeader.DataDirectory;
	}

	std::string Base::getSectionName(size_t sectionIndex)
	{
		return std::string((char*)(this->sectionHeaders[sectionIndex].Name), IMAGE_SIZEOF_SHORT_NAME);
	}

	size_t Base::getFileAddress(size_t RVA, size_t* sectionIndex)
	{
		for (size_t i = 0; i < this->ntHeaders->FileHeader.NumberOfSections; i++)
		{
			if (this->sectionHeaders[i].VirtualAddress <= RVA && RVA < this->sectionHeaders[i].VirtualAddress + this->sectionHeaders[i].SizeOfRawData)
			{
				if (sectionIndex)
					*sectionIndex = i;
				return this->sectionHeaders[i].PointerToRawData + (RVA - this->sectionHeaders[i].VirtualAddress);
			}
		}
		if (sectionIndex)
			*sectionIndex = (size_t)-1;
		return (size_t)-1;
	}

	void Base::printInfo()
	{
		std::cout << "========== MS-DOS HEADER ==========" << std::endl;
		std::cout << "e_magic:    " << this->dosHeader->e_magic    << std::endl;
		std::cout << "e_cblp:     " << this->dosHeader->e_cblp     << std::endl;
		std::cout << "e_cp:       " << this->dosHeader->e_cp       << std::endl;
		std::cout << "e_crlc:     " << this->dosHeader->e_crlc     << std::endl;
		std::cout << "e_cparhdr:  " << this->dosHeader->e_cparhdr  << std::endl;
		std::cout << "e_minalloc: " << this->dosHeader->e_minalloc << std::endl;
		std::cout << "e_maxalloc: " << this->dosHeader->e_maxalloc << std::endl;
		std::cout << "e_ss:       " << this->dosHeader->e_ss       << std::endl;
		std::cout << "e_sp:       " << this->dosHeader->e_sp       << std::endl;
		std::cout << "e_csum:     " << this->dosHeader->e_csum     << std::endl;
		std::cout << "e_ip:       " << this->dosHeader->e_ip       << std::endl;
		std::cout << "e_lfarlc:   " << this->dosHeader->e_lfarlc   << std::endl;
		std::cout << "e_oemid:    " << this->dosHeader->e_oemid    << std::endl;
		std::cout << "e_oeminfo:  " << this->dosHeader->e_oeminfo  << std::endl;
		std::cout << "e_lfanew:   " << this->dosHeader->e_lfanew   << std::endl;

		std::cout << "\n========== NATIVE HEADERS ==========" << std::endl;
		std::cout << "Signature:                                  " << this->ntHeaders->Signature                                  << std::endl;
		std::cout << "FileHeader.Machine:                         " << this->ntHeaders->FileHeader.Machine                         << std::endl;
		std::cout << "FileHeader.NumberOfSections:                " << this->ntHeaders->FileHeader.NumberOfSections                << std::endl;
		std::cout << "FileHeader.TimeDateStamp:                   " << this->ntHeaders->FileHeader.TimeDateStamp                   << std::endl;
		std::cout << "FileHeader.PointerToSymbolTable:            " << this->ntHeaders->FileHeader.PointerToSymbolTable            << std::endl;
		std::cout << "FileHeader.NumberOfSymbols:                 " << this->ntHeaders->FileHeader.NumberOfSymbols                 << std::endl;
		std::cout << "FileHeader.SizeOfOptionalHeader:            " << this->ntHeaders->FileHeader.SizeOfOptionalHeader            << std::endl;
		std::cout << "FileHeader.Characteristics:                 " << this->ntHeaders->FileHeader.Characteristics                 << std::endl;
		std::cout << "OptionalHeader.Magic:                       " << this->ntHeaders->OptionalHeader.Magic                       << std::endl;
		std::cout << "OptionalHeader.MajorLinkerVersion:          " << (uint32_t)this->ntHeaders->OptionalHeader.MajorLinkerVersion<< std::endl;
		std::cout << "OptionalHeader.MinorLinkerVersion:          " << (uint32_t)this->ntHeaders->OptionalHeader.MinorLinkerVersion<< std::endl;
		std::cout << "OptionalHeader.SizeOfCode:                  " << this->ntHeaders->OptionalHeader.SizeOfCode                  << std::endl;
		std::cout << "OptionalHeader.SizeOfInitializedData:       " << this->ntHeaders->OptionalHeader.SizeOfInitializedData       << std::endl;
		std::cout << "OptionalHeader.SizeOfUninitializedData:     " << this->ntHeaders->OptionalHeader.SizeOfUninitializedData     << std::endl;
		std::cout << "OptionalHeader.AddressOfEntryPoint:         " << this->ntHeaders->OptionalHeader.AddressOfEntryPoint         << std::endl;
		std::cout << "OptionalHeader.BaseOfCode:                  " << this->ntHeaders->OptionalHeader.BaseOfCode                  << std::endl;
		std::cout << "OptionalHeader.BaseOfData:                  " << this->ntHeaders->OptionalHeader.BaseOfData                  << std::endl;
		std::cout << "OptionalHeader.ImageBase:                   " << this->ntHeaders->OptionalHeader.ImageBase                   << std::endl;
		std::cout << "OptionalHeader.SectionAlignment:            " << this->ntHeaders->OptionalHeader.SectionAlignment            << std::endl;
		std::cout << "OptionalHeader.FileAlignment:               " << this->ntHeaders->OptionalHeader.FileAlignment               << std::endl;
		std::cout << "OptionalHeader.MajorOperatingSystemVersion: " << this->ntHeaders->OptionalHeader.MajorOperatingSystemVersion << std::endl;
		std::cout << "OptionalHeader.MinorOperatingSystemVersion: " << this->ntHeaders->OptionalHeader.MinorOperatingSystemVersion << std::endl;
		std::cout << "OptionalHeader.MajorImageVersion:           " << this->ntHeaders->OptionalHeader.MajorImageVersion           << std::endl;
		std::cout << "OptionalHeader.MinorImageVersion:           " << this->ntHeaders->OptionalHeader.MinorImageVersion           << std::endl;
		std::cout << "OptionalHeader.MajorSubsystemVersion:       " << this->ntHeaders->OptionalHeader.MajorSubsystemVersion       << std::endl;
		std::cout << "OptionalHeader.MinorSubsystemVersion:       " << this->ntHeaders->OptionalHeader.MinorSubsystemVersion       << std::endl;
		std::cout << "OptionalHeader.Win32VersionValue:           " << this->ntHeaders->OptionalHeader.Win32VersionValue           << std::endl;
		std::cout << "OptionalHeader.SizeOfImage:                 " << this->ntHeaders->OptionalHeader.SizeOfImage                 << std::endl;
		std::cout << "OptionalHeader.SizeOfHeaders:               " << this->ntHeaders->OptionalHeader.SizeOfHeaders               << std::endl;
		std::cout << "OptionalHeader.CheckSum:                    " << this->ntHeaders->OptionalHeader.CheckSum                    << std::endl;
		std::cout << "OptionalHeader.Subsystem:                   " << this->ntHeaders->OptionalHeader.Subsystem                   << std::endl;
		std::cout << "OptionalHeader.DllCharacteristics:          " << this->ntHeaders->OptionalHeader.DllCharacteristics          << std::endl;
		std::cout << "OptionalHeader.SizeOfStackReserve:          " << this->ntHeaders->OptionalHeader.SizeOfStackReserve          << std::endl;
		std::cout << "OptionalHeader.SizeOfStackCommit:           " << this->ntHeaders->OptionalHeader.SizeOfStackCommit           << std::endl;
		std::cout << "OptionalHeader.SizeOfHeapReserve:           " << this->ntHeaders->OptionalHeader.SizeOfHeapReserve           << std::endl;
		std::cout << "OptionalHeader.SizeOfHeapCommit:            " << this->ntHeaders->OptionalHeader.SizeOfHeapCommit            << std::endl;
		std::cout << "OptionalHeader.LoaderFlags:                 " << this->ntHeaders->OptionalHeader.LoaderFlags                 << std::endl;
		std::cout << "OptionalHeader.NumberOfRvaAndSizes:         " << this->ntHeaders->OptionalHeader.NumberOfRvaAndSizes         << std::endl;

		std::cout << "\n========== SECTIONS ==========" << std::endl;
		for (size_t i = 0; i < this->ntHeaders->FileHeader.NumberOfSections; i++)
		{
			std::cout << " - " << i << " - " << std::endl;
			std::cout << "Name:                 " << this->getSectionName(i) << std::endl;
			std::cout << "Misc.PhysicalAddress: " << this->sectionHeaders[i].Misc.PhysicalAddress << std::endl;
			std::cout << "Misc.VirtualSize:     " << this->sectionHeaders[i].Misc.VirtualSize 	  << std::endl;
			std::cout << "VirtualAddress:       " << this->sectionHeaders[i].VirtualAddress 	  << std::endl;
			std::cout << "SizeOfRawData:        " << this->sectionHeaders[i].SizeOfRawData 		  << std::endl;
			std::cout << "PointerToRawData:     " << this->sectionHeaders[i].PointerToRawData 	  << std::endl;
			std::cout << "PointerToRelocations: " << this->sectionHeaders[i].PointerToRelocations << std::endl;
			std::cout << "PointerToLinenumbers: " << this->sectionHeaders[i].PointerToLinenumbers << std::endl;
			std::cout << "NumberOfRelocations:  " << this->sectionHeaders[i].NumberOfRelocations  << std::endl;
			std::cout << "NumberOfLinenumbers:  " << this->sectionHeaders[i].NumberOfLinenumbers  << std::endl;
			std::cout << "Characteristics:      " << this->sectionHeaders[i].Characteristics 	  << std::endl;
		}

		std::cout << "\n========== DATA DIRECTORIES ==========" << std::endl;
		for (size_t i = 0; i < this->ntHeaders->OptionalHeader.NumberOfRvaAndSizes; i++)
		{
			std::cout << " - " << i << " - " << std::endl;
			std::cout << "VirtualAddress: " << this->ntHeaders->OptionalHeader.DataDirectory[i].VirtualAddress << std::endl;
			std::cout << "Size:           " << this->ntHeaders->OptionalHeader.DataDirectory[i].Size << std::endl;

			size_t sectionIndex = 0;
			size_t fileAddress = this->getFileAddress(this->ntHeaders->OptionalHeader.DataDirectory[i].VirtualAddress, &sectionIndex);
			std::cout << "Section:        " << (fileAddress < this->fileSize ? this->getSectionName(sectionIndex) : "NULL") << std::endl;
			std::cout << "FileAddress:    " << (fileAddress < this->fileSize ? std::to_string(fileAddress) : "NULL") << std::endl;
		}

		size_t importDescriptorFileAddress = this->getFileAddress(this->dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (importDescriptorFileAddress < this->fileSize)
		{
			std::cout << "\n========== IMPORT TABLE ENTRIES ==========" << std::endl;
			for (size_t i = 0; i < this->dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); i++)
			{
				IMAGE_IMPORT_DESCRIPTOR* e = (IMAGE_IMPORT_DESCRIPTOR*)(this->file + importDescriptorFileAddress) + i;
				size_t nameFileAddress = this->getFileAddress(e->Name);

				std::cout << " - " << i << " - " << std::endl;
				std::cout << "Characteristics:    " << e->Characteristics << std::endl;
				std::cout << "OriginalFirstThunk: " << e->OriginalFirstThunk << std::endl;
				std::cout << "TimeDateStamp:      " << e->TimeDateStamp << std::endl;
				std::cout << "ForwarderChain:     " << e->ForwarderChain << std::endl;
				std::cout << "Name:               " << (nameFileAddress < this->fileSize ? this->file + nameFileAddress : "NULL") << std::endl;
				std::cout << "FirstThunk:         " << e->FirstThunk << std::endl;
			}
		}

		size_t tlsHeaderFileAddress = this->getFileAddress(this->dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		if (tlsHeaderFileAddress < this->fileSize)
		{
			IMAGE_TLS_DIRECTORY32* TLSHeader = (IMAGE_TLS_DIRECTORY32*)(this->file + tlsHeaderFileAddress);
			std::cout << "\n========== TLS DIRECTORY ==========" << std::endl;
			std::cout << "StartAddressOfRawData: " << TLSHeader->StartAddressOfRawData << std::endl;
			std::cout << "EndAddressOfRawData:   " << TLSHeader->EndAddressOfRawData << std::endl;
			std::cout << "AddressOfIndex:        " << TLSHeader->AddressOfIndex << std::endl;
			std::cout << "AddressOfCallBacks:    " << TLSHeader->AddressOfCallBacks << std::endl;
			std::cout << "SizeOfZeroFill:        " << TLSHeader->SizeOfZeroFill << std::endl;
			std::cout << "Characteristics:       " << TLSHeader->Characteristics << std::endl;
		}


		size_t loadConfigFileAddress = this->getFileAddress(this->dataDirectories[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		if (loadConfigFileAddress < this->fileSize)
		{
			IMAGE_LOAD_CONFIG_DIRECTORY32* loadConfigHeader = (IMAGE_LOAD_CONFIG_DIRECTORY32*)(this->file + loadConfigFileAddress);
			std::cout << "\n========== LOAD CONFIG DIRECTORY ==========" << std::endl;
			std::cout << "Size                                                " << loadConfigHeader->Size << std::endl;
			std::cout << "TimeDateStamp                                       " << loadConfigHeader->TimeDateStamp << std::endl;
			std::cout << "MajorVersion                                        " << loadConfigHeader->MajorVersion << std::endl;
			std::cout << "MinorVersion                                        " << loadConfigHeader->MinorVersion << std::endl;
			std::cout << "GlobalFlagsClear                                    " << loadConfigHeader->GlobalFlagsClear << std::endl;
			std::cout << "GlobalFlagsSet                                      " << loadConfigHeader->GlobalFlagsSet << std::endl;
			std::cout << "CriticalSectionDefaultTimeout                       " << loadConfigHeader->CriticalSectionDefaultTimeout << std::endl;
			std::cout << "DeCommitFreeBlockThreshold                          " << loadConfigHeader->DeCommitFreeBlockThreshold << std::endl;
			std::cout << "DeCommitTotalFreeThreshold                          " << loadConfigHeader->DeCommitTotalFreeThreshold << std::endl;
			std::cout << "LockPrefixTable                                     " << loadConfigHeader->LockPrefixTable << std::endl;
			std::cout << "MaximumAllocationSize                               " << loadConfigHeader->MaximumAllocationSize << std::endl;
			std::cout << "VirtualMemoryThreshold                              " << loadConfigHeader->VirtualMemoryThreshold << std::endl;
			std::cout << "ProcessHeapFlags                                    " << loadConfigHeader->ProcessHeapFlags << std::endl;
			std::cout << "ProcessAffinityMask                                 " << loadConfigHeader->ProcessAffinityMask << std::endl;
			std::cout << "CSDVersion                                          " << loadConfigHeader->CSDVersion << std::endl;
			std::cout << "DependentLoadFlags                                  " << loadConfigHeader->DependentLoadFlags << std::endl;
			std::cout << "EditList                                            " << loadConfigHeader->EditList << std::endl;
			std::cout << "SecurityCookie                                      " << loadConfigHeader->SecurityCookie << std::endl;
			std::cout << "SEHandlerTable                                      " << loadConfigHeader->SEHandlerTable << std::endl;
			std::cout << "SEHandlerCount                                      " << loadConfigHeader->SEHandlerCount << std::endl;
			std::cout << "GuardCFCheckFunctionPointer                         " << loadConfigHeader->GuardCFCheckFunctionPointer << std::endl;
			std::cout << "GuardCFDispatchFunctionPointer                      " << loadConfigHeader->GuardCFDispatchFunctionPointer << std::endl;
			std::cout << "GuardCFFunctionTable                                " << loadConfigHeader->GuardCFFunctionTable << std::endl;
			std::cout << "GuardCFFunctionCount                                " << loadConfigHeader->GuardCFFunctionCount << std::endl;
			std::cout << "GuardFlags                                          " << loadConfigHeader->GuardFlags << std::endl;
			std::cout << "CodeIntegrity.Catalog                               " << loadConfigHeader->CodeIntegrity.Catalog << std::endl;
			std::cout << "CodeIntegrity.CatalogOffset                         " << loadConfigHeader->CodeIntegrity.CatalogOffset << std::endl;
			std::cout << "CodeIntegrity.Flags                                 " << loadConfigHeader->CodeIntegrity.Flags << std::endl;
			std::cout << "CodeIntegrity.Reserved                              " << loadConfigHeader->CodeIntegrity.Reserved << std::endl;
			std::cout << "GuardAddressTakenIatEntryTable                      " << loadConfigHeader->GuardAddressTakenIatEntryTable << std::endl;
			std::cout << "GuardAddressTakenIatEntryCount                      " << loadConfigHeader->GuardAddressTakenIatEntryCount << std::endl;
			std::cout << "GuardLongJumpTargetTable                            " << loadConfigHeader->GuardLongJumpTargetTable << std::endl;
			std::cout << "GuardLongJumpTargetCount                            " << loadConfigHeader->GuardLongJumpTargetCount << std::endl;
			std::cout << "DynamicValueRelocTable                              " << loadConfigHeader->DynamicValueRelocTable << std::endl;
			std::cout << "CHPEMetadataPointer                                 " << loadConfigHeader->CHPEMetadataPointer << std::endl;
			std::cout << "GuardRFFailureRoutine                               " << loadConfigHeader->GuardRFFailureRoutine << std::endl;
			std::cout << "GuardRFFailureRoutineFunctionPointer                " << loadConfigHeader->GuardRFFailureRoutineFunctionPointer << std::endl;
			std::cout << "DynamicValueRelocTableOffset                        " << loadConfigHeader->DynamicValueRelocTableOffset << std::endl;
			std::cout << "DynamicValueRelocTableSection                       " << loadConfigHeader->DynamicValueRelocTableSection << std::endl;
			std::cout << "Reserved2                                           " << loadConfigHeader->Reserved2 << std::endl;
			std::cout << "GuardRFVerifyStackPointerFunctionPoint              " << loadConfigHeader->GuardRFVerifyStackPointerFunctionPointer << std::endl;
			std::cout << "HotPatchTableOffset                                 " << loadConfigHeader->HotPatchTableOffset << std::endl;
			std::cout << "Reserved3                                           " << loadConfigHeader->Reserved3 << std::endl;
			std::cout << "EnclaveConfigurationPointer                         " << loadConfigHeader->EnclaveConfigurationPointer << std::endl;
			std::cout << "VolatileMetadataPointer                             " << loadConfigHeader->VolatileMetadataPointer << std::endl;
		}

		size_t relocationsDirectoryFileAddress = this->getFileAddress(this->dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		if (relocationsDirectoryFileAddress < this->fileSize)
		{
			std::cout << "\n========== RELOCATIONS ==========" << std::endl;
			size_t nBlocks = 0;
			size_t nEntries = 0;
			for (size_t chunk = 0, offset = 0; offset < this->dataDirectories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size; chunk++)
			{
				nBlocks++;
				IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)(this->file + relocationsDirectoryFileAddress + offset);
				WORD* entries = (WORD*)(block + 1);
				for (size_t i = 0; i < block->SizeOfBlock / sizeof(WORD); i++)
				{
					nEntries++;
					WORD entryType = entries[i] >> 12;
					size_t RVA = block->VirtualAddress + entries[i] & 0x0FFF;
				}
				offset += block->SizeOfBlock;
			}
			std::cout << "Number of blocks:  " << nBlocks  << std::endl;
			std::cout << "Number of entries: " << nEntries << std::endl;
		}
	}
}