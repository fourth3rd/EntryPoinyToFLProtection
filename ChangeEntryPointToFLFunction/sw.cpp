#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<string>
#include<Windows.h>
#include<vector>


std::vector<std::pair<int,std::pair<int, int > > > vctParseRelocation;
typedef struct Section
{
	char Name[8];
	int VirtualSize;
	int RVA;
	int SizeOfRawData;
	int PoitnerToRawData;
	int POinterToRelocations;
	int PointerToLineNumber;
	WORD NumberOfRelocations;
	WORD NumberOfLineNumbers;
	int Characteristics;
	int TempOffset;
}Section;

int FindMemoryBaseAddress(std::wstring src)
{
	int BaseAddress = 0;
	void* orgPtr = nullptr;
	void* curPtr = nullptr;
	wchar_t* strTemp = new wchar_t[src.size()];
	for(int i = 0; i < src.size(); i++)
	{
		*(strTemp + i) = src[i];
		*(strTemp + i + 1) = '\x00';
	}

	__asm
	{
		mov eax, fs: [0x18]        // TIB
		mov eax, [eax + 0x30]    // TIB->PEB
		mov eax, [eax + 0x0C]     // PEB->Ldr
		lea ebx, [eax + 0x0C]    // Ldr->InLoadOrderLinks
		mov orgPtr, ebx
		loadOrderLoop :
		mov edx, [ebx]            // InLoadOrderLinks->Flink
			mov curPtr, edx
			mov edi, [edx + 0x30]   // LDR_DATA_TABLE_ENTRY.BaseDllName.Buffer
			mov ecx, [edx + 0x18]
			test edi, edi
			je loadOrderFailed
			push strTemp
			push edi
			call strcmp
			add esp, 8
			test eax, eax
			cmp eax, eax
			je DllFind
			loadOrderFailed :
		mov ebx, curPtr
			mov ebx, [ebx]
			mov edx, orgPtr
			cmp ebx, edx
			jne loadOrderLoop
			DllFind :
		mov BaseAddress, ecx
	}

	return BaseAddress;
}
/*
void Decrypt(int Raw, int VA, int PointerToRawData, int Size)
{
	int* BaseAddress = FindMemoryBaseAddress(L"TestFunctionFixed.exe");

	int Start = Raw + VA - PointerToRawData;
	int From = Start + Size;

	for(int i = Start; i < From; i++)
	{
		BaseAddress[i] ^= 7;
	}
}
*/
int main()
{
	FILE* fp = fopen("TestFunction.exe", "rb");

	if(fp)
	{
		fseek(fp, 0, SEEK_END);
		size_t stSize = ftell(fp);

		char* buf = new char[stSize + 0x3000];
		char* Temp = new char[stSize];
		fseek(fp, 0, SEEK_SET);
		fread(buf, stSize, 1, fp);

		fclose(fp);
		fp = fopen(R"(TestFunctionFixed.exe)", "wb");
		fseek(fp, 0, SEEK_SET);

		PIMAGE_DOS_HEADER pDosH;
		PIMAGE_NT_HEADERS pNtH;
		PIMAGE_SECTION_HEADER pSecH;

		pDosH = (PIMAGE_DOS_HEADER)buf;
		pNtH = (PIMAGE_NT_HEADERS)((LPBYTE)buf + pDosH->e_lfanew);

		int i32BaseAddress = pNtH->OptionalHeader.ImageBase;
		int i32EntryPoint = pNtH->OptionalHeader.AddressOfEntryPoint;
		int i32PointerToRawData = 0;
		int i32RVA = 0;
		int i32SizeOfRawData = 0;
		int i32SizeOfCode = pNtH->OptionalHeader.SizeOfCode;

		int i32RelocRVA = 0;
		int i32RelocPointerToRawData = 0;
		int i32RelocSizeofRawData = 0;

		std::vector< Section> vctSection;


		for(int i = 0; i < pNtH->FileHeader.NumberOfSections; i++)
		{
			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buf + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			Section Temp;

			Temp.PoitnerToRawData = pSecH->PointerToRawData;
			Temp.RVA = pSecH->VirtualAddress;
			Temp.SizeOfRawData = pSecH->SizeOfRawData;
			strcpy(Temp.Name, (const char*)pSecH->Name);
			vctSection.push_back(Temp);

			if(!strcmp((const char*)pSecH->Name, ".text"))
			{
				i32PointerToRawData = pSecH->PointerToRawData;
				i32RVA = pSecH->VirtualAddress;
				i32SizeOfRawData = pSecH->SizeOfRawData;
			}
			else if(!strcmp((const char*)pSecH->Name, ".reloc"))
			{
				i32RelocRVA = pSecH->VirtualAddress;
				i32RelocPointerToRawData = pSecH->PointerToRawData;
				i32RelocSizeofRawData = pSecH->SizeOfRawData;
			}
		}

		for(int i = i32PointerToRawData; i < i32SizeOfCode; i++)
		{
			buf[i] = ~buf[i];
		}


		int* pModifiedTextCharacteristics = (int*)0xe0000060;
		int* ModifiedSizeOfImage = (int*)(pNtH->OptionalHeader.SizeOfImage + 0x3000);
		int* ModifiedEntryPoint = (int*)pNtH->OptionalHeader.SizeOfImage;
		memcpy((void*)&buf[0x130], (void*)&ModifiedSizeOfImage, 4);
		memcpy((void*)&buf[0x108], (void*)&ModifiedEntryPoint, 4);
		memcpy((void*)&buf[0x224], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x24c], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x274], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x29c], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x2c4], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x2ec], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x314], (void*)&pModifiedTextCharacteristics, 4);
		memcpy((void*)&buf[0x33c], (void*)&pModifiedTextCharacteristics, 4);
		buf[0xe6] = '\xa';
		Section FLSection;
		FLSection.Name[0] = '.';
		FLSection.Name[1] = 'F';
		FLSection.Name[2] = 'L';
		FLSection.Name[3] = '\x00';

		FLSection.VirtualSize = 0x3000;
		FLSection.RVA = 0x20000;
		FLSection.SizeOfRawData = 0x3000;
		FLSection.PoitnerToRawData = stSize;
		FLSection.POinterToRelocations = 0;
		FLSection.PointerToLineNumber = 0;
		FLSection.NumberOfRelocations = 0;
		FLSection.NumberOfLineNumbers = 0;
		FLSection.Characteristics = 0xe0000020;//

		memcpy((void*)&buf[0x340], (void*)&FLSection, sizeof(FLSection));

		std::vector<std::pair<int, int> > vctRelocationVector;

		int RvaOfBlock = 0;
		int SizeOfBlock = 0;

		int i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;

		memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
		memcpy((void*)&SizeOfBlock, (void*)&i32RelocPointerToRawDataToRelocSizeOfBlock, 4);


		vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
		while(1)
		{
			int TempRelocPointerToRawData = 0;
			memcpy((void*)&TempRelocPointerToRawData, (void*)&buf[SizeOfBlock], 4);
			i32RelocPointerToRawData += TempRelocPointerToRawData;

			i32RelocPointerToRawDataToRelocSizeOfBlock = i32RelocPointerToRawData + 4;
			if(buf[SizeOfBlock] == '\x0')
				break;
			memcpy((void*)&RvaOfBlock, (void*)&i32RelocPointerToRawData, 4);
			memcpy((void*)&SizeOfBlock, (void*)(&i32RelocPointerToRawDataToRelocSizeOfBlock), 4);
			vctRelocationVector.push_back({ RvaOfBlock,SizeOfBlock });
		}

		buf[stSize] = '\xe9';
		buf[stSize + 1] = '\x1b';
		buf[stSize + 2] = '\x0';
		buf[stSize + 3] = '\x0';
		buf[stSize + 4] = '\x0';
		for(int i = 5; i < 0x20; i++)
			buf[stSize + i] = '\x0';

		buf[stSize + 0x20] = '\x64';
		buf[stSize + 0x21] = '\xa1';
		buf[stSize + 0x22] = '\x18';
		buf[stSize + 0x23] = '\x0';

		buf[stSize + 0x24] = '\x0';
		buf[stSize + 0x25] = '\x0';
		buf[stSize + 0x26] = '\x8b';
		buf[stSize + 0x27] = '\x40';

		buf[stSize + 0x28] = '\x30';
		buf[stSize + 0x29] = '\x8b';
		buf[stSize + 0x2a] = '\x40';
		buf[stSize + 0x2b] = '\x0c';

		buf[stSize + 0x2c] = '\x8d';
		buf[stSize + 0x2d] = '\x58';
		buf[stSize + 0x2e] = '\x0c';
		buf[stSize + 0x2f] = '\x8b';

		buf[stSize + 0x30] = '\x13';
		buf[stSize + 0x31] = '\x8b';
		buf[stSize + 0x32] = '\x42';
		buf[stSize + 0x33] = '\x18';

		buf[stSize + 0x34] = '\x8b';
		buf[stSize + 0x35] = '\xd8';
		buf[stSize + 0x36] = '\x8b';
		buf[stSize + 0x37] = '\xd0';

		buf[stSize + 0x38] = '\x81';
		buf[stSize + 0x39] = '\xc2';
		buf[stSize + 0x3a] = '\x0c';
		buf[stSize + 0x3b] = '\x02';

		buf[stSize + 0x3c] = '\x00';
		buf[stSize + 0x3d] = '\x00';
		buf[stSize + 0x3e] = '\x8b';
		buf[stSize + 0x3f] = '\x1a';

		buf[stSize + 0x40] = '\x83';
		buf[stSize + 0x41] = '\xc2';
		buf[stSize + 0x42] = '\x04';

		buf[stSize + 0x43] = '\x8b';

		buf[stSize + 0x44] = '\x0a';
		buf[stSize + 0x45] = '\x83';
		buf[stSize + 0x46] = '\xc2';
		buf[stSize + 0x47] = '\x04';


		buf[stSize + 0x48] = '\x8b';
		buf[stSize + 0x49] = '\x32';
		buf[stSize + 0x4a] = '\x2b';
		buf[stSize + 0x4b] = '\xce';

		buf[stSize + 0x4c] = '\x03';
		buf[stSize + 0x4d] = '\xd8';
		buf[stSize + 0x4e] = '\x83';
		buf[stSize + 0x4f] = '\xc2';
		buf[stSize + 0x50] = '\x10';
		buf[stSize + 0x51] = '\xf6';
		buf[stSize + 0x52] = '\x13';
		buf[stSize + 0x53] = '\x83';
		buf[stSize + 0x54] = '\xc3';
		buf[stSize + 0x55] = '\x01';
		buf[stSize + 0x56] = '\x83';
		buf[stSize + 0x57] = '\xe9';
		buf[stSize + 0x58] = '\x01';
		buf[stSize + 0x59] = '\x83';
		buf[stSize + 0x5a] = '\xf9';
		buf[stSize + 0x5b] = '\x00';
		buf[stSize + 0x5c] = '\x75';
		buf[stSize + 0x5d] = '\xf3';
		/*
		buf[stSize + 0x5e] = '\xe9';

		buf[stSize + 0x5f] = '\xd1';
		buf[stSize + 0x60] = '\x12';
		buf[stSize + 0x61] = '\xff';
		buf[stSize + 0x62] = '\xff';
		*///Jump To Original Entry Point

		for(int i = 0; i < vctRelocationVector.size(); i++)
		{
			int RvaOfBlock = vctRelocationVector[i].first;
			int DeicdeToRvaOfBlock = 0;
			memcpy((void*)&DeicdeToRvaOfBlock, (void*)&buf[RvaOfBlock], 4);
			int Section = 0;
			for(int j = 0; j < vctSection.size() - 1; j++)
			{
				int FromRvaOfBlock = vctSection[j].RVA;
				int ToRvaOfBlock = vctSection[j + 1].RVA;

				if(FromRvaOfBlock <= DeicdeToRvaOfBlock && DeicdeToRvaOfBlock < ToRvaOfBlock)
				{
					Section = j;
					break;
				}
			}

			int Size = 0;
			memcpy((void*)&Size, (void*)&buf[vctRelocationVector[i].second], 4);

			int Start = vctRelocationVector[i].second + 4;

			for(int j = 2; j < Size; j += 2)
			{
				WORD Data = 0;
				int i32RvaOfBlock = 0;

				memcpy((void*)&i32RvaOfBlock, (void*)&buf[RvaOfBlock], 4);
				memcpy((void*)&Data, (void*)&buf[Start], 2);
				if(Data == 0)
					continue;
				Data &= 0x0fff;

				int RelocData = i32RvaOfBlock + Data;

				RelocData -= vctSection[Section].RVA;
				RelocData += vctSection[Section].PoitnerToRawData;
				RelocData += 2;

				vctParseRelocation.push_back({ Section,{RelocData,DeicdeToRvaOfBlock} });

				Start += 2;
			}
		}

		int BaseAddress = FindMemoryBaseAddress(L"TestFunctionFixed.exe");
		BaseAddress = BaseAddress & 0xffff0000;
		int cnt = 0x5e;
		for(int i = 0; i < vctParseRelocation.size(); i++)
		{
			int Section = vctParseRelocation[i].first;
			int RelocData = vctParseRelocation[i].second.first;
			int DeicdeToRvaOfBlock = vctParseRelocation[i].second.second;
			//int RVA = vctSection[Section].RVA;
			//int PointerToRawData = vctSection[Section].PoitnerToRawData;

			int InputData = RelocData + DeicdeToRvaOfBlock -vctSection[Section].PoitnerToRawData;
			//InputData += BaseAddress;

			char cInputData[4] = { 0, };

			memcpy((void*)&cInputData, (void*)&InputData, 4);

			char HighBaseAddress[2] = { 0, };

			WORD WDHighBaseAddress = (BaseAddress & 0xffff0000) >> 16;

			memcpy((void*)&HighBaseAddress, (void*)&(WDHighBaseAddress), 2);

			buf[stSize + cnt] = '\x8b';
			buf[stSize + cnt + 1] = '\xd8';
			buf[stSize + cnt + 2] = '\x81';
			buf[stSize + cnt + 3] = '\xc3';
			buf[stSize + cnt + 4] = cInputData[0];
			buf[stSize + cnt + 5] = cInputData[1];
			buf[stSize + cnt + 6] = cInputData[2];
			buf[stSize + cnt + 7] = cInputData[3];

			buf[stSize + cnt + 8] = '\x8b';
			buf[stSize + cnt + 9] = '\xf0';
			buf[stSize + cnt + 10] = '\xc1';
			buf[stSize + cnt + 11] = '\xee';
			buf[stSize + cnt + 12] = '\x10';

			buf[stSize + cnt + 13] = '\x3e';
			buf[stSize + cnt + 14] = '\x66';
			buf[stSize + cnt + 15] = '\x89';
			buf[stSize + cnt + 16] = '\x33';

			cnt += 17;

		}

		buf[stSize + cnt] = '\xe9';

		buf[stSize + cnt + 1] = '\x20';
		buf[stSize + cnt + 2] = '\xf7';
		buf[stSize + cnt + 3] = '\xfe';
		buf[stSize + cnt + 4] = '\xff';
		buf[stSize + cnt + 5] = '\x00';
		fwrite(buf, sizeof(char), stSize + 0x3000, fp);

		fclose(fp);
	}

}