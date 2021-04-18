#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include "Base.hpp"

struct instruction
{
	size_t RVA = 0;
	size_t fileAddress = 0;
	size_t size = 0;
	uint8_t* bin = nullptr;
	std::string cmds = "";
	std::string type = "";

	operator std::string()
	{
		std::string out = "";
		out += std::to_string(this->RVA);
		out += "+";
		out += std::to_string(this->size);
		out += "/";
		out += this->type;
		out += "/: ";
		out += this->cmds;
		return out;
	}
};

#define BINSTREAM(byte) (!!(byte & (1<<7))) << (!!(byte & (1<<6))) << (!!(byte & (1<<5))) << (!!(byte & (1<<4))) << (!!(byte & (1<<3))) << (!!(byte & (1<<2))) << (!!(byte & (1<<1))) << (!!(byte & (1<<0)))
#define RANDOM_IF(cond) if((rand()&1)&&(cond))
int main()
{
	srand(time(0));
	// parse PE file
	PE::Base pe("input.dll");
	pe.printInfo();

	std::cout << "disassembling..." << std::endl;
	// open disassembly file
	std::string disassembly;
	{
		std::ifstream ifile("disassembly.txt", std::ios::in);
		if (!ifile.is_open()) return 1;

		ifile.seekg(0, std::ios::end);
		size_t fileSize = ifile.tellg();
		ifile.seekg(0);

		char* fileData = (char*)malloc(fileSize);
		if (!fileData) return 2;
		ifile.read(fileData, fileSize);

		disassembly = std::string(fileData, fileSize);
	}
	
	size_t q = 0;
	size_t i = 0;
	std::istringstream iss(disassembly);
	std::vector<instruction> instructions = {};
	for (std::string line; std::getline(iss, line);)
	{
		if (line.at(0) == ';') continue;

		instruction ins;
		size_t plus_index = line.find_first_of('+');
		size_t slash1_index = line.find_first_of('/', plus_index + 1);
		size_t slash2_index = line.find_first_of('/', slash1_index + 1);

		ins.RVA = std::stoi(line.substr(i, plus_index));
		ins.size = std::stoi(line.substr(plus_index + 1, slash1_index - plus_index));
		ins.type = std::string(line.substr(slash1_index + 1, slash2_index - slash1_index - 1).c_str());
		ins.cmds = std::string(line.substr(slash2_index + 3).c_str());
		ins.fileAddress = pe.getFileAddress(ins.RVA);
		ins.bin = (uint8_t*)(pe.file + ins.fileAddress);

		if (ins.fileAddress >= pe.fileSize)
		{
			std::cout << "Couldn't locate in file - " << line << std::endl;
			continue;
		}
		q += ins.size;
		instructions.push_back(ins);
	}
	std::cout << "Max mutable space: " << q << std::endl;
	std::cout << "instruction count: " << instructions.size() << std::endl;

	char* bincopy = (char*)malloc(pe.fileSize);
	// make instructions relative to bincopy
	for (size_t i = 0; i < instructions.size(); i++)
	{
		instruction& ins = instructions.at(i);
		ins.bin = (uint8_t*)(bincopy + ((char*)ins.bin - pe.file));
	}

	for (int i = 0; i < 100; i++)
	{
		std::cout << "MUTATING " << i << std::endl;
		memcpy(bincopy, pe.file, pe.fileSize);

		size_t nBytesChanged = 0;
		for (size_t i = 0; i < instructions.size(); i++)
		{
			instruction& ins = instructions.at(i);
			bool* changed = new bool[ins.size];
			ZeroMemory(changed, ins.size);

			/*
			for (size_t o = 0; o < ins.size; o++)
			{
				std::cout << BINSTREAM(ins.bin[o]) << " ";
			}
			std::cout << ins.cmds << std::endl;
			*/


			// MOV instruction for 32bit registers is as follows:
			// 100010r1 11aaabbb
			// where aaa and bbb are 32bit registers
			// where `r=1` sets that `aaa` and `bbb` should *not* be swapped
			// mutate `mov a, b` to `push b // pop a`
			RANDOM_IF(ins.size == 2 && (ins.bin[0] & ~0b00000010) == 0b10001001 && (ins.bin[1] & 0b11000000) == 0b11000000)
			{
				// mov moveTo, moveFrom ; 32bit registers
				bool switchOperands = !(ins.bin[0] & 0b00000010);
				uint8_t moveFrom = ins.bin[1] & 0b00000111;
				uint8_t moveTo = (ins.bin[1] & 0b00111000) >> 3;
				if (switchOperands)
				{
					uint8_t t = moveFrom;
					moveFrom = moveTo;
					moveTo = t;
				}

				// push moveFrom // pop moveTo
				ins.bin[0] = 0b01010000 | moveFrom;
				ins.bin[1] = 0b01011000 | moveTo;

				//std::cout << "swapped mov for push/pop @ " << ins.fileAddress << std::endl;
				changed[0] = true;
				changed[1] = true;
			}

			// many 2 byte instructions have a flag to flip the order of 2 operators
			// 00ttt001 11aaabbb ; ttt aaa, bbb //ttt=[ADD,ADC,AND,OR,SUB,SBB,XOR,CMP]
			// 00ttt011 11aaabbb ; ttt bbb, aaa
			// 10001001 11aaabbb ; mov bbb, aaa
			// 10001011 11aaabbb ; mov aaa, bbb
			// mutate `add, adc, and, or, sub, sbb, xor, cmp, mov` bi directional operonds
			RANDOM_IF(ins.size == 2 && (ins.bin[1] & 0b11000000) == 0b11000000 && ((ins.bin[0] & 0b11000101) == 0b00000001 || (ins.bin[0] & ~0b00000010) == 0b10001001))
			{
				// invert flag
				ins.bin[0] ^= 0b00000010;
				// swap registers
				uint8_t loreg = ins.bin[1] & 0b00000111;
				uint8_t hireg = (ins.bin[1] & 0b00111000) >> 3;
				ins.bin[1] = 0b11000000 | loreg << 3 | hireg;

				//std::cout << "swapped order of arguments @ " << ins.fileAddress << std::endl;
				changed[0] = true;
				changed[1] = true;
			}

			//001100xx 11aaabbb     ; xor a, b
			//001010xx 11aaabbb     ; sub a, b
			// swap `xor x,x` to `sub x,x`
			RANDOM_IF(
				ins.size == 2 &&
				(((ins.bin[1] >> 3) & 0b00000111) == (ins.bin[1] & 0b00000111)) && // registers are equal and
				(((ins.bin[0] & 0b11111100) == 0b00110000) || ((ins.bin[0] & 0b11111100) == 0b00101000))) // opcode is xor or is sub
			{
				ins.bin[0] ^= 0b00011000;

				//std::cout << "swapped xor / sub @ " << ins.fileAddress << std::endl;
				changed[0] = true;
			}

			// add/sub 4-byte constant to/from register
			RANDOM_IF(ins.size == 6 && ins.bin[0] == 0b10000001 && ((ins.bin[1] & 0b11111000) == 0b11000000 || (ins.bin[1] & 0b11111000) == 0b11101000))
			{
				int32_t value = *(int32_t*)(ins.bin + 2);
				if (127 <= value && value <= 127 * 2)
				{
					// convert to multiple 1-byte add/subs
					ins.bin[0] |= 0b00000010;
					ins.bin[2] = 127;

					ins.bin[3] = ins.bin[0];
					ins.bin[4] = ins.bin[1];
					ins.bin[5] = (char)(value - 127);

					//std::cout << "swapped add/sub 4 byte to multiple add/sub single byte @ " << ins.fileAddress << std::endl;
					changed[0] = true;
					changed[2] = changed[2] || (value != 127);
					changed[3] = true;
					changed[4] = true;
					changed[5] = true;
				}
			}

			// or reg, -1
			// ; same as
			// xor reg, reg
			// dec reg
			RANDOM_IF(ins.size == 3 && ins.bin[0] == 0b10000011 && (ins.bin[1] & 0b11111000) == 0b11001000 && (int8_t)ins.bin[2] == -1)
			{
				bool flip = rand() % 2;
				uint8_t reg = ins.bin[1] & 0b00000111;
				// xor reg, reg
				ins.bin[0] = flip ? 0b00101011 : 0b00101001;
				ins.bin[1] = 0b11000000 | (reg << 3) | reg;
				// dec reg
				ins.bin[2] = 0b01001000 | reg;

				//std::cout << "swapped 'or reg, -1' for 'xor reg, reg // dec reg' @ " << ins.fileAddress << std::endl;
				changed[0] = true;
				changed[1] = true;
				changed[2] = true;
			}

			for (size_t i = 0; i < ins.size; i++)
				if (changed[i])
					nBytesChanged++;
			delete[] changed;
		}
		std::cout << "Changed a total of " << nBytesChanged << " bytes" << std::endl;
		std::ofstream out("out/" + std::to_string(i) + ".dll", std::ios::binary);
		out.write(bincopy, pe.fileSize);
		out.close();
	}

	return 0;
}