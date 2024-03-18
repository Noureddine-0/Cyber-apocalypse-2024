#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>


char flag[40];
uint32_t registers[15];

uint32_t rotr(uint32_t value, uint32_t shift) {
    return (value >> shift) | (value << (sizeof(value) * 8 - shift));
}

uint32_t rotl(uint32_t value, uint32_t shift) {
    return (value << shift) | (value >> (sizeof(value) * 8 - shift));
}

typedef struct Instruction{
	uint32_t opcode;
	uint32_t op0;
	uint32_t op1;
}Instruction;

	bool check() {
		if (registers[0] == 0x3ee88722 && registers[1] == 0xecbdbe2 && registers[2] == 0x60b843c4 && registers[3] == 0x5da67c7 && registers[4] == 0x171ef1e9 && registers[5] == 0x52d5b3f7 && registers[6] == 0x3ae718c0 && registers[7] == 0x8b4aacc2 && registers[8] == 0xe5cf78dd && registers[9] == 0x4a848edf && registers[10] == 0x8f && registers[11] == 0x4180000 && registers[12] == 0x0 && registers[13] == 0xd && registers[14] == 0x0){
			return true;
		}
		return false;
	}

	void execute_instruction(Instruction Insn){
        if  (Insn.opcode == 0) {
            registers[Insn.op0] = flag[Insn.op1];
        } else if  (Insn.opcode == 1) {
            registers[Insn.op0] = Insn.op1;
        } else if  (Insn.opcode == 2) {
            registers[Insn.op0] ^= Insn.op1;
        } else if  (Insn.opcode == 3) {
            registers[Insn.op0] ^= registers[Insn.op1];
        } else if  (Insn.opcode == 4) {
            registers[Insn.op0] |= Insn.op1;
        } else if  (Insn.opcode == 5) {
            registers[Insn.op0] |= registers[Insn.op1];
        } else if  (Insn.opcode == 6) {
            registers[Insn.op0] &= Insn.op1;
        } else if  (Insn.opcode == 7) {
            registers[Insn.op0] &= registers[Insn.op1];
        } else if  (Insn.opcode == 8) {
            registers[Insn.op0] += Insn.op1;
        } else if  (Insn.opcode == 9) {
            registers[Insn.op0] += registers[Insn.op1];
        } else if  (Insn.opcode == 10) {
            registers[Insn.op0] -= Insn.op1;
        } else if  (Insn.opcode == 11) {
            registers[Insn.op0] -= registers[Insn.op1];
        } else if  (Insn.opcode == 12) {
            registers[Insn.op0] *= Insn.op1;
        } else if  (Insn.opcode == 13) {
            registers[Insn.op0] *= registers[Insn.op1];
        } else if  (Insn.opcode == 14) {

        } else if  (Insn.opcode == 15) {

        } else if  (Insn.opcode == 16) {
            registers[Insn.op0] = rotr(registers[Insn.op0], Insn.op1);
        } else if  (Insn.opcode == 17) {
            registers[Insn.op0] = rotr(registers[Insn.op0], registers[Insn.op1]);
        } else if  (Insn.opcode == 18) {
            registers[Insn.op0] = rotl(registers[Insn.op0], Insn.op1);
        } else if  (Insn.opcode == 19) {
            registers[Insn.op0] = rotl(registers[Insn.op0], registers[Insn.op1]);
        } else if  (Insn.opcode == 20) {
            registers[Insn.op0] = registers[Insn.op1];
        } else if  (Insn.opcode == 21) {
            registers[Insn.op0] = 0;
        } else if  (Insn.opcode == 22) {
            registers[Insn.op0] >>= Insn.op1;
        } else if  (Insn.opcode == 23) {
            registers[Insn.op0] >>= registers[Insn.op1];
        } else if  (Insn.opcode == 24) {
            registers[Insn.op0] <<= Insn.op1;
        } else if  (Insn.opcode == 25) {
            registers[Insn.op0] <<= registers[Insn.op1];
	}
}

int main(int argc, char const *argv[])
{
	read(0,flag ,40);
	execute_instruction((Instruction){12, 13, 10});
	execute_instruction((Instruction){21, 0, 0});
	execute_instruction((Instruction){0, 13, 13}); 
	execute_instruction((Instruction){0, 14, 0}); 
	execute_instruction((Instruction){15, 11, 12}); 
	execute_instruction((Instruction){24, 14, 0});
    execute_instruction((Instruction){5, 0, 14}); 
    execute_instruction((Instruction){0, 14, 1}); 
    execute_instruction((Instruction){7, 11, 11}); 
    execute_instruction((Instruction){24, 14, 8}); 
    execute_instruction((Instruction){5, 0, 14}); 
    execute_instruction((Instruction){0, 14, 2}); 
    execute_instruction((Instruction){2, 10, 11}); 
    execute_instruction((Instruction){24, 14, 16}); 
    execute_instruction((Instruction){18, 12, 11}); 
    execute_instruction((Instruction){5, 0, 14}); 
    execute_instruction((Instruction){0, 14, 3}); 
    execute_instruction((Instruction){0, 11, 11}); 
    execute_instruction((Instruction){24, 14, 24}); 
    execute_instruction((Instruction){13, 10, 10}); 
    execute_instruction((Instruction){5, 0, 14}); 
    execute_instruction((Instruction){2, 11, 13}); 
    execute_instruction((Instruction){21, 1, 0}); 
    execute_instruction((Instruction){0, 14, 4}); 
    execute_instruction((Instruction){24, 14, 0}); 
    execute_instruction((Instruction){5, 1, 14}); 
    execute_instruction((Instruction){6, 11, 12}); 
    execute_instruction((Instruction){0, 14, 5}); 
    execute_instruction((Instruction){8, 10, 10}); 
    execute_instruction((Instruction){24, 14, 8}); 
    execute_instruction((Instruction){11, 12, 11}); 
    execute_instruction((Instruction){5, 1, 14}); 
    execute_instruction((Instruction){0, 14, 6}); execute_instruction((Instruction){0, 12, 10}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){9, 10, 13}); execute_instruction((Instruction){5, 1, 14}); execute_instruction((Instruction){0, 14, 7}); execute_instruction((Instruction){13, 12, 12}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){15, 10, 12}); execute_instruction((Instruction){5, 1, 14}); execute_instruction((Instruction){21, 2, 0}); execute_instruction((Instruction){20, 13, 13}); execute_instruction((Instruction){0, 14, 8}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){19, 10, 11}); execute_instruction((Instruction){5, 2, 14}); execute_instruction((Instruction){6, 12, 10}); execute_instruction((Instruction){0, 14, 9}); execute_instruction((Instruction){8, 11, 11}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){5, 2, 14}); execute_instruction((Instruction){0, 14, 10}); execute_instruction((Instruction){4, 11, 12}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){5, 2, 14}); execute_instruction((Instruction){0, 14, 11}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){4, 13, 12}); execute_instruction((Instruction){5, 2, 14}); execute_instruction((Instruction){21, 3, 0}); execute_instruction((Instruction){14, 10, 12}); execute_instruction((Instruction){0, 14, 12}); execute_instruction((Instruction){13, 10, 11}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){16, 10, 10}); execute_instruction((Instruction){5, 3, 14}); execute_instruction((Instruction){5, 11, 12}); execute_instruction((Instruction){0, 14, 13}); execute_instruction((Instruction){12, 10, 13}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){2, 10, 13}); execute_instruction((Instruction){5, 3, 14}); execute_instruction((Instruction){20, 11, 11}); execute_instruction((Instruction){0, 14, 14}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){18, 13, 11}); execute_instruction((Instruction){5, 3, 14}); execute_instruction((Instruction){6, 11, 13}); execute_instruction((Instruction){0, 14, 15}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){4, 11, 10}); execute_instruction((Instruction){5, 3, 14}); execute_instruction((Instruction){21, 4, 0}); execute_instruction((Instruction){15, 13, 11}); execute_instruction((Instruction){0, 14, 16}); execute_instruction((Instruction){6, 10, 10}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){14, 10, 12}); execute_instruction((Instruction){5, 4, 14}); execute_instruction((Instruction){0, 14, 17}); execute_instruction((Instruction){12, 13, 13}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){19, 11, 10}); execute_instruction((Instruction){5, 4, 14}); execute_instruction((Instruction){0, 14, 18}); execute_instruction((Instruction){17, 13, 12}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){5, 4, 14}); execute_instruction((Instruction){0, 14, 19}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){21, 12, 10}); execute_instruction((Instruction){5, 4, 14}); execute_instruction((Instruction){13, 13, 10}); execute_instruction((Instruction){21, 5, 0}); execute_instruction((Instruction){0, 14, 20}); execute_instruction((Instruction){19, 10, 13}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){5, 5, 14}); execute_instruction((Instruction){0, 14, 21}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){8, 13, 13}); execute_instruction((Instruction){5, 5, 14}); execute_instruction((Instruction){0, 14, 22}); execute_instruction((Instruction){16, 13, 11}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){10, 10, 13}); execute_instruction((Instruction){5, 5, 14}); execute_instruction((Instruction){7, 10, 12}); execute_instruction((Instruction){0, 14, 23}); execute_instruction((Instruction){19, 13, 10}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){5, 5, 14}); execute_instruction((Instruction){17, 12, 10}); execute_instruction((Instruction){21, 6, 0}); execute_instruction((Instruction){16, 11, 10}); execute_instruction((Instruction){0, 14, 24}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){10, 11, 10}); execute_instruction((Instruction){5, 6, 14}); execute_instruction((Instruction){0, 14, 25}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){7, 10, 12}); execute_instruction((Instruction){5, 6, 14}); execute_instruction((Instruction){0, 14, 26}); execute_instruction((Instruction){16, 12, 11}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){3, 11, 10}); execute_instruction((Instruction){5, 6, 14}); execute_instruction((Instruction){15, 11, 13}); execute_instruction((Instruction){0, 14, 27}); execute_instruction((Instruction){4, 12, 13}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){5, 6, 14}); execute_instruction((Instruction){14, 11, 13}); execute_instruction((Instruction){21, 7, 0}); execute_instruction((Instruction){0, 14, 28}); execute_instruction((Instruction){21, 13, 11}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){7, 12, 11}); execute_instruction((Instruction){5, 7, 14}); execute_instruction((Instruction){17, 11, 10}); execute_instruction((Instruction){0, 14, 29}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){5, 7, 14}); execute_instruction((Instruction){0, 14, 30}); execute_instruction((Instruction){12, 10, 10}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){5, 7, 14}); execute_instruction((Instruction){0, 14, 31}); execute_instruction((Instruction){20, 10, 10}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){5, 7, 14}); execute_instruction((Instruction){21, 8, 0}); execute_instruction((Instruction){18, 10, 12}); execute_instruction((Instruction){0, 14, 32}); execute_instruction((Instruction){9, 11, 11}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){21, 12, 11}); execute_instruction((Instruction){5, 8, 14}); execute_instruction((Instruction){0, 14, 33}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){19, 10, 13}); execute_instruction((Instruction){5, 8, 14}); execute_instruction((Instruction){8, 12, 13}); execute_instruction((Instruction){0, 14, 34}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){5, 8, 14}); execute_instruction((Instruction){8, 10, 10}); execute_instruction((Instruction){0, 14, 35}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){21, 13, 10}); execute_instruction((Instruction){5, 8, 14}); execute_instruction((Instruction){0, 12, 10}); execute_instruction((Instruction){21, 9, 0}); execute_instruction((Instruction){0, 14, 36}); execute_instruction((Instruction){24, 14, 0}); execute_instruction((Instruction){5, 9, 14}); execute_instruction((Instruction){17, 11, 11}); execute_instruction((Instruction){0, 14, 37}); execute_instruction((Instruction){14, 10, 13}); execute_instruction((Instruction){24, 14, 8}); execute_instruction((Instruction){5, 9, 14}); execute_instruction((Instruction){4, 10, 11}); execute_instruction((Instruction){0, 14, 38}); execute_instruction((Instruction){13, 11, 13}); execute_instruction((Instruction){24, 14, 16}); execute_instruction((Instruction){5, 9, 14}); execute_instruction((Instruction){0, 14, 39}); execute_instruction((Instruction){10, 11, 10}); execute_instruction((Instruction){24, 14, 24}); execute_instruction((Instruction){20, 13, 13}); execute_instruction((Instruction){5, 9, 14}); execute_instruction((Instruction){6, 12, 11}); execute_instruction((Instruction){21, 14, 0}); execute_instruction((Instruction){8, 0, 2769503260}); execute_instruction((Instruction){10, 0, 997841014}); execute_instruction((Instruction){19, 12, 11}); execute_instruction((Instruction){2, 0, 4065997671}); execute_instruction((Instruction){5, 13, 11}); execute_instruction((Instruction){8, 0, 690011675}); execute_instruction((Instruction){15, 11, 11}); execute_instruction((Instruction){8, 0, 540576667}); execute_instruction((Instruction){2, 0, 1618285201}); execute_instruction((Instruction){8, 0, 1123989331}); execute_instruction((Instruction){8, 0, 1914950564}); execute_instruction((Instruction){8, 0, 4213669998}); execute_instruction((Instruction){21, 13, 11}); execute_instruction((Instruction){8, 0, 1529621790}); execute_instruction((Instruction){10, 0, 865446746}); execute_instruction((Instruction){2, 10, 11}); execute_instruction((Instruction){8, 0, 449019059}); execute_instruction((Instruction){16, 13, 11}); execute_instruction((Instruction){8, 0, 906976959}); execute_instruction((Instruction){6, 10, 10}); execute_instruction((Instruction){8, 0, 892028723}); execute_instruction((Instruction){10, 0, 1040131328}); execute_instruction((Instruction){2, 0, 3854135066}); execute_instruction((Instruction){2, 0, 4133925041}); execute_instruction((Instruction){2, 0, 1738396966}); execute_instruction((Instruction){2, 12, 12}); execute_instruction((Instruction){8, 0, 550277338}); execute_instruction((Instruction){10, 0, 1043160697}); execute_instruction((Instruction){2, 1, 1176768057}); execute_instruction((Instruction){10, 1, 2368952475}); execute_instruction((Instruction){8, 12, 11}); execute_instruction((Instruction){2, 1, 2826144967}); execute_instruction((Instruction){8, 1, 1275301297}); execute_instruction((Instruction){10, 1, 2955899422}); execute_instruction((Instruction){2, 1, 2241699318}); execute_instruction((Instruction){12, 11, 10}); execute_instruction((Instruction){8, 1, 537794314}); execute_instruction((Instruction){11, 13, 10}); execute_instruction((Instruction){8, 1, 473021534}); execute_instruction((Instruction){17, 12, 13}); execute_instruction((Instruction){8, 1, 2381227371}); execute_instruction((Instruction){10, 1, 3973380876}); execute_instruction((Instruction){10, 1, 1728990628}); execute_instruction((Instruction){6, 11, 13}); execute_instruction((Instruction){8, 1, 2974252696}); execute_instruction((Instruction){0, 11, 11}); execute_instruction((Instruction){8, 1, 1912236055}); execute_instruction((Instruction){2, 1, 3620744853}); execute_instruction((Instruction){3, 10, 13}); execute_instruction((Instruction){2, 1, 2628426447}); execute_instruction((Instruction){11, 13, 12}); execute_instruction((Instruction){10, 1, 486914414}); execute_instruction((Instruction){16, 11, 12}); execute_instruction((Instruction){10, 1, 1187047173}); execute_instruction((Instruction){14, 12, 11}); execute_instruction((Instruction){2, 2, 3103274804}); execute_instruction((Instruction){13, 10, 10}); execute_instruction((Instruction){8, 2, 3320200805}); execute_instruction((Instruction){8, 2, 3846589389}); execute_instruction((Instruction){1, 13, 13}); execute_instruction((Instruction){2, 2, 2724573159}); execute_instruction((Instruction){10, 2, 1483327425}); execute_instruction((Instruction){2, 2, 1957985324}); execute_instruction((Instruction){14, 13, 12}); execute_instruction((Instruction){10, 2, 1467602691}); execute_instruction((Instruction){8, 2, 3142557962}); execute_instruction((Instruction){2, 13, 12}); execute_instruction((Instruction){2, 2, 2525769395}); execute_instruction((Instruction){8, 2, 3681119483}); execute_instruction((Instruction){8, 12, 11}); execute_instruction((Instruction){10, 2, 1041439413}); execute_instruction((Instruction){10, 2, 1042206298}); execute_instruction((Instruction){2, 2, 527001246}); execute_instruction((Instruction){20, 10, 13}); execute_instruction((Instruction){10, 2, 855860613}); execute_instruction((Instruction){8, 10, 10}); execute_instruction((Instruction){8, 2, 1865979270}); execute_instruction((Instruction){1, 13, 10}); execute_instruction((Instruction){8, 2, 2752636085}); execute_instruction((Instruction){2, 2, 1389650363}); execute_instruction((Instruction){10, 2, 2721642985}); execute_instruction((Instruction){18, 10, 11}); execute_instruction((Instruction){8, 2, 3276518041}); execute_instruction((Instruction){15, 10, 10}); execute_instruction((Instruction){2, 2, 1965130376}); execute_instruction((Instruction){2, 3, 3557111558}); execute_instruction((Instruction){2, 3, 3031574352}); execute_instruction((Instruction){16, 12, 10}); execute_instruction((Instruction){10, 3, 4226755821}); execute_instruction((Instruction){8, 3, 2624879637}); execute_instruction((Instruction){8, 3, 1381275708}); execute_instruction((Instruction){2, 3, 3310620882}); execute_instruction((Instruction){2, 3, 2475591380}); execute_instruction((Instruction){8, 3, 405408383}); execute_instruction((Instruction){2, 3, 2291319543}); execute_instruction((Instruction){0, 12, 12}); execute_instruction((Instruction){8, 3, 4144538489}); execute_instruction((Instruction){2, 3, 3878256896}); execute_instruction((Instruction){6, 11, 10}); execute_instruction((Instruction){10, 3, 2243529248}); execute_instruction((Instruction){10, 3, 561931268}); execute_instruction((Instruction){11, 11, 12}); execute_instruction((Instruction){10, 3, 3076955709}); execute_instruction((Instruction){18, 12, 13}); execute_instruction((Instruction){8, 3, 2019584073}); execute_instruction((Instruction){10, 13, 12}); execute_instruction((Instruction){8, 3, 1712479912}); execute_instruction((Instruction){18, 11, 11}); execute_instruction((Instruction){2, 3, 2804447380}); execute_instruction((Instruction){17, 10, 10}); execute_instruction((Instruction){10, 3, 2957126100}); execute_instruction((Instruction){18, 13, 13}); execute_instruction((Instruction){8, 3, 1368187437}); execute_instruction((Instruction){17, 10, 12}); execute_instruction((Instruction){8, 3, 3586129298}); execute_instruction((Instruction){10, 4, 1229526732}); execute_instruction((Instruction){19, 11, 11}); execute_instruction((Instruction){10, 4, 2759768797}); execute_instruction((Instruction){1, 10, 13}); execute_instruction((Instruction){2, 4, 2112449396}); execute_instruction((Instruction){10, 4, 1212917601}); execute_instruction((Instruction){2, 4, 1524771736}); execute_instruction((Instruction){8, 4, 3146530277}); execute_instruction((Instruction){2, 4, 2997906889}); execute_instruction((Instruction){16, 12, 10}); execute_instruction((Instruction){8, 4, 4135691751}); execute_instruction((Instruction){8, 4, 1960868242}); execute_instruction((Instruction){6, 12, 12}); execute_instruction((Instruction){10, 4, 2775657353}); execute_instruction((Instruction){16, 10, 13}); execute_instruction((Instruction){8, 4, 1451259226}); execute_instruction((Instruction){8, 4, 607382171}); execute_instruction((Instruction){13, 13, 13}); execute_instruction((Instruction){10, 4, 357643050}); execute_instruction((Instruction){2, 4, 2020402776}); execute_instruction((Instruction){8, 5, 2408165152}); execute_instruction((Instruction){13, 12, 10}); execute_instruction((Instruction){2, 5, 806913563}); execute_instruction((Instruction){10, 5, 772591592}); execute_instruction((Instruction){20, 13, 11}); execute_instruction((Instruction){2, 5, 2211018781}); execute_instruction((Instruction){10, 5, 2523354879}); execute_instruction((Instruction){8, 5, 2549720391}); execute_instruction((Instruction){2, 5, 3908178996}); execute_instruction((Instruction){2, 5, 1299171929}); execute_instruction((Instruction){8, 5, 512513885}); execute_instruction((Instruction){10, 5, 2617924552}); execute_instruction((Instruction){1, 12, 13}); execute_instruction((Instruction){8, 5, 390960442}); execute_instruction((Instruction){12, 11, 13}); execute_instruction((Instruction){8, 5, 1248271133}); execute_instruction((Instruction){8, 5, 2114382155}); execute_instruction((Instruction){1, 10, 13}); execute_instruction((Instruction){10, 5, 2078863299}); execute_instruction((Instruction){20, 12, 12}); execute_instruction((Instruction){8, 5, 2857504053}); execute_instruction((Instruction){10, 5, 4271947727}); execute_instruction((Instruction){2, 6, 2238126367}); execute_instruction((Instruction){2, 6, 1544827193}); execute_instruction((Instruction){8, 6, 4094800187}); execute_instruction((Instruction){2, 6, 3461906189}); execute_instruction((Instruction){10, 6, 1812592759}); execute_instruction((Instruction){2, 6, 1506702473}); execute_instruction((Instruction){8, 6, 536175198}); execute_instruction((Instruction){2, 6, 1303821297}); execute_instruction((Instruction){8, 6, 715409343}); execute_instruction((Instruction){2, 6, 4094566992}); execute_instruction((Instruction){14, 10, 11}); execute_instruction((Instruction){2, 6, 1890141105}); execute_instruction((Instruction){0, 13, 13}); execute_instruction((Instruction){2, 6, 3143319360}); execute_instruction((Instruction){10, 7, 696930856}); execute_instruction((Instruction){2, 7, 926450200}); execute_instruction((Instruction){8, 7, 352056373}); execute_instruction((Instruction){20, 13, 11}); execute_instruction((Instruction){10, 7, 3857703071}); execute_instruction((Instruction){8, 7, 3212660135}); execute_instruction((Instruction){5, 12, 10}); execute_instruction((Instruction){10, 7, 3854876250}); execute_instruction((Instruction){21, 12, 11}); execute_instruction((Instruction){8, 7, 3648688720}); execute_instruction((Instruction){2, 7, 2732629817}); execute_instruction((Instruction){4, 10, 12}); execute_instruction((Instruction){10, 7, 2285138643}); execute_instruction((Instruction){18, 10, 13}); execute_instruction((Instruction){2, 7, 2255852466}); execute_instruction((Instruction){2, 7, 2537336944}); execute_instruction((Instruction){3, 10, 13}); execute_instruction((Instruction){2, 7, 4257606405}); execute_instruction((Instruction){10, 8, 3703184638}); execute_instruction((Instruction){7, 11, 10}); execute_instruction((Instruction){10, 8, 2165056562}); execute_instruction((Instruction){8, 8, 2217220568}); execute_instruction((Instruction){19, 10, 12}); execute_instruction((Instruction){8, 8, 2088084496}); execute_instruction((Instruction){15, 13, 10}); execute_instruction((Instruction){8, 8, 443074220}); execute_instruction((Instruction){16, 13, 12}); execute_instruction((Instruction){10, 8, 1298336973}); execute_instruction((Instruction){2, 13, 11}); execute_instruction((Instruction){8, 8, 822378456}); execute_instruction((Instruction){19, 11, 12}); execute_instruction((Instruction){8, 8, 2154711985}); execute_instruction((Instruction){0, 11, 12}); execute_instruction((Instruction){10, 8, 430757325}); execute_instruction((Instruction){2, 12, 10}); execute_instruction((Instruction){2, 8, 2521672196}); execute_instruction((Instruction){10, 9, 532704100}); execute_instruction((Instruction){10, 9, 2519542932}); execute_instruction((Instruction){2, 9, 2451309277}); execute_instruction((Instruction){2, 9, 3957445476}); execute_instruction((Instruction){5, 10, 10}); execute_instruction((Instruction){8, 9, 2583554449}); execute_instruction((Instruction){10, 9, 1149665327}); execute_instruction((Instruction){12, 13, 12}); execute_instruction((Instruction){8, 9, 3053959226}); execute_instruction((Instruction){0, 10, 10}); execute_instruction((Instruction){8, 9, 3693780276}); execute_instruction((Instruction){15, 11, 10}); execute_instruction((Instruction){2, 9, 609918789}); execute_instruction((Instruction){2, 9, 2778221635}); execute_instruction((Instruction){16, 13, 10}); execute_instruction((Instruction){8, 9, 3133754553}); execute_instruction((Instruction){8, 11, 13}); execute_instruction((Instruction){8, 9, 3961507338}); execute_instruction((Instruction){2, 9, 1829237263}); execute_instruction((Instruction){16, 11, 13}); execute_instruction((Instruction){2, 9, 2472519933}); execute_instruction((Instruction){6, 12, 12}); execute_instruction((Instruction){8, 9, 4061630846}); execute_instruction((Instruction){10, 9, 1181684786}); execute_instruction((Instruction){13, 10, 11}); execute_instruction((Instruction){10, 9, 390349075}); execute_instruction((Instruction){8, 9, 2883917626}); execute_instruction((Instruction){10, 9, 3733394420}); execute_instruction((Instruction){10, 12, 12}); execute_instruction((Instruction){2, 9, 3895283827}); execute_instruction((Instruction){20, 10, 11}); execute_instruction((Instruction){2, 9, 2257053750}); execute_instruction((Instruction){10, 9, 2770821931}); execute_instruction((Instruction){18, 10, 13}); execute_instruction((Instruction){2, 9, 477834410}); execute_instruction((Instruction){19, 13, 12}); execute_instruction((Instruction){3, 0, 1}); execute_instruction((Instruction){12, 12, 12}); execute_instruction((Instruction){3, 1, 2}); execute_instruction((Instruction){11, 13, 11}); execute_instruction((Instruction){3, 2, 3}); execute_instruction((Instruction){3, 3, 4}); execute_instruction((Instruction){3, 4, 5}); execute_instruction((Instruction){1, 13, 13}); execute_instruction((Instruction){3, 5, 6}); execute_instruction((Instruction){7, 11, 11}); execute_instruction((Instruction){3, 6, 7}); execute_instruction((Instruction){4, 10, 12}); execute_instruction((Instruction){3, 7, 8}); execute_instruction((Instruction){18, 12, 12}); execute_instruction((Instruction){3, 8, 9}); execute_instruction((Instruction){21, 12, 10}); execute_instruction((Instruction){3, 9, 10});
	if (check(registers)){
		printf("Good\n");
		return 0 ;
	}
	printf("False");
	return 0;
}
