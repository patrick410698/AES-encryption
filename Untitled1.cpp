#include <iostream>
#include <stdio.h>
#include <bitset>
#include <string>
#include <fstream>
#include <vector>
#include <ctime>  


using namespace std;
int number_of_round = 0; //加密運算執行回合數，加密運算執行回合數, AES-128(10r), AES-192(12), AES-256(14)

int block_of_key = 0;  //定義一個Key有幾個block AES-128(4 block), AES-192(6), AES-256(8) 
const int number_of_block=4;//定義一個block是32bit
const int MODULUS = 0x11B;

unsigned char input[16];          // 輸入char陣列
unsigned char output[16];         // 密文區塊輸出陣列
unsigned int in_number[128];
unsigned int out_number[128];
unsigned char state[4][4];     //加密運算過程中的的狀態陣列 4 * 4 
unsigned char previous_state[4][4];
unsigned char Roundkey[240];   // round key array, stored Main Key and Expanded Key (Ex: AES-128(44words/176 bytes), AES-256(60w/260bytes)), 儲存主要鑰匙跟擴充鑰匙的陣列, w0(index 0 ~ 3) w1(index 4 ~ 7)....
unsigned char Key[32];         // Main key(input key Ex. AES-128(16 char), AES-256(32 char)), 輸入的金鑰

int S_Box[256] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};
int Inverse_S_Box[256]{
    
	0x52    ,0x09	,0x6a	,0xd5	,0x30	,0x36	,0xa5	,0x38	,0xbf	,0x40	,0xa3	,0x9e	,0x81	,0xf3	,0xd7	,0xfb,
	0x7c	,0xe3	,0x39	,0x82	,0x9b	,0x2f	,0xff	,0x87	,0x34	,0x8e	,0x43	,0x44	,0xc4	,0xde	,0xe9	,0xcb,
	0x54	,0x7b	,0x94	,0x32	,0xa6	,0xc2	,0x23	,0x3d	,0xee	,0x4c	,0x95	,0x0b	,0x42	,0xfa	,0xc3	,0x4e,
	0x08	,0x2e	,0xa1	,0x66	,0x28	,0xd9	,0x24	,0xb2	,0x76	,0x5b	,0xa2	,0x49	,0x6d	,0x8b	,0xd1	,0x25,
	0x72	,0xf8	,0xf6	,0x64	,0x86	,0x68	,0x98	,0x16	,0xd4	,0xa4	,0x5c	,0xcc	,0x5d	,0x65	,0xb6	,0x92,
	0x6c	,0x70	,0x48	,0x50	,0xfd	,0xed	,0xb9	,0xda	,0x5e	,0x15	,0x46	,0x57	,0xa7	,0x8d	,0x9d	,0x84,
	0x90	,0xd8	,0xab	,0x00	,0x8c	,0xbc	,0xd3	,0x0a	,0xf7	,0xe4	,0x58	,0x05	,0xb8	,0xb3	,0x45	,0x06,
	0xd0	,0x2c	,0x1e	,0x8f	,0xca	,0x3f	,0x0f	,0x02	,0xc1	,0xaf	,0xbd	,0x03	,0x01	,0x13	,0x8a	,0x6b,
	0x3a	,0x91	,0x11	,0x41	,0x4f	,0x67	,0xdc	,0xea	,0x97	,0xf2	,0xcf	,0xce	,0xf0	,0xb4	,0xe6	,0x73,
	0x96	,0xac	,0x74	,0x22	,0xe7	,0xad	,0x35	,0x85	,0xe2	,0xf9	,0x37	,0xe8	,0x1c	,0x75	,0xdf	,0x6e,
	0x47	,0xf1	,0x1a	,0x71	,0x1d	,0x29	,0xc5	,0x89	,0x6f	,0xb7	,0x62	,0x0e	,0xaa	,0x18	,0xbe	,0x1b,
	0xfc	,0x56	,0x3e	,0x4b	,0xc6	,0xd2	,0x79	,0x20	,0x9a	,0xdb	,0xc0	,0xfe	,0x78	,0xcd	,0x5a	,0xf4,
	0x1f	,0xdd	,0xa8	,0x33	,0x88	,0x07	,0xc7	,0x31	,0xb1	,0x12	,0x10	,0x59	,0x27	,0x80	,0xec	,0x5f,
	0x60	,0x51	,0x7f	,0xa9	,0x19	,0xb5	,0x4a	,0x0d	,0x2d	,0xe5	,0x7a	,0x9f	,0x93	,0xc9	,0x9c	,0xef,
	0xa0	,0xe0	,0x3b	,0x4d	,0xae	,0x2a	,0xf5	,0xb0	,0xc8	,0xeb	,0xbb	,0x3c	,0x83	,0x53	,0x99	,0x61,
	0x17	,0x2b	,0x04	,0x7e	,0xba	,0x77	,0xd6	,0x26	,0xe1	,0x69	,0x14	,0x63	,0x55	,0x21	,0x0c	,0x7d
};
//for key expansion
//RC[j] = 0x02 × RC[j ? 1]
int roundconstant[11] = 
{
//   0     1     2     3      4    5     6     7     8    9     10
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

void KeyExpansion(){
    unsigned char tempByte[4]; //變換過程中儲存一個word，ex:wo....
    unsigned char a0; // 執行left circular shift 先暫存a0 
    for (int i = 0;i < block_of_key;i++){
        Roundkey[i * 4] = Key[i * 4];
        Roundkey[i *4 + 1] = Key[i * 4 + 1];
        Roundkey[i *4 + 2] = Key[i * 4 + 2];
        Roundkey[i *4 + 3] = Key[i * 4 + 3];
    }
    for (int i = block_of_key;i < (number_of_block * (number_of_round + 1));i++)//128的話，10個round，11個儲存單位，共44個block
    {
        for (int j = 0;j < 4;j++){ // 處理每個block(W)
            tempByte[j] = Roundkey[(i - 1) * 4 + j]; // 要新增一個block(Word)故取前一個的W值存入tempW
        }
        if (i % block_of_key == 0){
            //forAES-128，從i=4到43共進來10次
            //根據 purdue講義，產生g()的方式有兩步，分別是shift跟substitution

            //AES-128 i 是 4 的倍數的 Wi 用 Wi-1產生 Wi =  SubWord(RotWord(Wi-1)) XOR Rcon[i/4]
            //同一列向左平移一。執行left circular shift
            // RotWord function, [a0, a1, a2, a3](4byte) left circular shift in a word [a1, a2, a3, a0]
            a0 = tempByte[0];
            tempByte[0] = tempByte[1];
            tempByte[1] = tempByte[2];
            tempByte[2] = tempByte[3];
            tempByte[3] = a0;

            //進行sbox的取代
            // SubWord function (S-Box substitution)
            //(int)tempByte[0]表示將資料類型從unsigned char轉換為int
            tempByte[0] = S_Box[(int)tempByte[0]];
            tempByte[1] = S_Box[(int)tempByte[1]];
            tempByte[2] = S_Box[(int)tempByte[2]];
            tempByte[3] = S_Box[(int)tempByte[3]];
    
            // XOR Rcon[i/4], only leftmost byte are changed (只會XOR最左的byte)
            tempByte[0] = tempByte[0] ^ roundconstant[i / block_of_key]; 
        }
        else if (block_of_key == 8 && i % block_of_key == 4){
            // Only AES-256 used, 僅 AES-256 使用此規則, 
            // 當 i mod 4 = 0 且 i mod 8 ≠ 0 時，Wn = SubWord (Wn?1) XOR Wn?8
            tempByte[0] = S_Box[(int)tempByte[0]];
            tempByte[1] = S_Box[(int)tempByte[1]];
            tempByte[2] = S_Box[(int)tempByte[2]];
            tempByte[3] = S_Box[(int)tempByte[3]];
        }
        /**
         * Wn = Wn-1 XOR Wk    k = current word - Nb_k
         * Ex: AES-128   Nb_k = 4  when W5 = Wn-1(W4) XOR Wk(W1)
         * Ex: AES-256   Nb_k = 8  when W10 = Wn-1(W9) XOR Wk(W2) 
         */
        Roundkey[i * 4 + 0] = Roundkey[(i - block_of_key) * 4 + 0] ^ tempByte[0];
        Roundkey[i * 4 + 1] = Roundkey[(i - block_of_key) * 4 + 1] ^ tempByte[1];
        Roundkey[i * 4 + 2] = Roundkey[(i - block_of_key) * 4 + 2] ^ tempByte[2];
        Roundkey[i * 4 + 3] = Roundkey[(i - block_of_key) * 4 + 3] ^ tempByte[3];   
    }
}

//進行加密的第一步，先add round key
/*
Each round has its own round key that is derived from the
original 128-bit encryption key in the manner described in this
section. One of the four steps of each round, for both
encryption and decryption, involves XORing of the round key
with the state array.
*/
void AddRoundKey(int round)
{
    /**
     * 根據round來使用key(每次用1個block = 16byte)
     * first key index = round * 16 bytes = round * Nb * 4;
     * Nb = 4
     */
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= Roundkey[(i * number_of_block + j) + (round * number_of_block * 4)]; 
}

// 第一步先進行S-Box Substitution
void SubBytes(){
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[i][j] = S_Box[state[i][j]];
}
void InverseSubBytes(){
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[i][j] = Inverse_S_Box[state[i][j]];
}
//第二步進行substitutuon
// left Circular Shift (row), 列移位函數
void ShiftRows(){
    unsigned char tempByte;
    
    //tempbyte儲存資料
    //第一列不動
    // 2nd row left Circular Shift 1 byte
    tempByte    = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = tempByte;

    // 3th row left Circular Shift 2 byte
    tempByte    = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tempByte;

    tempByte    = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tempByte;

    // 4th row left Circular Shift 3 byte
    tempByte    = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = tempByte;
}
void InverseShiftRow(){
    unsigned char tempByte;
    // 2nd row right Circular Shift 1 byte
    tempByte    = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tempByte;

    // 3th row right Circular Shift 2 byte
    tempByte    = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tempByte;

    tempByte    = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tempByte;

    // 4th row left Circular Shift 3 byte
    tempByte    = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tempByte;

}
//+1
unsigned int binaryAddition(unsigned int a, unsigned int b) {
    unsigned int carry = 0; // 進位初始化為0
    unsigned int result = 0; // 結果初始化為0

    while (b != 0) {
        // 將兩個位元相加，包括進位
        result = a ^ b; // 不進位相加
        carry = (a & b) << 1; // 計算進位

        // 更新a和b，繼續進行下一輪運算
        a = result;
        b = carry;
    }

    return result;
}
// Galois Field 乘法函數，用於乘以 0x02
unsigned int gfMultiplyBy02(unsigned int value) {
    unsigned int result = value << 1;// 左移一位，相當於將 value 乘以 2。結果存儲在 result 中
    if (result & 0x100) {  // 檢查是否超過 8 位
        result ^= MODULUS;
    }
    return result & 0xFF;  // 保持結果在 8 位內
}

// Galois Field 乘法函數，用於乘以 0x03
unsigned int gfMultiplyBy03(unsigned int value) {
    return gfMultiplyBy02(value) ^ value;  // 0x03 = 0x02 ^ 0x01
}
// Galois Field 乘法函數，用於乘以 0x09
unsigned int gfMultiplyBy09(unsigned int value) {
    unsigned int result = gfMultiplyBy03(value);// 左移一位，相當於將 value 乘以 2。結果存儲在 result 中
    unsigned int result2 = gfMultiplyBy03(result);
    if (result2 & 0x100) {  // 檢查是否超過 8 位
        result2 ^= MODULUS;
    }
    return result2 & 0xFF;  // 保持結果在 8 位內
}
// Galois Field 乘法函數，用於乘以 10
unsigned int gfMultiplyBy0A(unsigned int value) {
    unsigned int result = gfMultiplyBy09(value);// 左移一位，相當於將 value 乘以 2。結果存儲在 result 中
    unsigned int result2=binaryAddition(result,value);
    if (result2 & 0x100) {  // 檢查是否超過 8 位
        result2 ^= MODULUS;
    }
    return result2 & 0xFF;  // 保持結果在 8 位內
}
// Galois Field 乘法函數，用於乘以 11
unsigned int gfMultiplyBy0B(unsigned int value) {
    unsigned int result = gfMultiplyBy0A(value);// 左移一位，相當於將 value 乘以 2。結果存儲在 result 中
    unsigned int result2=binaryAddition(result,value);
    if (result2 & 0x100) {  // 檢查是否超過 8 位
        result2 ^= MODULUS;
    }
    return result2 & 0xFF;  // 保持結果在 8 位內
}
// Galois Field 乘法函數，用於乘以 0x13
unsigned int gfMultiplyBy0D(unsigned int value) {
    unsigned int result = gfMultiplyBy02(value);// 左移一位，相當於將 value 乘以 2。結果存儲在 result 中
    unsigned int result2 = gfMultiplyBy03(result);
    unsigned int result3 = gfMultiplyBy03(result2);
    unsigned int result4=binaryAddition(result3,value);
    if (result4 & 0x100) {  // 檢查是否超過 8 位
        result4 ^= MODULUS;
    }
    return result4 & 0xFF;  // 保持結果在 8 位內
}
// Galois Field 乘法函數，用於乘以 0x14
unsigned int gfMultiplyBy0E(unsigned int value) {
    unsigned int result = gfMultiplyBy0D(value);// 左移一位，相當於將 value 乘以 2。結果存儲在 result 中
    unsigned int result2=binaryAddition(result,value);
    if (result2 & 0x100) {  // 檢查是否超過 8 位
        result2 ^= MODULUS;
    }
    return result2 & 0xFF;  // 保持結果在 8 位內
}
void MixColumns()
{
for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            previous_state[i][j] = state[i][j];
        }
    }
for (int i = 0;i < 4;i++) { 
state[0][i]= gfMultiplyBy02(previous_state[0][i]) ^ gfMultiplyBy03(previous_state[1][i]) ^ previous_state[2][i] ^ previous_state[3][i];
state[1][i]= gfMultiplyBy02(previous_state[1][i]) ^ gfMultiplyBy03(previous_state[2][i]) ^ previous_state[0][i] ^ previous_state[3][i];
state[0][i]= gfMultiplyBy02(previous_state[2][i]) ^ gfMultiplyBy03(previous_state[3][i]) ^ previous_state[0][i] ^ previous_state[1][i];
state[0][i]= gfMultiplyBy02(previous_state[3][i]) ^ gfMultiplyBy03(previous_state[0][i]) ^ previous_state[1][i] ^ previous_state[2][i];
}
}
void InverseMixColumns()
{
for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            previous_state[i][j] = state[i][j];
        }
    }
for (int i = 0;i < 4;i++) { 
state[0][i]= gfMultiplyBy0E(previous_state[0][i]) ^ gfMultiplyBy0B(previous_state[1][i]) ^ gfMultiplyBy0D(previous_state[2][i]) ^gfMultiplyBy09(previous_state[3][i]);
state[1][i]= gfMultiplyBy09(previous_state[1][i]) ^ gfMultiplyBy0E(previous_state[2][i]) ^ gfMultiplyBy0B(previous_state[0][i]) ^gfMultiplyBy0D(previous_state[3][i]);
state[0][i]= gfMultiplyBy0D(previous_state[2][i]) ^ gfMultiplyBy09(previous_state[3][i]) ^ gfMultiplyBy0E(previous_state[0][i]) ^gfMultiplyBy0B(previous_state[1][i]);
state[0][i]= gfMultiplyBy0B(previous_state[3][i]) ^ gfMultiplyBy0D(previous_state[0][i]) ^ gfMultiplyBy09(previous_state[1][i]) ^gfMultiplyBy0E(previous_state[2][i]);
}
}
     
void Cipher()
{   
   
    int round = 0;
    
    
    //in[](plaintext) 轉換成 column 排列方式
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input[i * 4 + j]; // transform input(plaintext), 將plaintext 轉成 column形式(w0, w1, w2, w3)
    
    // round 0 : add round key, 第0回合: 僅執行-key XOR block - key使用[w0 ~ w3]
    AddRoundKey(0);

    // Round 1 ~ Nr-1, 反覆執行 1 ~ Nr-1回合
    for (round = 1;round < number_of_round;round++){
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }

    // Round Nr, no MixColumns(), 第 Nr 回合 沒有混合行運算
    SubBytes();
    ShiftRows();
    AddRoundKey(number_of_round);

    //將state[] transform 到 out[]上
   
     
    for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            output[i * 4 + j]=state[j][i];
}
void decrypt(){
    int round = number_of_round;
   
    
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input[i * 4 + j]; 
    AddRoundKey(round);
    for (round = number_of_round-1;round>0 ;round--){
    InverseShiftRow();
    InverseSubBytes();
    AddRoundKey(round);
    InverseMixColumns();
    }
    InverseShiftRow();
    InverseSubBytes();
    AddRoundKey(0);
}


void printUnsignedCharArrayToInt(unsigned char input[], int size){
    for (int i = 0;i < size;i++){
        printf("%d ", input[i]);
    }
}

int main(){
    
    int KeySize = 0; // key Size
    int feof_flag = 0; // detect end of file flag
    unsigned char input_key[32]; // user input Main Key, AES主Key
    unsigned char plaintext_block[16]; // plaintext, encrpty each block (128bit) once


    int decision=0 ;
    int encrypt=0;
    int keysize=0;
    string file_name;
    string output_file;
    string key_name;
    string text;
    string key;
    string ciphertext;
    cout<<"welcome to a shit-like AES encryption system\n";
    cout<<"press 1 to encrypt,press 2 to decrypt\n";
    cin>>encrypt;
    
    
    
        cout<<"Enter intput file name\n";
        cin>>file_name;
        cout<<"Enter output file name\n";
        cin>>output_file;
        cout<<"Enter key file name\n";
        cin>>key_name;

        cout<<"enter key size\n";
        cout<<"press 1 for 128\n";
        cout<<"press 2 for 192\n";
        cout<<"press 3 for 256\n";
        cin>>decision;

        //read key
        if (decision==1){
            keysize=128;
            ifstream inFile(key_name, std::ios::binary);
            if (inFile) {
                inFile.read(reinterpret_cast<char*>(Key), 16);  // Reading the first 16 bytes
            }
        inFile.close();
        }
        else if(decision==2){
            keysize=192;
            ifstream inFile(key_name, std::ios::binary);
            if (inFile) {//inFile.read 配合的是 char* ?型的指?。
                inFile.read(reinterpret_cast<char*>(Key), 24);  // Reading the first 16 bytes
            }
        inFile.close();
        }
         else if(decision==3){
            keysize=256;
            ifstream inFile(key_name, std::ios::binary);
            if (inFile) {
                inFile.read(reinterpret_cast<char*>(Key), 32);  // Reading the first 16 bytes
            }
        inFile.close();    
        }
        
        block_of_key = keysize / 32;    
        number_of_round   = block_of_key + 6;      // Number of round(Nr),  計算AES 運算回合次數 (Ex:AES-128 : 10)

        srand( time(NULL) );
        clock_t sTime = clock();
        /* Key Expansion function, 擴充鑰匙函數產生所有鑰匙 */
        KeyExpansion(); // Expansion Key - AES-128(44words/176 bytes), AES-192(52w/208 bytes), AES-256(60w/260bytes)
        
        /*infile有哪些
        *is_open()：檢查文件是否成功打開。
        read(char* s, std::streamsize n)：從文件中讀取 n 個字節到 s 指向的緩衝區。
        eof()：檢查是否達到文件結尾。
        */

        //read text
        int read_round=0;
        int read_byte=0;
        int remaining_byte=0;
        ifstream inFile(file_name,std::ios::binary);
        if(inFile){
            vector<char> plaintext_block(16); // 用向量來保存每個區塊的資料
            int feof_flag = 1;
            //gcount 是 std::istream 類的一個成員函數，用來返回最近一次非格式化輸入操作中實際讀取的字節數。
            
            while (feof_flag == 1) {//plaintext_block 是一個大小至少為 16 的向量，用來存儲從文件中讀取的數據。
                inFile.read(plaintext_block.data(), 16); // 一次讀取 16 個字元（一個區塊）
                std::streamsize bytes_read = inFile.gcount(); // 確認實際讀取的字節數
                //上面如果你請求讀取 16 個字節但文件中剩餘的字節數少於 16，則 gcount() 會返回實際讀取的字節數。
                if (bytes_read == 0) {
                break; // 已讀取到檔案末尾，退出循環
                }

                if (bytes_read < 16) {
                    // 如果不足 16 個字元，填充 0x00 直到滿足 16 個字元
                    remaining_byte=bytes_read;
                    for (int padding = bytes_read; padding < 16; padding++) {
                        plaintext_block[padding] = 0x00;//在不足16的位置補上0
                    }
                    feof_flag = 0; // 已讀取到檔案末尾
                }

                if (inFile.eof()) {
                feof_flag = 0;
                break; // 已達到文件末尾，退出循環
                }

                else
                read_round++;

                // 在這裡你可以對 plaintext_block 做任何你需要的處理
                // 例如，將 plaintext_block 傳遞給加密函式進行處理
                if(encrypt==1){
        
                int blockNum = 0;
                /**
                * Call Encrypt  function, encrypt one block (128 bit) once
                * input: in[](plaintext), Key[](key)
                * output: out[](cipher) 
                */
                Cipher(); 
                // print plaintext(character format) in Integer Format
                printf("Block %d- plaintext ", blockNum);
                printUnsignedCharArrayToInt(input, 16);    
                printf("\n");
                // print Cipher(character format) in Integer Format
                printf("Block %d - Cipher: ", blockNum); // print ciphertext(char) in integer format
                printUnsignedCharArrayToInt(output, 16);
                printf("\n");
                blockNum++;
                
                }
                else if(encrypt==2){
                    /* Key Expansion function, 擴充鑰匙函數產生所有鑰匙 */
                 // Expansion Key - AES-128(44words/176 bytes), AES-192(52w/208 bytes), AES-256(60w/260bytes)
                int blockNum = 0;
                decrypt();

                // print plaintext(character format) in Integer Format
                printf("Block %d - Ciphertext : ", blockNum);
                printUnsignedCharArrayToInt(input, 16);    
                printf("\n");
                // print Cipher(character format) in Integer Format
                printf("Block %d - plaintext : ", blockNum); // print ciphertext(char) in integer format
                printUnsignedCharArrayToInt(output, 16);
                printf("\n");
                blockNum++;
                }
            } 
        }
        else {
            std::cerr << "Error: Unable to open file!" << std::endl;
        }
        inFile.close(); // 關閉檔案
        read_byte=128*read_round+remaining_byte;
        
        for (int c = 0;c < 16;c++){
            input[c] = plaintext_block[c];
        }
        clock_t eTime =clock();

        double time_elapse=static_cast<double>(eTime-sTime)/CLOCKS_PER_SEC;
        double speed=read_byte/time_elapse;
        if(encrypt==1){
            cout<<"encryption speed"<<speed<<"byte/s\n";
            printf("------------------------------------------------\n");
            printf("Encryption process complete !! \n");
        }
        else if(encrypt==2){
            cout<<"decryption speed"<<speed<<"byte/s\n";
            printf("------------------------------------------------\n");
            printf("decryption process complete !! \n");
        }
        ofstream myFile;
        myFile.open(output_file);
        for(int i=0;i<16;i++){
            myFile<<output[i];
        }
        myFile.close();

}
