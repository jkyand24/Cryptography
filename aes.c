#include "aes.h"
#include <stdio.h>
#include <string.h>

char SUBMISSION_INFO[256] = "2019250027_정기연";

typedef uint8_t AES_STATE_t_4x4b[4][4]; // 4 byte x 4 byte인 array
typedef uint32_t WORD; // 32 bit

#define convert_4b_to_w(b0, b1, b2, b3) (((WORD)(b0) << 24) | ((WORD)(b1) << 16) | ((WORD)(b2) << 8) | ((WORD)(b3))) // byte 4개 -> WORD 1개

#define HIHEX(x) (x>>4) // 한 byte (= 두 자리의 16진수) 중 첫째 자리

#define LOWHEX(x) (x & 0x0F) // 한 byte (= 두 자리의 16진수) 중 둘째 자리

void state16b_to_state4x4b(AES_STATE_t in, AES_STATE_t_4x4b out) { // 16 byte array ---> 4 byte x 4 byte array (꼭 이렇게 할필요 없지만 단지 제 이해를 위한 것입니다)
	for (int col = 0; col < 4; col++) {
		for (int row = 0; row < 4; row++) {
			out[row][col] = in[col * 4 + row];
		}
	}
}

void state4x4b_to_state16b(AES_STATE_t_4x4b in, AES_STATE_t out) { // 4 byte x 4 byte array ---> 16 byte array
	for (int i = 0; i < 16; i++) {
		int col = i / 4;
		int row = i % 4;

		out[i] = in[row][col];
	}
}

/////// 중간 함수

void RotWord(WORD* word) { // {a0, a1, a2, a3} ---> {a1, a2, a3, a0}
	*word = (*word << 8) | (*word >> 24);
}

uint8_t S_box[16][16] = { 
99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
};

uint8_t Inv_S_box[16][16] = {
	{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
	{0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
	{0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
	{0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
	{0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
	{0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
	{0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
	{0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
	{0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
	{0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
	{0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
	{0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
	{0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
	{0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
	{0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
};

void SubWord(WORD* word) { // 32 bit 중 8 bit씩을 뽑아냄 (xy) ---> S_box[x][y] ---> 다시 합쳐 32 bit 만듦
	WORD result = 0x00000000;

	for (int i = 0; i < 4; i++) {
		uint8_t one_byte = ((*word) >> (8 * i)) & 0xFF;
		uint8_t one_byte_sboxed = S_box[HIHEX(one_byte)][LOWHEX(one_byte)];
		result = result | ((WORD)(one_byte_sboxed) << (8 * i));
	}

	*word = result;
}

WORD Rcon[13] = {
0x01000000, 0x02000000, 0x04000000, 0x08000000,
0x10000000, 0x20000000, 0x40000000, 0x80000000,
0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
0xab000000
};

void SubBytes(uint8_t state[][4]) { // 4 byte x 4 byte array 중 1 byte씩을 S_box 적용
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = S_box[HIHEX(state[i][j])][LOWHEX(state[i][j])];
		}
	}
}

void InvSubBytes(uint8_t state[][4]) { // 4 byte x 4 byte array 중 1 byte씩을 Inv_S_box 적용
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			state[i][j] = Inv_S_box[HIHEX(state[i][j])][LOWHEX(state[i][j])];
		}
	}
}

void CirShiftRows(uint8_t state[4]) { // 4 byte array {b0, b1, b2, b3} ---> {b1, b2, b3, b0}
	uint8_t temp = state[0];
	state[0] = state[1];
	state[1] = state[2];
	state[2] = state[3];
	state[3] = temp;
}

void ShiftRows(uint8_t state[][4]) { 
	for (int i = 1; i < 4; i++)
		for (int j = 0; j < i; j++) // j는 무의미함, 단지 횟수만 설정 (1회, 2회, 3회)
			CirShiftRows(state[i]);
}

void InvCirShiftRows(uint8_t state[4]) { // 4 byte array {b0, b1, b2, b3} ---> {b3, b0, b1, b2}
	uint8_t temp = state[3];
	state[3] = state[2];
	state[2] = state[1];
	state[1] = state[0];
	state[0] = temp;
}

void InvShiftRows(uint8_t state[][4]) {
	for (int i = 1; i < 4; i++)
		for (int j = 0; j < i; j++) // j는 무의미함, 단지 횟수만 설정 (1회, 2회, 3회)
			InvCirShiftRows(state[i]);
}

uint8_t gf_mul2(uint8_t value) { // Galois Field Multiplication
	return (value << 1) ^ ((value & 0x80) ? 0x1B : 0x00);
}

uint8_t gf_mul3(uint8_t value) { // Galois Field Multiplication
	return gf_mul2(value) ^ value;
}

void MixColumns(uint8_t state[][4]) {
	for (int i = 0; i < 4; i++) {
		uint8_t new_4b_0, new_4b_1, new_4b_2, new_4b_3;
		new_4b_0 = gf_mul2(state[0][i]) ^ gf_mul3(state[1][i]) ^ state[2][i] ^ state[3][i];
		new_4b_1 = state[0][i] ^ gf_mul2(state[1][i]) ^ gf_mul3(state[2][i]) ^ state[3][i];
		new_4b_2 = state[0][i] ^ state[1][i] ^ gf_mul2(state[2][i]) ^ gf_mul3(state[3][i]);
		new_4b_3 = gf_mul3(state[0][i]) ^ state[1][i] ^ state[2][i] ^ gf_mul2(state[3][i]);

		state[0][i] = new_4b_0;
		state[1][i] = new_4b_1;
		state[2][i] = new_4b_2;
		state[3][i] = new_4b_3;
	}
}

uint8_t gf_mul9(uint8_t value) { // Galois Field Multiplication
	return gf_mul2(gf_mul2(gf_mul2(value))) ^ value;
}

uint8_t gf_mul11(uint8_t value) { // Galois Field Multiplication
	return gf_mul2(gf_mul2(gf_mul2(value)) ^ value) ^ value;
}

uint8_t gf_mul13(uint8_t value) { // Galois Field Multiplication
	return gf_mul2(gf_mul2(gf_mul2(value) ^ value)) ^ value;
}

uint8_t gf_mul14(uint8_t value) { // Galois Field Multiplication
	return gf_mul2(gf_mul2(gf_mul2(value) ^ value) ^ value);
}

void InvMixColumns(uint8_t state[][4]) {
	for (int i = 0; i < 4; i++) {
		uint8_t new_4b_0, new_4b_1, new_4b_2, new_4b_3;
		new_4b_0 = gf_mul14(state[0][i]) ^ gf_mul11(state[1][i]) ^ gf_mul13(state[2][i]) ^ gf_mul9(state[3][i]);
		new_4b_1 = gf_mul9(state[0][i]) ^ gf_mul14(state[1][i]) ^ gf_mul11(state[2][i]) ^ gf_mul13(state[3][i]);
		new_4b_2 = gf_mul13(state[0][i]) ^ gf_mul9(state[1][i]) ^ gf_mul14(state[2][i]) ^ gf_mul11(state[3][i]);
		new_4b_3 = gf_mul11(state[0][i]) ^ gf_mul13(state[1][i]) ^ gf_mul9(state[2][i]) ^ gf_mul14(state[3][i]);

		state[0][i] = new_4b_0;
		state[1][i] = new_4b_1;
		state[2][i] = new_4b_2;
		state[3][i] = new_4b_3;
	}
}

void AddRoundKey_128(uint8_t state[][4], WORD in_arr[4 * (10 + 1)], int start) {
	for (int col = 0; col < 4; col++) {
		WORD word = in_arr[start + col]; // 32 bit

		for (int row = 0; row < 4; row++) { // 32 bit의 매 8 bit 마다
			uint8_t b_from_w = (word >> (8 * (3 - row))) & 0xFF; // WORD로부터 한 byte씩을 추출
			state[row][col] ^= b_from_w; // 이 byte와 XOR하여 저장
		}
	}
}

void AddRoundKey_192(uint8_t state[][4], WORD in_arr[4 * (12 + 1)], int start) {
	for (int col = 0; col < 4; col++) {
		WORD word = in_arr[start + col]; // 32 bit

		for (int row = 0; row < 4; row++) { // 32 bit의 매 8 bit 마다
			uint8_t b_from_w = (word >> (8 * (3 - row))) & 0xFF; // WORD로부터 한 byte씩을 추출
			state[row][col] ^= b_from_w; // 이 byte와 XOR하여 저장
		}
	}
}

void AddRoundKey_256(uint8_t state[][4], WORD in_arr[4 * (14 + 1)], int start) {
	for (int col = 0; col < 4; col++) {
		WORD word = in_arr[start + col]; // 32 bit

		for (int row = 0; row < 4; row++) { // 32 bit의 매 8 bit 마다
			uint8_t b_from_w = (word >> (8 * (3 - row))) & 0xFF; // WORD로부터 한 byte씩을 추출
			state[row][col] ^= b_from_w; // 이 byte와 XOR하여 저장
		}
	}
}

/////// Key Expansion, Encoding, Decoding (표준문서에 나온 pseudocode를 참조하였습니다)

void AES128_keyexp(AES128_KEY_t in, WORD out[4 * (10+1)]) {
	WORD temp;

	// i = 0 ~ 3

	int i = 0;

	while (i < 4) {
		out[i] = convert_4b_to_w(in[4 * i], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]); 
		i += 1;
	}

	// i = 4 ~ 끝

	i = 4;

	while (i < 4 * (10 + 1)) {
		temp = out[i - 1];

		if (i % 4 == 0) {
			RotWord(&temp); 
			SubWord(&temp); 
			temp = temp ^ Rcon[i / 4 - 1];
		}

		out[i] = out[i - 4] ^ temp;

		i += 1;
	}
}

void AES192_keyexp(AES128_KEY_t in, WORD out[4 * (12 + 1)]) {
	WORD temp;

	// i = 0 ~ 5

	int i = 0;

	while (i < 6) {
		out[i] = convert_4b_to_w(in[4 * i], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
		i += 1;
	}

	// i = 6 ~ 끝

	i = 6;

	while (i < 4 * (12 + 1)) {
		temp = out[i - 1];

		if (i % 6 == 0) {
			RotWord(&temp);
			SubWord(&temp);
			temp = temp ^ Rcon[i / 6 - 1];
		}

		out[i] = out[i - 6] ^ temp;

		i += 1;
	}
}

void AES256_keyexp(AES128_KEY_t in, WORD out[4 * (14 + 1)]) {
	WORD temp;

	// i = 0 ~ 7

	int i = 0;

	while (i < 8) {
		out[i] = convert_4b_to_w(in[4 * i], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
		i += 1;
	}

	// i = 8 ~ 끝

	i = 8;

	while (i < 4 * (14 + 1)) {
		temp = out[i - 1];

		if (i % 8 == 0) {
			RotWord(&temp);
			SubWord(&temp);
			temp = temp ^ Rcon[i / 8 - 1];
		}
		else if (i % 8 == 4) {
			SubWord(&temp);
		}

		out[i] = out[i - 8] ^ temp;

		i += 1;
	}
}

void AES128_enc(AES_STATE_t C, AES_STATE_t P, AES128_KEY_t K128)
{
	// state에 P를 복사해넣음

	AES_STATE_t state;
	memmove(state, P, sizeof(uint8_t) * 16);

	// state -> state4x4b

	AES_STATE_t_4x4b state_4x4b;
	state16b_to_state4x4b(state, state_4x4b);
	
	// key expansion

	WORD K128_expanded[4 * (10 + 1)];
	AES128_keyexp(K128, K128_expanded);

	// encoding

	AddRoundKey_128(state_4x4b, K128_expanded, 0);

	for (int round = 1; round < 10; round++) {
		SubBytes(state_4x4b);
		ShiftRows(state_4x4b);
		MixColumns(state_4x4b);
		AddRoundKey_128(state_4x4b, K128_expanded, round * 4);
	}

	SubBytes(state_4x4b);
	ShiftRows(state_4x4b);
	AddRoundKey_128(state_4x4b, K128_expanded, 10 * 4);

	// state4x4b -> state

	state4x4b_to_state16b(state_4x4b, C);
}

void AES128_dec(AES_STATE_t P, AES_STATE_t C, AES128_KEY_t K128)
{
	// state에 C를 복사해넣음

	AES_STATE_t state;
	memmove(state, C, sizeof(uint8_t) * 16);

	// state -> state4x4b

	AES_STATE_t_4x4b state_4x4b;
	state16b_to_state4x4b(state, state_4x4b);

	// key expansion

	WORD K128_expanded[4 * (10 + 1)];
	AES128_keyexp(K128, K128_expanded);

	// decoding

	AddRoundKey_128(state_4x4b, K128_expanded, 10 * 4);

	for (int round = 9; round > 0; round--) {
		InvShiftRows(state_4x4b);
		InvSubBytes(state_4x4b);
		AddRoundKey_128(state_4x4b, K128_expanded, round * 4);
		InvMixColumns(state_4x4b);
	}

	InvShiftRows(state_4x4b);
	InvSubBytes(state_4x4b);
	AddRoundKey_128(state_4x4b, K128_expanded, 0);

	// state4x4b -> state

	state4x4b_to_state16b(state_4x4b, P);
}

void AES192_enc(AES_STATE_t C, AES_STATE_t P, AES192_KEY_t K192)
{
	// state에 P를 복사해넣음

	AES_STATE_t state;
	memmove(state, P, sizeof(uint8_t) * 16);

	// state -> state4x4b

	AES_STATE_t_4x4b state_4x4b;
	state16b_to_state4x4b(state, state_4x4b);

	// key expansion

	WORD K192_expanded[4 * (12 + 1)];
	AES192_keyexp(K192, K192_expanded);

	// encoding

	AddRoundKey_192(state_4x4b, K192_expanded, 0);

	for (int round = 1; round < 12; round++) {
		SubBytes(state_4x4b);
		ShiftRows(state_4x4b);
		MixColumns(state_4x4b);
		AddRoundKey_192(state_4x4b, K192_expanded, round * 4);
	}

	SubBytes(state_4x4b);
	ShiftRows(state_4x4b);
	AddRoundKey_192(state_4x4b, K192_expanded, 12 * 4);

	// state4x4b -> state

	state4x4b_to_state16b(state_4x4b, C);
}

void AES192_dec(AES_STATE_t P, AES_STATE_t C, AES192_KEY_t K192)
{
	// state에 C를 복사해넣음

	AES_STATE_t state;
	memmove(state, C, sizeof(uint8_t) * 16);

	// state -> state4x4b

	AES_STATE_t_4x4b state_4x4b;
	state16b_to_state4x4b(state, state_4x4b);

	// key expansion

	WORD K192_expanded[4 * (12 + 1)];
	AES192_keyexp(K192, K192_expanded);

	// decoding

	AddRoundKey_192(state_4x4b, K192_expanded, 12 * 4);

	for (int round = 11; round > 0; round--) {
		InvShiftRows(state_4x4b);
		InvSubBytes(state_4x4b);
		AddRoundKey_192(state_4x4b, K192_expanded, round * 4);
		InvMixColumns(state_4x4b);
	}

	InvShiftRows(state_4x4b);
	InvSubBytes(state_4x4b);
	AddRoundKey_192(state_4x4b, K192_expanded, 0);

	// state4x4b -> state

	state4x4b_to_state16b(state_4x4b, P);
}

void AES256_enc(AES_STATE_t C, AES_STATE_t P, AES256_KEY_t K256)
{
	// state에 P를 복사해넣음

	AES_STATE_t state;
	memmove(state, P, sizeof(uint8_t) * 16);

	// state -> state4x4b

	AES_STATE_t_4x4b state_4x4b;
	state16b_to_state4x4b(state, state_4x4b);

	// key expansion

	WORD K256_expanded[4 * (14 + 1)];
	AES256_keyexp(K256, K256_expanded);

	// encoding

	AddRoundKey_256(state_4x4b, K256_expanded, 0);

	for (int round = 1; round < 14; round++) {
		SubBytes(state_4x4b);
		ShiftRows(state_4x4b);
		MixColumns(state_4x4b);
		AddRoundKey_256(state_4x4b, K256_expanded, round * 4);
	}

	SubBytes(state_4x4b);
	ShiftRows(state_4x4b);
	AddRoundKey_256(state_4x4b, K256_expanded, 14 * 4);

	// state4x4b -> state

	state4x4b_to_state16b(state_4x4b, C);
}

void AES256_dec(AES_STATE_t P, AES_STATE_t C, AES256_KEY_t K256)
{
	// state에 C를 복사해넣음

	AES_STATE_t state;
	memmove(state, C, sizeof(uint8_t) * 16);

	// state -> state4x4b

	AES_STATE_t_4x4b state_4x4b;
	state16b_to_state4x4b(state, state_4x4b);

	// key expansion

	WORD K256_expanded[4 * (14 + 1)];
	AES256_keyexp(K256, K256_expanded);

	// decoding

	AddRoundKey_256(state_4x4b, K256_expanded, 14 * 4);

	for (int round = 13; round > 0; round--) {
		InvShiftRows(state_4x4b);
		InvSubBytes(state_4x4b);
		AddRoundKey_256(state_4x4b, K256_expanded, round * 4);
		InvMixColumns(state_4x4b);
	}

	InvShiftRows(state_4x4b);
	InvSubBytes(state_4x4b);
	AddRoundKey_256(state_4x4b, K256_expanded, 0);

	// state4x4b -> state

	state4x4b_to_state16b(state_4x4b, P);
}