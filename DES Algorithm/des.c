#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include "des table.h"

int L0[8][4]; // left32 plaintext
int R0[8][4]; // right32 plaintext
int Plaintext_8_6[8][6];
int Plaintext_48[48];
int Plaintext_32[32];
int R_AfterXOR_Key[48]; //key와 Xor 연산
int R_AfterXOR_L[48]; //left & right XOR 연산
int R_AfterSBox_8_4[8][4]; //s box 연산 결과 
int plaintext[64]; //평문
int Original_key[64] = { 1,0,1,0, 0,0,1,0, 1,1,0,1, 1,0,0,0,
               0,1,0,1, 1,1,0,1, 0,0,1,0, 0,1,1,1,
               1,1,1,1, 0,0,0,0, 1,1,1,1, 0,0,0,0,
               0,0,0,0, 1,1,1,1, 0,0,0,0, 1,1,1,1};
int subkey[16][32]; 
int key56bit[56];
int key48bit[48];

//평문 permutation (with IP Table) 평문=Plaintext
void Plaintext_AfterPermutation() {
    int i;
    int temp; int q[64];

    for (i = 0; i < 64; i++) {

        q[i] = plaintext[i];
    }
    for (i = 0; i < 64; i++) {
        temp = DES_IP_TABLE[i];
        plaintext[i] = q[temp - 1];
    }
}

//역ip permutation 연산 
void Permutation_PI() {
    int i;
    int temp; int q[64];

    for (i = 0; i < 64; i++) {

        q[i] = plaintext[i];
    }
    for (i = 0; i < 64; i++) {
        temp = PI_TABLE[i];
        plaintext[i] = q[temp - 1];
    }
}

//평문 left right division
void Divide_L_R(int plaint[64]) {
    int i, j; int k = 0;
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 4; j++) {
            L0[i][j] = plaint[j + k];
            R0[i][j] = plaint[j + 32 + k];
        }
        k = k + 4;
    }
}

// L0[8][4]와 R0[8][4]를 Plaintext[64]로 합치는 함수
void combineToPlaintext() {
    int index = 0;

    // L0 행렬의 요소를 상위 32개로 복사
    for (int row = 0; row < 8; row++) {
        for (int col = 0; col < 4; col++) {
            plaintext[index++] = L0[row][col];
        }
    }

    // R0 행렬의 요소를 하위 32개로 복사
    for (int row = 0; row < 8; row++) {
        for (int col = 0; col < 4; col++) {
            plaintext[index++] = R0[row][col];
        }
    }
}

// 32bit R -> 48bit R 로 확장
void Extend_R(int arr[8][4], int exArr[8][6]) {
    int i, j;
    for (i = 0; i < 8; i++) {
        exArr[i][5] = arr[(i + 1) % 8][0];
        exArr[i][0] = arr[(7 + i) % 8][3];

        for (j = 1; j < 5; j++) {
            exArr[i][j] = arr[i][j - 1];
        }
    }
}

// Arr[8][6] -> Arr[48]
void Combine_8_6bit_to_48bit(int Arr2[8][6], int Arr[48]) {
    int i, j;
    int k = 0;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 6; j++) {
            Arr[j + k] = Arr2[i][j];
        }
        k = k + 6;
    }
}

// 48bit R 과 Key가 xor한 결과
void XOR_key(int Arr[], int Arr2[]) {
    int i = 0;

    for (i = 0; i < 48; i++) {
        R_AfterXOR_Key[i] = Arr[i] ^ Arr2[i];
    }
}

// 32bit Left, Right가 xor한 결과
void XOR_LR(int Arr[], int Arr2[8][4]) {
    int i = 0; int j = 0;
    int count = 0;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 4; j++) {
            R_AfterXOR_L[j+count] = Arr[j + count] ^ Arr2[i][j];
        }
        count += 4;
    }
}


// Arr[48] -> Arr[8][6]
void Divide_48bit_to_8_6(int Arr[48], int Arr2[8][6]) {
    int i, j;
    int k = 0;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 6; j++) {
            Arr2[i][j] = Arr[j + k];
        }
        k = k + 6;
    }
}

// S 박스 , substitution
void Sbox(int exArr[8][6]) {
    int num;
    int j = 0;
    int row = 0, col = 0;

    for (int i = 0; i < 8; i++) {
        row = (exArr[i][0] * 2) + (exArr[i][5] * 1);
        col = (exArr[i][1] * 8) + (exArr[i][2] * 4) + (exArr[i][3] * 2) +
            (exArr[i][4] * 1);
        num = S_BOX[j][row*col]; // 10진수 출력
        R_AfterSBox_8_4[i][0] = (num / 8) ? 1 : 0; num %= 8;  //2진수 변화
        R_AfterSBox_8_4[i][1] = (num / 4) ? 1 : 0; num %= 4;
        R_AfterSBox_8_4[i][2] = (num / 2) ? 1 : 0; num %= 2;
        R_AfterSBox_8_4[i][3] = (num / 1) ? 1 : 0;
        j++;
        if (j == 8) { j = 0; };
    }
}

//p table permutation
void Permutation_P(int Arr[32]) {
    int i;
    int temp; int q[32];
    int count = 0;

    for (i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            q[j+count] = R_AfterSBox_8_4[i][j];
        }
        count += 4;
    }
    for (i = 0; i < 32; i++) {
        temp = P_TABLE[i];
        Arr[i] = q[temp - 1];
    }
}

void Permutation_PC1_key(int Arr[64],int Arr2[56]) {
    int i;
    int q[64];
    

    for (i = 0; i < 64; i++) {

        q[i] = Arr[i];
    }

    for (i = 0; i < 56; i++) {
        Arr2[i] = q[PC_1_TABLE[i] - 1];
    }
}

void Permutation_PC2_key(int Left[28], int Right[28],int Arr[48]) {
    int i;
    int temp; int q[56];


    for (i = 0; i < 28; i++) {
        q[i] = Left[i];
        q[i + 28] = Right[i];
    }

    for (i = 0; i < 48; i++) {
        temp = PC_2_TABLE[i];
        Arr[i] = q[temp - 1];
    }
}

//key calculation 
void Key_generate(int key[]) {
    int Left_key[28], Right_key[28];
    int shift_l,shift_r;
    
    Permutation_PC1_key(key,key56bit); //PC1 Permutation

    for (int i = 0; i < 28; i++) { //key divide
        Left_key[i] = key56bit[i];
        Right_key[i] = key56bit[i + 28];
    }

    //left sift 
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < SHIFTS[i]; j++) {
            shift_l = Left_key[0];
            shift_r = Right_key[0];
            for (int k = 0; k < 27; k++) {
                Left_key[k] = Left_key[k + 1];
                Right_key[k] = Right_key[k + 1];
            }
            Left_key[27] = shift_l;
            Right_key[27] = shift_r;
        }
        
        Permutation_PC2_key(Left_key,Right_key,key48bit);  //PC2 
        for (int j = 0; j < 48; j++) {
            subkey[i][j] = key48bit[j];   //round 후 만들어진 key 저장 
        }
    }
}

void Save_LR() {
    int i = 0; int j = 0;
    int count = 0;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 4; j++) {
            L0[i][j] = R0[i][j];
            R0[i][j] = R_AfterXOR_L[i + count];
        }
        count += 4;
    }
}

// 문자를 8비트 2진수로 변환하여 출력하는 함수
void charToBinary(char c, FILE* outputFile) {
    for (int i = 7; i >= 0; i--) {
        fprintf(outputFile, "%d", (c >> i) & 1);
    }
}

void DES_Round(int i) {
    Extend_R(R0, Plaintext_8_6);  //평문 확장 
    Combine_8_6bit_to_48bit(Plaintext_8_6, Plaintext_48); //[8][6] -> 48 
    XOR_key(Plaintext_48, subkey[i]);
    Divide_48bit_to_8_6(R_AfterXOR_Key, Plaintext_8_6); //48 -> [8][6]
    Sbox(Plaintext_8_6);  //s_box 연산
    Permutation_P(Plaintext_32);  //permutation P (sbox 연산이 끝난 결과를 섞음)
    XOR_LR(Plaintext_32, L0);  //L문 R문 XOR
    Save_LR(); // 변경된 L문 R문 저장
}

void DES_Alggorithm(int i) {
    if (i == 1) //암호화
    {
        Plaintext_AfterPermutation(); //평문 ip permutation
        Key_generate(Original_key); //subkey 생성
        Divide_L_R(plaintext);  //평문 나눔
        for (int i = 0; i < 16; i++)
            DES_Round(i);
        combineToPlaintext(); // L(32)과 R(32)을 64비트 평문으로 합침
        Permutation_PI();  //역 IP 연산 수행
    }
    else {  //복호화  
        Plaintext_AfterPermutation(); //평문 ip permutation
        Key_generate(Original_key); //subkey 생성
        Divide_L_R(plaintext);  //평문 나눔
        for (int i = 15; i >= 0; i--)
            DES_Round(i);
        combineToPlaintext(); // L(32)과 R(32)을 64비트 평문으로 합침
        Permutation_PI();  //역 IP 연산 수행
    }
}



int main()
{
    FILE* PlainFile, * inputFile,* outputFile;
    char PlainFilename[100];
    int s;
    char c;
    int count = 0;    

    printf("입력 텍스트 파일의 이름을 입력하세요(존재하는 파일 선택): ");
    scanf("%s", PlainFilename);

    PlainFile = fopen(PlainFilename, "r"); // 입력 파일을 읽기 모드로 열기

    if (PlainFile == NULL) {
        perror("입력 파일 열기 오류");
        return 1;
    }

    outputFile = fopen("binary.txt", "w"); // 출력 파일을 쓰기 모드로 열기

    if (outputFile == NULL) {
        perror("출력 파일 열기 오류");
        fclose(PlainFile);
        return 1;
    }
    
    // 입력 파일에서 문자를 읽어 2진수로 변환하여 출력 파일에 저장
    while ((c = fgetc(PlainFile)) != EOF) {
        charToBinary(c, outputFile);
        count++;
        // 64비트에 문자열이 채워졌을 때, 개행 문자 추가
        if (count == 8) {
            fprintf(outputFile, "\n");
            count = 0; // 초기화
        }
    }

    // 마지막 줄이 64비트 미만인 경우 나머지 비트를 0으로 채움
    while (count !=0 && count < 8) {
        fprintf(outputFile, "00000000");
        count++;
    }

    fclose(PlainFile); // 입력 파일 닫기
    fclose(outputFile); // 출력 파일 닫기


    inputFile = fopen("binary.txt", "r"); // 입력 파일을 읽기 모드로 열기

    if (inputFile == NULL) {
        perror("입력 파일 열기 오류");
        return 1;
    }

    //베열에 평문 저장   
    for (int i = 0; i < 64; i++) {
        c = fgetc(inputFile);
        s = (int)c;
        plaintext[i] = s - 48;
    }

    fclose(inputFile); // 입력 파일 닫기

    // plaintext 출력
    printf("plaintext:\n");
    for (int i = 0; i < 64; i++) {
        printf("%d ", plaintext[i]);
    }
    printf("\n");

    DES_Alggorithm(1);
     
    printf("Encryption: \n");
    for (int i = 0; i < 64; i++) {
        printf("%d ", plaintext[i]);
    }
    printf("\n");

    DES_Alggorithm(0);

    printf("Decryption: \n");
    for (int i = 0; i < 64; i++) {
        printf("%d ", plaintext[i]);
    }
    printf("\n");

    //outputFile = fopen("result.txt", "w"); // 출력 파일을 쓰기 모드로 열기
    //if (outputFile == NULL) {
    //    perror("출력 파일 열기 오류");
    //    fclose(inputFile);
    //    return 1;
    //}

    //fclose(outputFile); // 출력 파일 닫기


    return 0;

}