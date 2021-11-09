#include "encoder.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include "server.h"
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <bits/stdc++.h>
#include "stopwatch.h"

#define NUM_PACKETS 8
#define pipe_depth 4
#define DONE_BIT_L (1 << 7)
#define DONE_BIT_H (1 << 15)
#define CHUNK_NUM 70000000

//SHA
#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

char sha256[256];
char* SHA_Table[CHUNK_NUM][4];

//LZW
using namespace std;
vector <int> result;
vector <int> result_table[CHUNK_NUM];
unordered_map<string, int> table;
int chunk_offset = 0;

//variable
int chunk_num = 0;
int offset = 0;
unsigned char* file;
int First_Index=0;
int Last_Index=0;


void handle_input(int argc, char* argv[], int* payload_size) {
	int x;
	extern char *optarg;

	while ((x = getopt(argc, argv, ":c:")) != -1) {
		switch (x) {
		case 'c':
			*payload_size = atoi(optarg);
			printf("payload_size is set to %d optarg\n", *payload_size);
			break;
		case ':':
			printf("-%c without parameter\n'", optopt);
			break;
		}
	}
}

char* StrSHA256(const char* str, long long length, char* sha256){
   char *pp, *ppend;
   long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
       H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
       H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
   long K[64] = {
     0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
   };
   l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
   if (!(pp = (char*)malloc((unsigned long)l))) return 0;
   for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
   for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
   *((long*)(pp + l - 4)) = length << 3;
   *((long*)(pp + l - 8)) = length >> 29;
   for (ppend = pp + l; pp < ppend; pp += 64){
       for (i = 0; i < 16; W[i] = ((long*)pp)[i], i++);
       for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
       A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
       for (i = 0; i < 64; i++){
           T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
           T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
           H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
       }
       H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
   }
   free(addlp); fclose(fh);
   sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
   return sha256;
}


uint64_t hash_func(unsigned char *input, unsigned int pos_)
{
  int WIN_SIZE = 16;
  int PRIME = 3;
  uint64_t hash=0;
  for(int i=0; i<16; i++){
   	hash += ((input[pos+WIN_SIZE-1-i])*(pow(PRIME, i+1)));
  }
  return hash;
}

void cdc(unsigned char *buff, unsigned int buff_size)
{
  for(int j =0; j<256; j++)  SHA_Table[0][j] = 0; //
  int MODULUS = 256;
  int TARGET = 0;
  for(int i=16; i < (buff_size-16); i+=1){
  	uint64_t hash = hash_func(buff,i);
  	if((hash%MODULUS) == TARGET){
		   Last_Index = i;
       char cur_chunk[Last_Index - First_Index+1];
       memcpy(&buff[First_Index], cur_chunk[Last_Index - First_Index+1], Last_Index - First_Index+1);
       SHA_Table[1][chunk_num-chunk_offset] = StrSHA256(cur_chunk,Last_Index-First_Index, sha256);
       SHA_Table[0][chunk_num-chunk_offset] = chunk_num;
       SHA_Table[2][chunk_num-chunk_offset] = Last_Index;
       SHA_Table[3][chunk_num-chunk_offset] = First_Index;
       deplication(buff,chunk_num);

       chunk_num++;
		   First_Index=Last_Index+1;
  	}
  }
}

void deplication(unsigned char *buff, int chunk_num){
  int check = 0;
  for (int i = 0; i < CHUNK_NUM; i++){
      if(SHA_Table[1][chunk_num-chunk_offset] == SHA_Table[1][i-chunk_offset] && chunk_num != i){
          char* temp_chunk;
          memcpy(SHA_Table[0][chunk_num-chunk_offset], &temp_chunk, strlen(SHA_Table[0][chunk_num-chunk_offset]));
          sprintf(SHA_Table[0][chunk_num-chunk_offset],"%s,%d",temp_chunk,i);
          check = 1;
          SHA_Table[0][chunk_num-chunk_offset] = 0;
          SHA_Table[1][chunk_num-chunk_offset] = 0;
          SHA_Table[2][chunk_num-chunk_offset] = 0;
          SHA_Table[3][chunk_num-chunk_offset] = 0;
          chunk_offset++;
    }
  }
  if(!check){
    char* chunk;
    memcpy(&buff[SHA_Table[3][chunk_num-chunk_offset]], &chunk, SHA_Table[2][chunk_num-chunk_offset]-SHA_Table[3][chunk_num-chunk_offset]+1);
    result = LZWencoding(chunk);
    result_table.push_back(result);
  }

}
vector<int> LZWencoding(string s1)
{
    cout << "Encoding\n";

    for (int i = 0; i <= 255; i++) {
        string ch = "";
        ch += char(i);
        table[ch] = i;
    }

    string p = "", c = "";
    p += s1[0];
    int code = 256;
    vector<int> output_code;
    cout << "String\tOutput_Code\tAddition\n";
    for (int i = 0; i < s1.length(); i++) {
        if (i != s1.length() - 1)
            c += s1[i + 1];
        if (table.find(p + c) != table.end()) {
            p = p + c;
        }
        else {
            cout << p << "\t" << table[p] << "\t\t"
                 << p + c << "\t" << code << endl;
            output_code.push_back(table[p]);
            table[p + c] = code;
            code++;
            p = c;
        }
        c = "";
    }
    cout << p << "\t" << table[p] << endl;
    output_code.push_back(table[p]);
    return output_code;
}

void LZWdecoding(vector<int> op)
{
    cout << "\nDecoding\n";
    unordered_map<int, string> table;
    for (int i = 0; i <= 255; i++) {
        string ch = "";
        ch += char(i);
        table[i] = ch;
    }
    int old = op[0], n;
    string s = table[old];
    string c = "";
    c += s[0];
    cout << s;
    int count = 256;
    for (int i = 0; i < op.size() - 1; i++) {
        n = op[i + 1];
        if (table.find(n) == table.end()) {
            s = table[old];
            s = s + c;
        }
        else {
            s = table[n];
        }
        cout << s;
        c = "";
        c += s[0];
        table[count] = table[old] + c;
        count++;
        old = n;
    }
}


int main(int argc, char* argv[]) {
	stopwatch ethernet_timer;
	unsigned char* input[NUM_PACKETS];
	int writer = 0;
	int done = 0;
	int length = 0;
	int count = 0;
	ESE532_Server server;

	// default is 2k
	int payload_size = PAYLOAD_SIZE;

	// set payload_size if decalred through command line
	handle_input(argc, argv, &payload_size);

	file = (unsigned char*) malloc(sizeof(unsigned char) * CHUNK_NUM);
	if (file == NULL) {
		printf("help\n");
	}

	for (int i = 0; i < NUM_PACKETS; i++) {
		input[i] = (unsigned char*) malloc(
				sizeof(unsigned char) * (NUM_ELEMENTS + HEADER));
		if (input[i] == NULL) {
			std::cout << "aborting " << std::endl;
			return 1;
		}
	}

	server.setup_server(payload_size);

	writer = pipe_depth;
	server.get_packet(input[writer]);

	count++;

	// get packet
	unsigned char* buffer = input[writer];

	// decode
	done = buffer[1] & DONE_BIT_L;
	length = buffer[0] | (buffer[1] << 8);
	length &= ~DONE_BIT_H;
	// printing takes time so be weary of transfer rate
	//printf("length: %d offset %d\n",length,offset);

	// we are just memcpy'ing here, but you should call your
	// top function here.
	memcpy(&file[offset], &buffer[HEADER], length);

	offset += length;
	writer++;

	//last message
	while (!done) {
		// reset ring buffer
		if (writer == NUM_PACKETS) {
			writer = 0;
		}

		ethernet_timer.start();
		server.get_packet(input[writer]);
		ethernet_timer.stop();

		count++;

		// get packet
		unsigned char* buffer = input[writer];

		// decode
		done = buffer[1] & DONE_BIT_L;
		length = buffer[0] | (buffer[1] << 8);
		length &= ~DONE_BIT_H;
		//printf("length: %d offset %d\n",length,offset);
		memcpy(&file[offset], &buffer[HEADER], length);

		offset += length;
		writer++;
	}

//================================================================================
  cdc(file, CHUNK_NUM);

  printf("%d\n", result_table);

	// write file to root and you can use diff tool on board
	FILE *outfd = fopen("output_cpu.bin", "wb");
	int bytes_written = fwrite(&file[0], 1, offset, outfd);
	printf("write file with %d\n", bytes_written);
	fclose(outfd);

	for (int i = 0; i < NUM_PACKETS; i++) {
		free(input[i]);
	}
// int main()
// {
//
//     string s = "WYS*WYGWYS*WYSWYSG";
//     vector<int> output_code = encoding(s);
//     cout << "Output Codes are: ";
//     for (int i = 0; i < output_code.size(); i++) {
//         cout << output_code[i] << " ";
//     }
//     cout << endl;
//     decoding(output_code);
// }

	free(file);
	std::cout << "--------------- Key Throughputs ---------------" << std::endl;
	float ethernet_latency = ethernet_timer.latency() / 1000.0;
	float input_throughput = (bytes_written * 8 / 1000000.0) / ethernet_latency; // Mb/s
	std::cout << "Input Throughput to Encoder: " << input_throughput << " Mb/s."
			<< " (Latency: " << ethernet_latency << "s)." << std::endl;

	return 0;
}
