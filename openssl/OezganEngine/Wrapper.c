/*
 * wrapper.cc
 *
 *  Created on: Sep 30, 2015
 *      Author: oezgan
 */

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "wrapper.h"


using namespace std;
typedef unsigned char       byte;
typedef std::vector<byte> ByteVector;

void getRandomBytes_C(unsigned char* buffer, int numBytes) {
	string str = "oezgan engine wrapper getRandomBytes C++ method";
	cout << str << "\n";
	string fileName = "/dev/urandom";
	ByteVector result;
	std::ifstream inFile(fileName.c_str());

	std::filebuf* fileBuf = inFile.rdbuf();
	result.resize(numBytes);
	fileBuf->sgetn(reinterpret_cast<char*>(&result[0]), numBytes);
	inFile.close();
	memcpy(buffer,&result[0],numBytes);

}