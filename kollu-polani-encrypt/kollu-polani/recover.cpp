#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <iostream>
#include "CryptoPP\osrng.h"

using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "CryptoPP\cryptlib.h"
using CryptoPP::Exception;

#include "CryptoPP\sha.h"
using CryptoPP::SHA256;

#include "CryptoPP\hmac.h"
using CryptoPP::HMAC;

#include "CryptoPP\base64.h"
using CryptoPP::Base64Encoder;

#include "CryptoPP\hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "CryptoPP\filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashFilter;

#include "CryptoPP\des.h"
using CryptoPP::DES_EDE2;

#include "CryptoPP\modes.h"
using CryptoPP::CBC_Mode;

#include "CryptoPP\secblock.h"
using CryptoPP::SecByteBlock;
#include <iostream>
#include <string>
#include "CryptoPP\modes.h"
#include "CryptoPP\aes.h"
using CryptoPP::AES;
#include "CryptoPP\filters.h"
#include <fstream>

int recover(string fk)
{
	system("pause");
	string decryptedtext,line;
       bool cstatus = false;
	string encoded, niv;
	std::ifstream myfile3("encode.txt");

	if (myfile3.is_open())
	{
		while (getline(myfile3, line))
		{
			if ((line.compare("tag") == 0))
			{
				//cout << "tag start"  << endl;
				cstatus = false;
			}
			if (cstatus)
			{
				cout << "started iv line is"  << endl;
				niv = niv + line;
			}
			if ((line.compare("iv") == 0))
			{
				cout << "iv not yet started line is"  << endl;
				cstatus = true;
			}
		}
		myfile3.close();
	}

	cout << "new iv is" << niv;

	cstatus = false;
	myfile3.close();

	std::ifstream myfile4("encode.txt");
	if (myfile4.is_open())
	{
		while (getline(myfile4, line))
		{
			if (cstatus)
			{
				cout << "started cipher line is" << endl;
				encoded = encoded + line;
			}
			if ((line.compare("ci") == 0))
			{
				cout << "cipher not yet started line is"  << endl;
				cstatus = true;
			}
		}
		myfile4.close();
	}
	
	cout << "return cipher is" << encoded;

	cstatus = false;
	string ntag;
	std::ifstream myfile5("encode.txt");

	if (myfile5.is_open())
	{
		while (getline(myfile5, line))
		{
			if ((line.compare("ci") == 0))
			{
				cout << "cipher start"  << endl;
				cstatus = false;
			}
			if (cstatus)
			{
				cout << "started tag line is"  << endl;
				ntag = ntag + line;
			}
			if ((line.compare("tag") == 0))
			{
				cout << "tag not yet started line is"  << endl;
				cstatus = true;
			}
		}
		myfile5.close();
	}

	cout << "new tag is" << ntag << endl;
	system("pause");

	cout << endl;
	cout << endl;
	char *name2;
	name2 = (char*)malloc(niv.length() + 1); // don't forget to free!!!!
	//s2 = Database_row_count; // I forget if the string class can implicitly be converted to char*
	//s2[0] = '1';

	strcpy(name2, niv.c_str());

	const char* hex_str = name2;

	std::string iv;
	unsigned int ch;
	for (; std::sscanf(hex_str, "%2x", &ch) == 1; hex_str += 2)
		iv += ch;
	cout << "HEX FORM to iv text :: ";
	std::cout << iv << '\n';
	cout << endl;
	cout << endl;

	/////////////////////////////////////
	//////////////////////////////
	///iv back to original/////////
	///////////////


	char *name3;
	name3 = (char*)malloc(encoded.length() + 1); // don't forget to free!!!!
	//s2 = Database_row_count; // I forget if the string class can implicitly be converted to char*
	//s2[0] = '1';

	strcpy(name3, encoded.c_str());

	const char* hex_str3 = name3;

	std::string result_string;
	unsigned int ch3;
	for (; std::sscanf(hex_str3, "%2x", &ch3) == 1; hex_str3 += 2)
		result_string += ch3;
	cout << "HEX FORM to cipher text :: ";
	std::cout << result_string << '\n';
	cout << endl;
	cout << endl;



	///////////////////////////////
/////////////////data intigrity check/////////////////////
	//////////////////////////





	string encodedd;
	string mac;
	try
	{
		HMAC< SHA256 > hmac((byte*)fk.c_str(), fk.size());

		StringSource ss2(encoded, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encodedd.clear();
	StringSource ss3(mac, true,
		new HexEncoder(
		new StringSink(encodedd)
		) // HexEncoder
		); // StringSource

	cout << "hmac: " << encodedd << endl;


	if ((encodedd.compare(ntag) == 0))
	{
		cout << "intigrity verified";
	}

	else
	{
		cout << "file data compromised exiting without decryption";
		exit(1);
	}
	/*********************************\
	\*********************************/
	//result_string = "1234567812345678" + result_string;
	cout << "before decrypt fk is" << fk << endl;
		CryptoPP::AES::Decryption aesDecryption((byte *)fk.c_str(), CryptoPP::AES::MAX_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (byte *)iv.c_str());

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	//stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size()); 
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size());

	stfDecryptor.MessageEnd();
	std::cout << "Decrypted Text: " << std::endl;
	std::cout << decryptedtext;
	std::cout << std::endl << std::endl;

	system("pause");

	return 0;
}