// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
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

string sign(string, string );
int recover(string);

int main(int argc, char* argv[]) {
	

	AutoSeededRandomPool prng;
	byte ivs[AES::BLOCKSIZE];
	prng.GenerateBlock(ivs, sizeof(ivs));
	string iv(reinterpret_cast< char const* >(ivs), sizeof(ivs));
	
	string cipher, encoded, recovered;
    string line,plaintext;
	string keyfile, f1, fn1,fn1file;
	if (argc == 4)
	{
		keyfile = argv[1];
		f1 = argv[2];
		fn1file = argv[3];

	}
	else
	{
		cout << "invalid input";
		exit(1);
	}


	string line2;
	std::ifstream myfile9(fn1file);
	if (myfile9.is_open())
	{
		while (getline(myfile9, line2))
		{
			fn1 = fn1 + line2;
		}
		myfile9.close();
	}


	// hard code inputs
	//keyfile = "key.txt";
	//f1 = "test.txt";
	//fn1 = "testname";
	std::ifstream myfile(f1);
	if (myfile.is_open())
	{
		while (getline(myfile, line))
		{
			plaintext=plaintext+line;
		}
		myfile.close();
	}


	
	string key;
	std::ifstream readkey(keyfile);
	if (readkey.is_open())
	{
		while (getline(readkey, line))
		{
			key = key + line;
		}
		readkey.close();
	}

	std::string ciphertext;
	std::string decryptedtext;

	string fk;
	// calculate fk
//adding authorize code//

//	cout << "before authrize fname is" << fn1 << "key is" << key << endl;

	string encodedd;
	string mac;
	try
	{
		HMAC< SHA256 > hmac((byte*)key.c_str(), key.size());

		StringSource ss2(fn1, true,
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

//	cout << "hmac: " << encodedd << endl;

	//////////////////////////////////
	///////////////////////
	/////file name converstion/////


	CryptoPP::SHA1 sha1;
	std::string source = fn1;  //This will be randomly generated somehow
	std::string hash = "";
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

	//cout << "new filename is" << endl << endl << hash<<endl;




	fk = encodedd.substr(0, 31);
   //cout << "fk is" << fk<<std::endl;

	CryptoPP::AES::Encryption aesEncryption((byte *)fk.c_str(), CryptoPP::AES::MAX_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (byte *)iv.c_str());

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1);
	stfEncryptor.MessageEnd();
	//cout << "cipher text plain: " << ciphertext << endl;
	string temp = ciphertext;
//	std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
//	cout << endl;
//	cout << endl;
//	std::cout << "cipher text In HEX FORM:: ";
	for (int i = 0; i < ciphertext.size(); i++) {

	}
//	cout << endl;
//	cout << endl;
	encoded.clear();
	
	StringSource(ciphertext, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource
	//cout << "cipher text In HEX FORM (Modified):: " << encoded << endl;

	string f2=hash+".txt";
	
	//data intigrity check
	string tag;

	//cout << "before tag cipher is" << encoded << endl;
	
	//cout << "before tag fk is" << fk << endl;
	
	string macc;
	string ifk = fk;
		try
	{
		HMAC< SHA256 > hmacc((byte*)ifk.c_str(), ifk.length());

		StringSource(encoded, true,
			new HashFilter(hmacc,
			new StringSink(macc)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}
	tag.clear();
	StringSource(macc, true,
		new Base64Encoder(
		new StringSink(tag)
		) // Base64Encoder
		); // StringSource

	tag.clear();
	StringSource ss4(macc, true,
		new HexEncoder(
		new StringSink(tag)
		) // HexEncoder
		); // StringSource

//	cout << endl << endl << endl << "tag size is" << tag.size() << endl;
	
	//iv hex encoder
	
	string ivh;
	ivh.clear();
	StringSource ss5(iv, true,
		new HexEncoder(
		new StringSink(ivh)
		) // HexEncoder
		); // StringSource



	// write all to output file..
	//write this modified hex to file
	//calculate fn2 from filename modify with sha1
	std::ofstream myfile2(f2);
	if (myfile2.is_open())
	{
		myfile2 << "GG" << endl;
		myfile2 << ivh << endl;
		myfile2 << "HH" << endl;
		myfile2 << tag << endl;
		myfile2 << "II" << endl;
		myfile2 << encoded << endl;

		myfile2.close();
	}

	 
	//cout << "calling recover";
	//int a = recover(fk);
	//cout << "in main";
	
	// from now in recover
	//////////////


	/*
	bool cstatus = false;
	string encoded2,niv;
	std::ifstream myfile3("encode.txt");

	if (myfile3.is_open())
	{
		while (getline(myfile3, line))
		{
			if ((line.compare("tag") == 0))
			{
				cout << "tag start" << line << endl;
				cstatus = false;
			}
			if (cstatus)
			{
				cout << "started iv line is" << line << endl;
				niv = niv + line;
			}
			if ((line.compare("iv") == 0))
			{
				cout << "iv not yet started line is" << line << endl;
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
				cout << "started cipher line is" << line << endl;
				encoded2 = encoded2 + line;
			}
			if (!(line.compare("ci")==0))
			{
				cout << "cipher not yet started line is" << line << endl;
				cstatus = true;
			}
		}
		myfile4.close();
	}
	encoded = encoded2;
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
				cout << "cipher start" << line << endl;
				cstatus = false;
			}
			if (cstatus)
			{
				cout << "started tag line is" << line << endl;
				ntag = ntag + line;
			}
			if ((line.compare("tag") == 0))
			{
				cout << "tag not yet started line is" << line << endl;
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
	name2 = (char*)malloc(encoded.length() + 1); // don't forget to free!!!!
	//s2 = Database_row_count; // I forget if the string class can implicitly be converted to char*
	//s2[0] = '1';
	
	strcpy(name2, encoded.c_str());

	const char* hex_str = name2;

	std::string result_string;
	unsigned int ch;
	for (; std::sscanf(hex_str, "%2x", &ch) == 1; hex_str += 2)
		result_string += ch;
	cout << "HEX FORM to cipher text :: ";
	std::cout << result_string << '\n';
	cout << endl;
	cout << endl;
	/*********************************\
	\*********************************
	//result_string = "1234567812345678" + result_string;
	cout << "before decrypt fk is" << fk<<endl;
	result_string=temp;
	CryptoPP::AES::Decryption aesDecryption((byte *)fk.c_str(), CryptoPP::AES::MAX_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (byte *)iv.c_str());

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	//stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size()); 
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size());

	stfDecryptor.MessageEnd();
	std::cout << "Decrypted Text: " << std::endl;
	std::cout << decryptedtext;
	std::cout << std::endl << std::endl;

	*/

cout << "Preprocess Completed"<<endl;
	system("pause");

	return 0;
}
