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
#include "CryptoPP\filters.h"
#include <fstream>

int main(int argc, char* argv[])
{

	string keyfile = argv[1];
	string fn1file = argv[2];
	//cout << "filename filel is" << fn1file;
	string line;
	string key, fn1;
	
	std::ifstream myfile(keyfile);
	if (myfile.is_open())
	{
		while (getline(myfile, line))
		{
			key = key + line;
		}
		myfile.close();
	}
	//cout << "in authorize key resd is" << key;
	
	string line2;
	std::ifstream myfile2(fn1file);
	if (myfile2.is_open())
	{
		while (getline(myfile2, line2))
		{
			fn1 = fn1 + line2;
		}
		myfile2.close();
	}
	//cout << "in authorize fn1 resd is" << fn1;
	//////////////////////////////////
	///////////////////////
	/////file name converstion/////


	CryptoPP::SHA1 sha1;
	std::string source = fn1;  //This will be randomly generated somehow
	std::string hash = "";
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

//	cout << "new filename is" << endl << endl << hash << endl;

	
//	cout << "before authrize fname is" << fn1 << "key is" << key << endl;
	string mac, encoded;
	try
	{
		HMAC< SHA256 > hmac((byte*)key.c_str(), key.length());

		StringSource(fn1, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}

	encoded.clear();
	StringSource(mac, true,
		new Base64Encoder(
		new StringSink(encoded)
		) // Base64Encoder
		); // StringSource

	encoded.clear();
	StringSource ss3(mac, true,
		new HexEncoder(
		new StringSink(encoded)
		) // HexEncoder
		); // StringSource

	string fk = encoded.substr(0, 31);
	//cout << "Key fk is stored in fkey.txt" << endl;
	//cout << "New file name is stored in sfilename.txt" << endl;


	std::ofstream myfile3("fkey.txt");
	if (myfile3.is_open())
	{
		
		myfile3 << fk << endl;
		myfile3.close();
	}


	std::ofstream myfile4("sfilename.txt");
	if (myfile4.is_open())
	{

		myfile4 << hash << endl;
		myfile4.close();
	}
	cout << "fk is stored in fkey.txt and new name is stored in sfilename.txt"<<endl;
	system("pause");
	return 1;
}