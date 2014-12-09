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

string sign(string key, string plain,string fn1)
{

	//////////////////////////////////
	///////////////////////
	/////file name converstion/////


	CryptoPP::SHA1 sha1;
	std::string source = fn1;  //This will be randomly generated somehow
	std::string hash = "";
	CryptoPP::StringSource(source, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

	cout << "new filename is" << endl << endl << hash << endl;



	string mac, encoded;
	try
	{
		HMAC< SHA256 > hmac((byte*)key.c_str(), key.length());

		StringSource(plain, true,
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

	cout << "hmac: " << encoded << endl;
	return encoded;
}