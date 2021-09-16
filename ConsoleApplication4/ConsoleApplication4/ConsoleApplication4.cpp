#include <iostream>
#include <string>

#include "cryptlib.h"
#include "filters.h"
#include "eccrypto.h"
#include "osrng.h"
#include "files.h"
#include "sha.h"
#include "hex.h"

#include "pem.h"

int main()
{
	using namespace CryptoPP;

	std::string pt =
		"40BA49FCBA45C7EEB2261B1BE0EBC7C14D6484B9EF8A23B060EBE67F97252BBC"
		"987BA49DF364A0C9926F2B6DE1BAF46068A13A2C5C9812B2F3451F48B75719EE";

	HexDecoder decoder;
	decoder.Put((byte*)&pt[0], pt.size());
	decoder.MessageEnd();

	ECP::Point q;
	size_t len = decoder.MaxRetrievable();

	q.identity = false;
	q.x.Decode(decoder, len / 2);
	q.y.Decode(decoder, len / 2);

	ECDSA<ECP, SHA256>::PublicKey pkey;
	pkey.Initialize(ASN1::brainpoolP256r1(), q);

	FileSink fs("pubkey.pem");
	PEM_Save(fs, pkey);

    std::cout << "Hello World!\n";
}
