#include <iostream>
#include <fstream>
#include <botan/auto_rng.h>
#include <botan/pipe.h>
#include <botan/pbkdf.h>
#include <botan/cipher_mode.h>
#include <botan/filters.h>

void Encrypt(Botan::OctetString key, Botan::InitializationVector iv, std::string inFileName, std::string outFileName)
{
   std::ifstream in(inFileName.c_str(), std::ios::binary);
   std::ofstream out(outFileName.c_str(), std::ios::binary);

   Botan::Pipe pipe(Botan::get_cipher("AES-128/CBC", key, iv, Botan::Cipher_Dir::Encryption), new Botan::DataSink_Stream(out));
   pipe.start_msg();
   in >> pipe;
   pipe.end_msg();

   out.flush();
   out.close();
   in.close();

   std::cout << "Encrypted!" << std::endl;
}


void Decrypt(Botan::OctetString key, Botan::InitializationVector iv, std::string inFileName, std::string outFileName)
{
   std::ifstream in(inFileName.c_str(), std::ios::binary);
   std::ofstream out(outFileName.c_str(), std::ios::binary);

   Botan::Pipe pipe(Botan::get_cipher("AES-128/CBC", key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));
   pipe.start_msg();
   in >> pipe;
   pipe.end_msg();

   out.flush();
   out.close();
   in.close();

   std::cout << "Decrypted!" << std::endl;
}


int main()
{
   std::cout << "Start Botan programm:" << std::endl;
   std::string filePlainText = "C:\\VS_projects\\EncryptFileBotan\\soursetext.txt";
   std::string fileEncrypted = "C:\\VS_projects\\EncryptFileBotan\\encrypted.txt";
   std::string fileDecrypted = "C:\\VS_projects\\EncryptFileBotan\\decrypted.txt";

   std::string_view password = "Botan2023";
   Botan::AutoSeeded_RNG rng;

   //Setup the key derive functions
   const Botan::u32bit PBKDF2_ITERATIONS = 8192;
   size_t size = 16;
   std::unique_ptr<Botan::PBKDF> pbkdf = Botan::PBKDF::create_or_throw("PBKDF2(SHA-256)");
 
  
   Botan::SecureVector<std::uint8_t> salt = rng.random_vec(16);
   Botan::OctetString aes256_key = pbkdf->derive_key(size, password, &salt[0], salt.size(), PBKDF2_ITERATIONS);
   Botan::InitializationVector iv(rng, 16);

   std::cout << "Encryption key: " << aes256_key.to_string() << std::endl;

   Encrypt(aes256_key, iv, filePlainText, fileEncrypted);
   Decrypt(aes256_key, iv, fileEncrypted, fileDecrypted);


}

