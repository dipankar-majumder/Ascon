#include <iostream>
#include <string>
#include <vector>
#include "Ascon128.hpp"

// Helper function to convert a string to a vector of bytes
std::vector<uint8_t> stringToBytes(const std::string &str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}

// Helper function to convert a vector of bytes to a string
std::string bytesToString(const std::vector<uint8_t> &bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

int main()
{
    Ascon128 ascon;

    // Example key, nonce, and data
    std::vector<uint8_t> key(ASCON_KEY_SIZE, 0x01);
    std::vector<uint8_t> nonce(ASCON_NONCE_SIZE, 0x02);
    std::vector<uint8_t> associated_data = stringToBytes("Associated Data");
    std::vector<uint8_t> plaintext = stringToBytes("This is a secret message.");

    std::cout << "Original message: " << std::endl << bytesToString(plaintext) << std::endl;

    // Encrypt the data
    try
    {
        std::vector<uint8_t> ciphertext = ascon.encrypt(key, nonce, associated_data, plaintext);
        std::cout << "Encryption successful. Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;

        // Decrypt the data
        std::vector<uint8_t> decrypted_message = ascon.decrypt(key, nonce, associated_data, ciphertext);

        if (decrypted_message.empty())
        {
            std::cout << "Decryption failed! Tag mismatch or invalid ciphertext." << std::endl;
        }
        else
        {
            std::cout << "Decryption successful." << std::endl;
            std::cout << "Decrypted message: " << std::endl << bytesToString(decrypted_message) << std::endl;

            if (decrypted_message == plaintext)
            {
                std::cout << "Test passed: Decrypted message matches original." << std::endl;
            }
            else
            {
                std::cout << "Test failed: Decrypted message does not match original." << std::endl;
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}