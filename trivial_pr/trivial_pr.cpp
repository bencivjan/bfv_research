#include "seal/seal.h"
#include <iostream>
#include <time.h>
#include <cstdlib>

using namespace std;
using namespace seal;

// declare functions
int client_populate(vector<Ciphertext>& client_array, size_t len, size_t index, Encryptor* encryptor);
Ciphertext server_compute(vector<Plaintext>& data, vector<Ciphertext>& client_array, size_t len, Evaluator* evaluator, Decryptor* d);
Ciphertext server_compute_relinearized(vector<Plaintext>& data, vector<Ciphertext>& client_array, size_t len, Evaluator* evaluator, RelinKeys relin_keys);
Plaintext client_decrypt(Ciphertext server_val, Decryptor* decryptor);

// Server data should be plaintext
// Reduce n & q (not t) so noise budget is as small as possible after computing (1 bit of budget left)
// Increase data elements (10,000, 20k -> 100,000) and see how it affects budget and timing

// keep track of:
// data size, n, q, budget, time

int main() {
    // instantiate timing variables
    clock_t start;
    clock_t t;

    // initialize encryption parameters
    EncryptionParameters parms(scheme_type::bfv);

    // n
    // select from 1024, 2048, 4096, 8192, 16384, 32768
    size_t poly_modulus_degree = 32768;
    cout << "Polynomial Modulus (n): " << poly_modulus_degree << endl;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // q
    cout << "Coefficient Modulus (q): [ ";
    for (Modulus m : CoeffModulus::BFVDefault(poly_modulus_degree)) {
        cout << m.value() << " (" << m.bit_count() << " bits)" << ", ";
    }
    cout << "]" << endl;
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // t
    uint64_t plain_mod = (uint64_t) pow(2, 59);//131072;//32768;//8192;//1024;
    cout << "Plaintext Modulus (t): " << plain_mod << endl;
    parms.set_plain_modulus(plain_mod);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    size_t len = 1600;//32000;
    // initialize arrays
    // use vectors instead of arrays
    vector<Plaintext> data(len);
    vector<Ciphertext> request(len);

    cout << "Initializing server data array..." << endl;

    // Initialize random seed
    srand(time(0));

    start = clock();
    for (uint64_t i = 0; i < len; i++) {
        // Value should be between 1 and plain_mod
        uint64_t val = rand() % (plain_mod-1) + 1;
        Plaintext i_plain(seal::util::uint_to_hex_string(&val, size_t(1)));
        data[i] = i_plain;
    }
    t = clock() - start;
    cout << "Size of data array: " << len << endl;
    printf("Time to initialize server data array (s): %f\n", ((float)t)/CLOCKS_PER_SEC);

    size_t index;
    cout << "Input the index to retreive: " << endl;
    cin >> index;

    cout << "Populating client retrieval array..." << endl;

    start = clock();
    client_populate(request, len, index, &encryptor);
    t = clock() - start;
    printf("Time to initialize client retrieval array (s): %f\n", ((float)t)/CLOCKS_PER_SEC);

    cout << "Computing dot product..." << endl;

    start = clock();
    Ciphertext server_val = server_compute(data, request, len, &evaluator, &decryptor);
    t = clock() - start;
    printf("Time to compute array dot product (s): %f\n", ((float)t)/CLOCKS_PER_SEC);

    cout << "Decrypting dot product..." << endl;

    start = clock();
    Plaintext result = client_decrypt(server_val, &decryptor);
    t = clock() - start;
    printf("Time to decrypt dot product (s): %f\n", ((float)t)/CLOCKS_PER_SEC);

    // Verify correct decryption result
    if (result != data[index]) {
        cout << "ERROR: Retrieved incorrect value" << endl;
        cout << "Expected 0x" << data[index].to_string() << endl;
        cout << "Retrieved 0x" << result.to_string() << endl;
        return -1;
    }

    cout << "0x" << result.to_string() << endl;


    // cout << "Computing relinearized dot product..." << endl;

    // RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);

    // start = clock();
    // Ciphertext server_val_relinearized = server_compute_relinearized(data, request, len, &evaluator, relin_keys);
    // t = clock() - start;
    // printf("Time to compute relinearized dot product (s): %f\n", ((float)t)/CLOCKS_PER_SEC);

    // cout << "Decrypting relinearized dot product..." << endl;

    // Plaintext result_relinearized = client_decrypt(server_val_relinearized, &decryptor);

    // cout << "0x" << result_relinearized.to_string() << endl;
}

// populates client array
int client_populate(vector<Ciphertext>& client_array, size_t len, size_t index, Encryptor* encryptor) {
    Ciphertext encrypted_zero;
    Ciphertext encrypted_one;

    encryptor->encrypt_symmetric(Plaintext("0"), encrypted_zero);
    encryptor->encrypt_symmetric(Plaintext("1"), encrypted_one);

    for (size_t i = 0; i < len; i++) {
        client_array[i] = encrypted_zero;
        if (i == index) {
            client_array[i] = encrypted_one;
        }
    }
    return 0;
}

Ciphertext server_compute(vector<Plaintext>& data, vector<Ciphertext>& client_array, size_t len, Evaluator* evaluator, Decryptor* d) {
    Ciphertext out_data;
    Ciphertext intermediate;
    evaluator->multiply_plain(client_array[0], data[0], out_data);
    // cout << "Out_data budget: " << d->invariant_noise_budget(out_data) << endl;
    for (uint64_t i = 1; i < len; i++) {
        // ciphertext multiply
        // cout << data[i].to_string() << endl;
        evaluator->multiply_plain(client_array[i], data[i], intermediate);
        // cout << "intermediate budget: " << d->invariant_noise_budget(intermediate) << endl;
        // ciphertext add
        evaluator->add_inplace(out_data, intermediate);
        // cout << "Out_data budget: " << d->invariant_noise_budget(out_data) << endl;
    }
    return out_data;
}

Ciphertext server_compute_relinearized(vector<Plaintext>& data, vector<Ciphertext>& client_array, size_t len, Evaluator* evaluator, RelinKeys relin_keys) {
    Ciphertext out_data;
    Ciphertext intermediate;
    evaluator->multiply_plain(client_array[0], data[0], out_data);
    for (uint64_t i = 1; i < len; i++) {
        // ciphertext multiply
        evaluator->multiply_plain(client_array[i], data[i], intermediate);
        // ciphertext add
        evaluator->add_inplace(out_data, intermediate);
    }
    cout << out_data.size() << endl;
    evaluator->relinearize_inplace(out_data, relin_keys);
    return out_data;
}

Plaintext client_decrypt(Ciphertext server_val, Decryptor* decryptor) {
    Plaintext result_decrypted;
    cout << "    + decryption of result_encrypted: ";
    decryptor->decrypt(server_val, result_decrypted);

    cout << "    + size of encrypted x after computation: " << server_val.size() << endl;
    cout << "    + noise budget in encrypted x after computation: " << decryptor->invariant_noise_budget(server_val) << " bits"
         << endl;
    return result_decrypted;
}
