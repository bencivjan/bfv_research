#include "seal/seal.h"
#include <iostream>
#include <time.h>

using namespace std;
using namespace seal;

// declare function
void bfv_playground(int selection);

int main() {
    while (1) {
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Please enter a number corresponding to the polynomial   |" << endl;
        cout << "| that you wish to calculate.                             |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| Input                      | Polynomial                 |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1                          | x                          |" << endl;
        cout << "| 2                          | x^2                        |" << endl;
        cout << "| 3                          | x^2 + 1                    |" << endl;
        cout << "| 4                          | x^2 + x                    |" << endl;
        cout << "| 5                          | x^2 + 3*x                  |" << endl;
        cout << "| 6                          | x^4 with no relinearization|" << endl;
        cout << "| 7                          | x^4 with relinearization   |" << endl;
        //cout << "| 8. Performance Test        | 8_performance.cpp          |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        int selection = 0;
        cin >> selection;

        if (selection > 0) {
            bfv_playground(selection);
        }
        else {
            return 0;
        }
    }
    return -1;
}


void bfv_playground(int selection) {
    EncryptionParameters parms(scheme_type::bfv);
    clock_t start;
    clock_t t;

    // n
    // select from 1024, 2048, 4096, 8192, 16384, 32768
    size_t poly_modulus_degree = 8192;
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
    uint64_t plain_mod = 1024;
    cout << "Plaintext Modulus (t): " << plain_mod << endl;
    parms.set_plain_modulus(plain_mod);

    SEALContext context(parms);

    cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    // PublicKey public_key;
    // keygen.create_public_key(public_key);

    Encryptor encryptor(context, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    uint64_t x = 9;
    Plaintext x_plain(seal::util::uint_to_hex_string(&x, size_t(1)));
    Ciphertext x_encrypted;
    encryptor.encrypt_symmetric(x_plain, x_encrypted);

    cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
    cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits"
         << endl;

    Ciphertext x_result_encrypted;
    // We always want to minimize the multiplicative depth
    
    // Make switch statement
    // Measure time of computations
        // relinearization, multiplications
    start = clock();
    if (selection == 1) {
        // do nothing, since we are just decrypting x
        x_result_encrypted = x_encrypted;
    }
    else if (selection == 2) {
        // x^2
        evaluator.square(x_encrypted, x_result_encrypted);
    }
    else if (selection == 3) {
        // x^2 + 1
        evaluator.square(x_encrypted, x_result_encrypted);
        Plaintext one("1");
        evaluator.add_plain_inplace(x_result_encrypted, one);
        //one.data()
    }
    else if (selection == 4) {
        // x^2 + x
        evaluator.square(x_encrypted, x_result_encrypted);
        evaluator.add_inplace(x_result_encrypted, x_encrypted);
    }
    else if (selection == 5) {
        // x^2 + 3*x
        clock_t mult_start;
        clock_t time;

        Ciphertext three_x_encrypted;
        mult_start = clock();
        evaluator.square(x_encrypted, x_result_encrypted);
        time = clock() - mult_start;
        printf("Ciphertext - Ciphertext multiplication time (s): %f\n", ((float)time)/CLOCKS_PER_SEC);

        mult_start = clock();
        evaluator.multiply_plain(x_encrypted, Plaintext("3"), three_x_encrypted);
        time = clock() - mult_start;
        printf("Ciphertext - Plaintext multiplication time (s): %f\n", ((float)time)/CLOCKS_PER_SEC);

        evaluator.add_inplace(x_result_encrypted, three_x_encrypted);
    }
    // multiplication of a and b results in size a+b-1
    else if (selection == 6) {
        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);
        // x^4 with no relinearization
        evaluator.square(x_encrypted, x_result_encrypted);
        // evaluator.relinearize_inplace(x_result_encrypted, relin_keys);
        evaluator.square_inplace(x_result_encrypted);

        // evaluator.multiply(x_encrypted, x_encrypted, x_result_encrypted);
        // evaluator.multiply_inplace(x_result_encrypted, x_encrypted);
        // evaluator.multiply_inplace(x_result_encrypted, x_encrypted);
        
        // Ciphertext three_encrypted;
        // encryptor.encrypt_symmetric(Plaintext("3"), three_encrypted);
        // evaluator.multiply_inplace(x_result_encrypted, three_encrypted);
        // evaluator.relinearize_inplace(x_result_encrypted, relin_keys);
        // evaluator.multiply_inplace(x_result_encrypted, three_encrypted);
        // evaluator.relinearize_inplace(x_result_encrypted, relin_keys);
        // evaluator.square_inplace(x_result_encrypted);
    }
    else if (selection == 7) {
        // x^4 with relinearization
        clock_t relin_start;
        clock_t time;

        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        evaluator.square(x_encrypted, x_result_encrypted);
        relin_start = clock();
        evaluator.relinearize_inplace(x_result_encrypted, relin_keys);
        time = clock() - relin_start;
        printf("Relinearization time (s): %f\n", ((float)time)/CLOCKS_PER_SEC);
        evaluator.square_inplace(x_result_encrypted);
        evaluator.relinearize_inplace(x_result_encrypted, relin_keys);
    }
    t = clock() - start;
    printf("Computation time (s): %f\n", ((float)t)/CLOCKS_PER_SEC);

    Plaintext x_result_decrypted;
    cout << "    + decryption of x_result_encrypted: ";
    decryptor.decrypt(x_result_encrypted, x_result_decrypted);
    cout << "0x" << x_result_decrypted.to_string() << endl;

    cout << "    + size of encrypted x after computation: " << x_result_encrypted.size() << endl;
    cout << "    + noise budget in encrypted x after computation: " << decryptor.invariant_noise_budget(x_result_encrypted) << " bits"
         << endl;

}
