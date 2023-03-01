#include "seal/seal.h"
#include <iostream>
#include <time.h>
#include <cmath>

using namespace std;
using namespace seal;

Ciphertext vector_dot_cp(vector<Ciphertext>& col_select_vec, vector<Plaintext>& row_select_vec, size_t len, Evaluator* evaluator, Decryptor* d);
Ciphertext vector_dot_cc(vector<Ciphertext>& col_select_vec, vector<Ciphertext>& row_select_vec, size_t len, Evaluator* evaluator, Decryptor* d);
void populate_retrieval_vectors(vector<Ciphertext>& col_select_vec, vector<Ciphertext>& row_select_vec, int vec_len, int index, Encryptor* encryptor);
void print_plainvec(const vector<Plaintext>& vec);

/*
How this works:
Based on the desired retrieval index, we generate 2 vectors
Vector 1 is dotted with each row of the database to generate an intermediate vector
The intermediate vector is dotted with Vector 2 to generate the retrieved element

E.g.
Database = [[1, 2]
            [3, 4]]

Desired number: 3

col_select_vec = [1, 0]

TempVec = [Database[0] * col_select_vec, Database[1] * col_select_vec]
                 = [1, 3]
row_select_vec = [0, 1]

Result = TempVec * row_select_vec = 3

*/

int main() {
    cout << "VectorPR" << endl;

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
    uint64_t plain_mod = (uint64_t) pow(2, 59);//524288;//131072;//8192;//1024;   // max -> (uint64_t) pow(2, 59)
    cout << "Plaintext Modulus (t): " << plain_mod << endl;
    parms.set_plain_modulus(plain_mod);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, secret_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // database must be a square matrix
    // Sizes: 64
    size_t db_len = 1600; // 1,000,000, 490k, 90000, 40000, 10000, 64
    size_t vec_len = (size_t) sqrt((float) db_len);
    if (db_len != vec_len * vec_len) {
        cout << "Error: Database length must be a square" << endl;
        return -1;
    }

    // initialize arrays
    // use vectors instead of arrays
    vector<vector<Plaintext>> data(vec_len);

    // name variables more intuitively
    vector<Ciphertext> col_select_vec(vec_len);
    vector<Ciphertext> row_select_vec(vec_len);

    cout << "Initializing server data array..." << endl;

    // Initialize random seed
    srand(time(0));

    // ======= initialize 2d database vector ===========
    for (int i = 0; i < vec_len; i++) {
        vector<Plaintext> temp(vec_len);
        for (int j = 0; j < vec_len; j++) {
            // Value should be between 1 and plain_mod
            uint64_t val = rand() % (plain_mod-1) + 1;
            // encrypt i
            Plaintext i_plain(seal::util::uint_to_hex_string(&val, size_t(1)));
            temp[j] = i_plain;
        }
        data[i] = temp;
    }

    // pretty print 2d vector
    // cout << "Database:" << endl;
    // for (auto& e : data) {
    //     print_plainvec(e);
    // }

    cout << "Size of database: " << db_len << endl;

    size_t index;
    cout << "Input the index to retreive: " << endl;
    cin >> index;

    if (index >= db_len) {
        cout << "ERROR: Index cannot be greater than datase length" << endl;
        return 1;
    }

    cout << "Populating client retrieval vectors..." << endl;

    populate_retrieval_vectors(col_select_vec, row_select_vec, vec_len, index, &encryptor);

    cout << "Computing dot product of columns..." << endl;

    // print col_select_vec for debugging
    // vector<Plaintext> vec1_debug(vec_len);
    // for (int i = 0; i < vec_len; i++) {
    //     decryptor.decrypt(col_select_vec[i], vec1_debug[i]);
    // }
    // print_plainvec(vec1_debug);

    // multiply vector1 with database
    vector<Ciphertext> intermediate_vec(vec_len);
    clock_t cp_start = clock();
    for (int i = 0; i < vec_len; i++) {
        intermediate_vec[i] = vector_dot_cp(col_select_vec, data[i], vec_len, &evaluator, &decryptor);
    }
    clock_t t1 = clock() - cp_start;
    float cp_comptime = ((float)t1)/CLOCKS_PER_SEC;
    printf("Time to compute ciphertext-plaintext dot product (s): %f\n", cp_comptime);

    // print intermediate_vec for debugging
    // vector<Plaintext> intermediate_vec_debug(vec_len);
    // for (int i = 0; i < vec_len; i++) {
    //     decryptor.decrypt(intermediate_vec[i], intermediate_vec_debug[i]);
    // }
    // print_plainvec(intermediate_vec_debug);

    // print row_select_vec for debugging
    // vector<Plaintext> vec2_debug(vec_len);
    // for (int i = 0; i < vec_len; i++) {
    //     decryptor.decrypt(row_select_vec[i], vec2_debug[i]);
    // }
    // print_plainvec(vec2_debug);

    cout << "Computing dot product of rows..." << endl;
    // multiply vector2 with above result
    clock_t cc_start = clock();
    Ciphertext retrieved = vector_dot_cc(row_select_vec, intermediate_vec, vec_len, &evaluator, &decryptor);
    clock_t t2 = clock() - cc_start;
    float cc_comptime = ((float)t2)/CLOCKS_PER_SEC;
    printf("Time to compute ciphertext-ciphertext dot product (s): %f\n", cc_comptime);

    float total = cp_comptime + cc_comptime;
    printf("Total retrieval time (s): %f\n", total);

    // Relinearize result
    // cout << "Relinearizing result ciphertext..." << endl;
    // RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);
    // evaluator.relinearize_inplace(retrieved, relin_keys);

    // decrypt result
    Plaintext result_decrypted;
    decryptor.decrypt(retrieved, result_decrypted);

    // Verify correct decryption result
    if (result_decrypted != data[index / vec_len][index % vec_len]) {
        cout << "ERROR: Retrieved incorrect value" << endl;
        cout << "Expected 0x" << data[index / vec_len][index % vec_len].to_string() << endl;
        cout << "Retrieved 0x" << result_decrypted.to_string() << endl;
        return -1;
    }

    cout << "      decryption of result_encrypted: 0x" << result_decrypted.to_string() << endl;;
    cout << "    + size of encrypted x after computation: " << retrieved.size() << endl;
    cout << "    + noise budget in encrypted x after computation: " << decryptor.invariant_noise_budget(retrieved) << " bits"
         << endl;

    return 0;
}

Ciphertext vector_dot_cp(vector<Ciphertext>& col_select_vec, vector<Plaintext>& row_select_vec, size_t len, Evaluator* evaluator, Decryptor* d) {
    Ciphertext result;
    if (len < 1) {
        cout << "ERROR: Vector length should be greater than or equal to 1" << endl;
        return result;
    }

    evaluator->multiply_plain(col_select_vec[0], row_select_vec[0], result);
    for (size_t j = 1; j < len; j++) {
        Ciphertext temp;
        evaluator->multiply_plain(col_select_vec[j], row_select_vec[j], temp);
        // cout << "intermediate budget: " << d->invariant_noise_budget(temp) << endl;
        evaluator->add_inplace(result, temp);
        // cout << "Out_data budget: " << d->invariant_noise_budget(result) << endl;
    }
    return result;
}

Ciphertext vector_dot_cc(vector<Ciphertext>& col_select_vec, vector<Ciphertext>& row_select_vec, size_t len, Evaluator* evaluator, Decryptor* d) {
    Ciphertext result;
    if (len < 1) {
        cout << "ERROR: Vector length should be greater than or equal to 1" << endl;
        return result;
    }
    
    evaluator->multiply(col_select_vec[0], row_select_vec[0], result);
    for (size_t j = 1; j < len; j++) {
        Ciphertext temp;
        // cout << "before (col, vec): " << d->invariant_noise_budget(col_select_vec[j]) << ", " << d->invariant_noise_budget(row_select_vec[j]) << endl;
        evaluator->multiply(col_select_vec[j], row_select_vec[j], temp);
        // cout << "c-c intermediate budget: " << d->invariant_noise_budget(temp) << endl;
        evaluator->add_inplace(result, temp);
        // cout << "c-c Out_data budget: " << d->invariant_noise_budget(result) << endl;
    }
    return result;
}

void print_plainvec(const vector<Plaintext>& vec) {
    cout << "[ ";
    for (auto& d : vec) {
        cout << d.to_string() << " ";
    }
    cout << "]" << endl;
}

void populate_retrieval_vectors(vector<Ciphertext>& col_select_vec, vector<Ciphertext>& row_select_vec, int vec_len, int index, Encryptor* encryptor) {
    Ciphertext encrypted_zero;
    Ciphertext encrypted_one;
    encryptor->encrypt_symmetric(Plaintext("0"), encrypted_zero);
    encryptor->encrypt_symmetric(Plaintext("1"), encrypted_one);

    // vector 1 is dotted with columns of database
    // vector 2 is dotted with (col_select_vec * DB)
    size_t row = index / vec_len;
    size_t col = index % vec_len;

    cout << "Populating vectors..." << endl;
    for (int i = 0; i < vec_len; i++) {
        if (i == col) {
            col_select_vec[i] = encrypted_one;
        } else {
            col_select_vec[i] = encrypted_zero;
        }

        if (i == row) {
            row_select_vec[i] = encrypted_one;
        } else {
            row_select_vec[i] = encrypted_zero;
        }
    }
}