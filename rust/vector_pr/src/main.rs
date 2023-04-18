mod util;

use fhe::bfv::{BfvParametersBuilder, BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey, self};
use fhe_traits::*;
use rand::{rngs::OsRng, thread_rng, rngs::ThreadRng, Rng};
use core::panic;
use std::sync::Arc;
use util::timing::{timeit, timeit_n};

//debug
// use std::env;

fn main() {
    //debug
    // env::set_var("RUST_BACKTRACE", "1");

    const POLY_DEG: usize = 2048;
    let cipher_mod: &[u64] = &[0x3fffffff000001];
    const PLAIN_MOD: u64 = 1 << 10;

    let parameters = Arc::new(
        BfvParametersBuilder::new()
            .set_degree(POLY_DEG)
            .set_moduli(cipher_mod)
            .set_plaintext_modulus(PLAIN_MOD)
            .build()
            .unwrap(),
    );
    let mut rng = thread_rng();

    let secret_key = SecretKey::random(&parameters, &mut OsRng);
    let _public_key = PublicKey::new(&secret_key, &mut rng);

    let plaintext_0 = Plaintext::try_encode(&[0_u64], Encoding::poly(), &parameters).unwrap();
    let ciphertext_0: Ciphertext = secret_key.try_encrypt(&plaintext_0, &mut rng).unwrap();
    
    const LEN: usize = 100;

    let mut data = vec![];

    timeit!("Database creation",
        for _i in 0..LEN {
            let rand_val: i64 = rng.gen_range(1..PLAIN_MOD).try_into().unwrap();
            let p = Plaintext::try_encode(&[rand_val], Encoding::poly(), &parameters).unwrap();
            data.push(p);
        }
    );

    let vec_len: usize = (LEN as f64).sqrt() as usize;
    if LEN != vec_len * vec_len {
        panic!("ERROR: Database length must be a square");
    }

    let mut col_select_vec = vec![ciphertext_0.clone(); vec_len];
    let mut row_select_vec = vec![ciphertext_0.clone(); vec_len];

    println!("Input the index to retreive: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Invalid input");

    let trimmed = input.trim();
    let i = trimmed.parse::<usize>().expect("Please input an integer...");
    client_populate(&mut col_select_vec, &mut row_select_vec, LEN, i, &secret_key, rng, parameters);

    let start_comp = std::time::Instant::now();
    let intermediate_vec = vector_dot_cp(&data, &col_select_vec);
    let retrieved_val = vector_dot_cc(&intermediate_vec, &row_select_vec);
    println!("⏱  Total computation time: {} s", start_comp.elapsed().as_secs_f64());
    let (retrieved_val_plaintext, retrieved_val_decrypted) = client_decrypt(&retrieved_val, &secret_key);

    assert_eq!(retrieved_val_plaintext, data[i]);
    println!("Retrieved: 0x{:?}", retrieved_val_decrypted);
}

fn client_populate(col_select_vec: &mut Vec<Ciphertext>, row_select_vec: &mut Vec<Ciphertext>, len: usize, index: usize, secret_key: &SecretKey, mut rng: ThreadRng, parameters: Arc<BfvParameters>) {
    let plaintext_zero = Plaintext::try_encode(&[0_u64], Encoding::poly(), &parameters).unwrap();
    let plaintext_one = Plaintext::try_encode(&[1_i64], Encoding::poly(), &parameters).unwrap();

    let vec_len = (len as f64).sqrt() as usize;
    if len != vec_len * vec_len {
        panic!("ERROR: Database length must be a square");
    }

    let row = index / vec_len;
    let col = index % vec_len;

    timeit!("Time to initialize retrieval vectors", 
        for i in 0..vec_len {
            col_select_vec[i] = secret_key.try_encrypt(&plaintext_zero, &mut rng).unwrap();
            row_select_vec[i] = secret_key.try_encrypt(&plaintext_zero, &mut rng).unwrap();

            if i == col {
                col_select_vec[i] = secret_key.try_encrypt(&plaintext_one, &mut rng).unwrap();
            }
            if i == row {
                row_select_vec[i] = secret_key.try_encrypt(&plaintext_one, &mut rng).unwrap();
            }
        }
    );
}

fn vector_dot_cp(data: &Vec<Plaintext>, client_array: &Vec<Ciphertext>) -> Vec<Ciphertext> {
    let mut ret = vec![];
    timeit!("Time to computer ciphertext-plaintext dot product",
        for _ in 0..client_array.len() {
            ret.push(bfv::dot_product_scalar(client_array.iter(), data.iter()).unwrap());
        }
    );
    ret
}

fn vector_dot_cc(data: &Vec<Ciphertext>, client_array: &Vec<Ciphertext>) -> Ciphertext {
    if data.len() < 1 || client_array.len() < 1 {
        panic!("ERROR: Vector length should be greater than or equal to 1");
    }
    let mut result = &data[0] * &client_array[0];
    let mut temp;

    timeit!("Time to computer ciphertext-ciphertext dot product",
        for (i, c) in client_array[1..].iter().enumerate() {
            temp = c * &data[i];
            result += &temp;
        }
    );
    result
}

fn client_decrypt(server_val: &Ciphertext, secret_key: &SecretKey) -> (Plaintext, u64) {
    let decrypted_plaintext = secret_key.try_decrypt(&server_val).unwrap();
    let decrypted_vector = Vec::<u64>::try_decode(&decrypted_plaintext, Encoding::poly()).unwrap();
    (decrypted_plaintext, decrypted_vector[0])
}