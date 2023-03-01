mod util;

use fhe::bfv::{BfvParametersBuilder, BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey, self};
use fhe_traits::*;
use rand::{rngs::OsRng, thread_rng, rngs::ThreadRng, Rng};
use std::sync::Arc;
use util::timing::{timeit, timeit_n};

fn main() {
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
            // print!("0x{:x}, ", rand_val);
            let p = Plaintext::try_encode(&[rand_val], Encoding::poly(), &parameters).unwrap();
            data.push(p);
        }
        // println!("");
    );

    let mut client_vec = vec![ciphertext_0.clone(); LEN];

    println!("Input the index to retreive: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("Invalid input");

    let trimmed = input.trim();
    let i = trimmed.parse::<usize>().expect("Please input an integer...");
    client_populate(&mut client_vec, LEN, i, &secret_key, rng, parameters);

    let retrieved_val = server_compute(&data, &client_vec);
    let (retrieved_val_plaintext, retrieved_val_decrypted) = client_decrypt(&retrieved_val, &secret_key);

    assert_eq!(retrieved_val_plaintext, data[i]);
    println!("Retrieved: 0x{:x}", retrieved_val_decrypted);
}

fn client_populate(client_array: &mut Vec<Ciphertext>, len: usize, index: usize, secret_key: &SecretKey, mut rng: ThreadRng, parameters: Arc<BfvParameters>) {
    let plaintext_zero = Plaintext::try_encode(&[0_u64], Encoding::poly(), &parameters).unwrap();
    let plaintext_one = Plaintext::try_encode(&[1_i64], Encoding::poly(), &parameters).unwrap();

    for i in 0..len {
        client_array[i] = secret_key.try_encrypt(&plaintext_zero, &mut rng).unwrap();
        if i == index {
            client_array[i] = secret_key.try_encrypt(&plaintext_one, &mut rng).unwrap();
        }
    }
}

fn server_compute(data: &Vec<Plaintext>, client_array: &Vec<Ciphertext>) -> Ciphertext {
    bfv::dot_product_scalar(client_array.iter(), data.iter()).unwrap()
}

fn client_decrypt(server_val: &Ciphertext, secret_key: &SecretKey) -> (Plaintext, u64) {
    let decrypted_plaintext = secret_key.try_decrypt(&server_val).unwrap();
    let decrypted_vector = Vec::<u64>::try_decode(&decrypted_plaintext, Encoding::poly()).unwrap();
    (decrypted_plaintext, decrypted_vector[0])
}