use nodnonce::keypair::Keypair;
use solana_sdk::{hash::Hash, instruction::Instruction, signer::Signer, transaction::Transaction};
use spl_memo;

fn main() {
    let payer = Keypair::new();

    let recent_blockhash = Hash::default();

    let mut transaction = Transaction::new_signed_with_payer(
        &[Instruction {
            program_id: spl_memo::ID,
            accounts: vec![],
            data: vec![1, 2, 3, 4],
        }],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    println!("signature: {:?}", transaction.signatures[0]);

    let message_data = transaction.message_data();

    // Produces some other possible signatures
    for i in 1..=255u8 {
        let new_signature = payer.sign_message_with_index(&message_data, i);
        println!("new_signature {i:}: {new_signature:?}");

        // Internally verifies the signature
        transaction
            .replace_signatures(&[(payer.pubkey(), new_signature)])
            .unwrap();
    }
}
