#[test]
fn try_deshred() {
    use std::{collections::HashMap, fs};

    use solana_ledger::shred::Shred;

    let f = fs::read("./decoded_shreds.json").unwrap();
    let raw_shreds: Vec<String> = serde_json::from_slice(&f).unwrap();
    let shreds = raw_shreds.into_iter().map(|s| {
        use base64::{Engine, prelude::BASE64_STANDARD};

        let d = BASE64_STANDARD.decode(s).unwrap();
        let s = Shred::new_from_serialized_shred(d).unwrap();
        s
    });

    let mut by_batch = HashMap::<u32, Vec<Shred>>::new();
    for shred in shreds {
        by_batch
            .entry(shred.fec_set_index())
            .or_default()
            .push(shred);
    }

    for (batch, shred) in by_batch {
        use crate::rpc::deshred_to_entries;

        match deshred_to_entries(&shred) {
            Ok(entries) => println!("batch entries {entries:?}"),
            Err(e) => println!("batch {batch} failed {e}"),
        }
    }
}
