use crate::util::shred::get_slot_entries_and_parent_slot_from_raw_shreds;

#[test]
fn try_deshred() {
    use std::{collections::HashMap, fs};

    use solana_ledger::shred::Shred;

    let _ = simple_logger::init_with_level(log::Level::Info);
    let f = fs::read("./decoded_shreds.json").unwrap();
    let raw_shreds: Vec<String> = serde_json::from_slice(&f).unwrap();
    let shreds = raw_shreds.into_iter().map(|s| {
        use base64::{Engine, prelude::BASE64_STANDARD};

        let d = BASE64_STANDARD.decode(s).unwrap();
        Shred::new_from_serialized_shred(d).unwrap()
    });

    let mut by_batch = HashMap::<u32, Vec<Shred>>::new();
    for shred in shreds {
        by_batch
            .entry(shred.fec_set_index())
            .or_default()
            .push(shred);
    }

    for (batch, shred) in by_batch {
        use crate::util::shred::deshred_to_entries;

        match deshred_to_entries(shred.iter()) {
            Ok(entries) => println!("batch entries {entries:?}"),
            Err(e) => println!("batch {batch} failed {e}"),
        }
    }
}

#[test]
fn try_decode_and_deshred() {
    use std::fs;

    let _ = simple_logger::init_with_level(log::Level::Info);
    let f = fs::read("./stored_shreds.json").unwrap();
    let raw_shreds: Vec<String> = serde_json::from_slice(&f).unwrap();
    let shreds = raw_shreds.into_iter().map(|s| {
        use base64::{Engine, prelude::BASE64_STANDARD};

        BASE64_STANDARD.decode(s).unwrap()
    });

    let (entries, _) = get_slot_entries_and_parent_slot_from_raw_shreds(shreds).unwrap();

    println!(
        "total transaction count: {}",
        entries.iter().fold(0, |acc, e| acc + e.transactions.len())
    );
}
