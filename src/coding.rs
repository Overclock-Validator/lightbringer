use std::collections::BTreeMap;

use crate::util::shred::{deshred_to_entries, recover_shreds_and_group_by_completion};

#[test]
fn try_deshred() {
    use std::{collections::HashMap, fs};

    use solana_ledger::shred::Shred;

    simple_logger::init_with_level(log::Level::Info).unwrap();
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

    use solana_ledger::shred::Shred;

    simple_logger::init_with_level(log::Level::Info).unwrap();
    let f = fs::read("./stored_shreds.json").unwrap();
    let raw_shreds: Vec<String> = serde_json::from_slice(&f).unwrap();
    let shreds = raw_shreds.into_iter().map(|s| {
        use base64::{Engine, prelude::BASE64_STANDARD};

        let d = BASE64_STANDARD.decode(s).unwrap();
        Shred::new_from_serialized_shred(d).unwrap()
    });

    let mut by_batch = BTreeMap::<u32, Vec<Shred>>::new();
    for shred in shreds {
        by_batch
            .entry(shred.fec_set_index())
            .or_default()
            .push(shred);
    }

    let mut entries = Vec::new();
    for data_shreds in recover_shreds_and_group_by_completion(by_batch).unwrap() {
        let mut deshred_entries = deshred_to_entries(data_shreds.values()).unwrap();
        entries.append(&mut deshred_entries);
    }

    println!(
        "total transaction count: {}",
        entries.iter().fold(0, |acc, e| acc + e.transactions.len())
    );
}
