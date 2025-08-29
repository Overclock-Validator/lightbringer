use crate::rpc::{deshred_to_entries, process_shreds_with_recovery};

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

#[test]
fn try_decode_and_deshred() {
    use std::{collections::HashMap, fs};

    use solana_ledger::shred::Shred;

    simple_logger::init_with_level(log::Level::Info).unwrap();
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
    let slot = by_batch.values().next().unwrap()[0].slot();

    for (batch_index, shred_list) in by_batch {
        let coding = shred_list.iter().find_map(|s| match s {
            Shred::ShredCode(c) => Some(c.coding_header()),
            Shred::ShredData(_) => None,
        });
        log::info!(
            "decoding {batch_index}, slot: {slot}, shreds_cnt {}, header: {coding:?}",
            shred_list.len()
        );
        let (new_data_shreds, _coding_shreds) = match process_shreds_with_recovery(shred_list) {
            Ok(v) => v,
            Err(e) => {
                println!("recovery failed: batch {batch_index}, {e}");
                continue;
            }
        };

        match deshred_to_entries(&new_data_shreds) {
            Ok(entries) => println!("batch entries {entries:?}"),
            Err(e) => println!("batch {batch_index} failed {e}"),
        }
    }
}
