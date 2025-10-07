use solana_entry::entry::Entry as SolEntry;
use solana_sdk::{
    instruction::CompiledInstruction as SolCompiledInstruction,
    message::{
        MessageHeader as SolMessageHeader, VersionedMessage,
        v0::MessageAddressTableLookup as SolMessageAddressTableLookup,
    },
    transaction::VersionedTransaction as SolVersionedTransaction,
};

tonic::include_proto!("slot_entry");

impl From<SolMessageAddressTableLookup> for MessageAddressTableLookup {
    fn from(value: SolMessageAddressTableLookup) -> Self {
        Self {
            account_key: value.account_key.as_array().to_vec(),
            writable_indexes: value.writable_indexes,
            readonly_indexes: value.readonly_indexes,
        }
    }
}

impl From<SolCompiledInstruction> for CompiledInstruction {
    fn from(value: SolCompiledInstruction) -> Self {
        Self {
            program_id_index: value.program_id_index as u32,
            accounts: value.accounts,
            data: value.data,
        }
    }
}

impl From<SolMessageHeader> for MessageHeader {
    fn from(value: SolMessageHeader) -> Self {
        Self {
            num_required_signatures: value.num_required_signatures as u32,
            num_readonly_signed_accounts: value.num_readonly_signed_accounts as u32,
            num_readonly_unsigned_accounts: value.num_readonly_unsigned_accounts as u32,
        }
    }
}

impl From<VersionedMessage> for versioned_transaction::Message {
    fn from(value: VersionedMessage) -> Self {
        match value {
            VersionedMessage::Legacy(msg) => Self::MessageLegacy(VersionedMessageLegacy {
                header: Some(msg.header.into()),
                account_keys: msg
                    .account_keys
                    .into_iter()
                    .map(|k| k.as_array().to_vec())
                    .collect(),
                recent_blockhash: msg.recent_blockhash.to_bytes().to_vec(),
                instructions: msg
                    .instructions
                    .into_iter()
                    .map(|instr| instr.into())
                    .collect(),
            }),
            VersionedMessage::V0(msg) => Self::MessageV0(VersionedMessageV0 {
                header: Some(msg.header.into()),
                account_keys: msg
                    .account_keys
                    .into_iter()
                    .map(|k| k.as_array().to_vec())
                    .collect(),
                recent_blockhash: msg.recent_blockhash.to_bytes().to_vec(),
                instructions: msg
                    .instructions
                    .into_iter()
                    .map(|instr| instr.into())
                    .collect(),
                address_table_lookups: msg
                    .address_table_lookups
                    .into_iter()
                    .map(|tbl| tbl.into())
                    .collect(),
            }),
        }
    }
}

impl From<SolVersionedTransaction> for VersionedTransaction {
    fn from(value: SolVersionedTransaction) -> Self {
        Self {
            signatures: value
                .signatures
                .into_iter()
                .map(|s| s.as_array().to_vec())
                .collect(),
            message: Some(value.message.into()),
        }
    }
}

impl From<SolEntry> for Entry {
    fn from(value: SolEntry) -> Self {
        Self {
            num_hashes: value.num_hashes,
            hash: value.hash.to_bytes().to_vec(),
            transactions: value.transactions.into_iter().map(|t| t.into()).collect(),
        }
    }
}
