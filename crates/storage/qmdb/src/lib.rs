//! Core QMDB abstractions and traits for Kora.

#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/refcell/kora/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod batch;
pub use batch::StoreBatches;

mod changes;
pub use changes::{AccountUpdate, ChangeSet};

mod encoding;
pub use encoding::{AccountEncoding, StorageKey};

mod error;
pub use error::QmdbError;

mod root;
pub use root::StateRoot;

mod store;
pub use store::{
    COMMIT_SEQ_ACCOUNT_KEY, COMMIT_SEQ_CODE_KEY, COMMIT_SEQ_STORAGE_KEY, PartitionCommitSeqs,
    QmdbStore, Stores, encode_commit_seq_account, encode_commit_seq_code,
};

mod traits;
pub use traits::{QmdbBatchable, QmdbGettable};
