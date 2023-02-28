
use crate::{
	AccountId, AccountSignature, AuthorityId, Block, BlockNumber, Digest, Header, Runtime, Transfer,
	H256 as Hash,
};
use codec::{Decode, Encode, KeyedVec};
use frame_support::storage;
use sp_core::storage::well_known_keys;
use sp_io::{hashing::blake2_256, storage::root as storage_root, trie};
use sp_runtime::{
	generic,
	traits::Header as _,
	transaction_validity::{
		InvalidTransaction, TransactionValidity, TransactionValidityError, ValidTransaction,
	},
	ApplyExtrinsicResult,
};
use sp_std::prelude::*;

const NONCE_OF: &[u8] = b"nonce:";
const BALANCE_OF: &[u8] = b"balance:";

pub use self::pallet::*;

#[frame_support::pallet]
mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config {}

	#[pallet::storage]
	pub type ExtrinsicData<T> = StorageMap<_, Blake2_128Concat, u32, Vec<u8>, ValueQuery>;

	// The current block number being processed. Set by `execute_block`.
	#[pallet::storage]
	pub type Number<T> = StorageValue<_, BlockNumber, OptionQuery>;

	#[pallet::storage]
	pub type ParentHash<T> = StorageValue<_, Hash, ValueQuery>;

	#[pallet::storage]
	pub type NewAuthorities<T> = StorageValue<_, Vec<AuthorityId>, OptionQuery>;

	#[pallet::storage]
	pub type StorageDigest<T> = StorageValue<_, Digest, OptionQuery>;

	#[pallet::storage]
	pub type Authorities<T> = StorageValue<_, Vec<AuthorityId>, ValueQuery>;

	#[pallet::genesis_config]
	#[cfg_attr(feature = "std", derive(Default))]
	pub struct GenesisConfig {
		pub authorities: Vec<AuthorityId>,
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
			<Authorities<T>>::put(self.authorities.clone());
		}
	}

	// #[pallet::hooks]
	// impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
	// 	fn on_initialize(n: T::BlockNumber) -> Weight {
	// 	}
    //
	// 	fn on_finalize(n: T::BlockNumber) {
	// 	}
    //
	// }

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// pub enum ExtrinsicXxx {
		// 	AuthoritiesChange(Vec<AuthorityId>),
		// 	Transfer {
		// 		transfer: Transfer,
		// 		signature: AccountSignature,
		// 		exhaust_resources_when_not_first: bool,
		// 	},
		// 	IncludeData(Vec<u8>),
		// 	StorageChange(Vec<u8>, Option<Vec<u8>>),
		// 	OffchainIndexSet(Vec<u8>, Vec<u8>),
		// 	OffchainIndexClear(Vec<u8>),
		// 	Store(Vec<u8>),
		// }

		#[pallet::call_index(0)]
		#[pallet::weight(0)]
		pub fn authorities_change(origin: OriginFor<T>, new_authorities: Vec<AuthorityId>) -> DispatchResult {
			// NOTE: does not make any different.
			frame_system::ensure_signed(origin)?;
			<NewAuthorities<Runtime>>::put(new_authorities.to_vec());
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(0)]
		pub fn transfer(origin: OriginFor<T>, transfer: Transfer, signature: AccountSignature, exhaust_resources_when_not_first: bool) -> DispatchResult {
			frame_system::ensure_root(origin)?;
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(0)]
		pub fn include_data(origin: OriginFor<T>, data_: Vec<u8>) -> DispatchResult {
			frame_system::ensure_root(origin)?;
			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(0)]
		pub fn storage_change(origin: OriginFor<T>, key: Vec<u8>, value: Option<Vec<u8>>) -> DispatchResult {
			frame_system::ensure_root(origin)?;
			match value {
				Some(value) => storage::unhashed::put_raw(&key, &value),
				None => storage::unhashed::kill(&key),
			}
			Ok(())
		}

		#[pallet::call_index(4)]
		#[pallet::weight(0)]
		pub fn offchain_index_set(origin: OriginFor<T>, key: Vec<u8>, value: Vec<u8>) -> DispatchResult {
			frame_system::ensure_root(origin)?;
			sp_io::offchain_index::set(&key, &value);
			Ok(())
		}

		#[pallet::call_index(5)]
		#[pallet::weight(0)]
		pub fn offchain_index_clear(origin: OriginFor<T>, key: Vec<u8>) -> DispatchResult {
			frame_system::ensure_root(origin)?;
			sp_io::offchain_index::clear(&key);
			Ok(())
		}

		#[pallet::call_index(6)]
		#[pallet::weight(0)]
		pub fn store(origin: OriginFor<T>, data: Vec<u8>) -> DispatchResult {
			frame_system::ensure_root(origin)?;
			let content_hash = sp_io::hashing::blake2_256(&data);
			let extrinsic_index: u32 = storage::unhashed::get(well_known_keys::EXTRINSIC_INDEX).unwrap();
			sp_io::transaction_index::index(extrinsic_index, data.len() as u32, content_hash);
			Ok(())
		}
	}


	// #[pallet::validate_unsigned]
	// impl<T: Config> ValidateUnsigned for Pallet<T> {
	// 	type Call = Call<T>;
    //
	// 	// Inherent call is accepted for being dispatched
	// 	fn pre_dispatch(call: &Self::Call) -> Result<(), TransactionValidityError> {
	// 		match call {
	// 			Call::allowed_unsigned { .. } => Ok(()),
	// 			Call::inherent_call { .. } => Ok(()),
	// 			_ => Err(UnknownTransaction::NoUnsignedValidator.into()),
	// 		}
	// 	}
    //
	// 	// Inherent call is not validated as unsigned
	// 	fn validate_unsigned(
	// 		_source: TransactionSource,
	// 		call: &Self::Call,
	// 	) -> TransactionValidity {
	// 		match call {
	// 			Call::allowed_unsigned { .. } => Ok(Default::default()),
	// 			_ => UnknownTransaction::NoUnsignedValidator.into(),
	// 		}
	// 	}
	// }
}

pub fn balance_of_key(who: AccountId) -> Vec<u8> {
	who.to_keyed_vec(BALANCE_OF)
}

pub fn balance_of(who: AccountId) -> u64 {
	storage::hashed::get_or(&blake2_256, &balance_of_key(who), 0)
}

pub fn nonce_of(who: AccountId) -> u64 {
	storage::hashed::get_or(&blake2_256, &who.to_keyed_vec(NONCE_OF), 0)
}

pub fn authorities() -> Vec<AuthorityId> {
	<Authorities<Runtime>>::get()
}

pub fn get_block_number() -> Option<BlockNumber> {
	<Number<Runtime>>::get()
}

pub fn take_block_number() -> Option<BlockNumber> {
	<Number<Runtime>>::take()
}
