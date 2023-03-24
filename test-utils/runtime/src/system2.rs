
use crate::{
	AccountId, AccountSignature, AuthorityId, BlockNumber, Digest, Runtime, Transfer,
	H256 as Hash,
};
use codec::KeyedVec;
use frame_support::storage;
use sp_core::storage::well_known_keys;
use sp_io::hashing::blake2_256;
use sp_std::prelude::*;

const NONCE_OF: &[u8] = b"nonce:";
const BALANCE_OF: &[u8] = b"balance:";

pub use self::pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use pallet_timestamp::{self as timestamp}; //todo?
    use pallet_timestamp::WeightInfo;

	#[pallet::pallet]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::config]
	pub trait Config: frame_system::Config + timestamp::Config {} //todo: timestamp::config needed?

	#[pallet::storage]
	pub type ExtrinsicData<T> = StorageMap<_, Blake2_128Concat, u32, Vec<u8>, ValueQuery>;

	// The current block number being processed. Set by `execute_block`.
	#[pallet::storage]
	pub type Number<T: Config> = StorageValue<_, T::BlockNumber, OptionQuery>;

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

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(n: T::BlockNumber) -> Weight {
			// populate environment.
			Number::<T>::put(n);
			storage::unhashed::put(well_known_keys::EXTRINSIC_INDEX, &0u32);
            //
			let d = <frame_system::Pallet<T>>::digest();

			// try to read something that depends on current header digest
			// so that it'll be included in execution proof
			if let Some(sp_runtime::generic::DigestItem::Other(v)) = d.logs().iter().next() {
				let _: Option<u32> = storage::unhashed::get(v);
			}


			frame_support::log::info!(
				target: "frame::executive",
				"yyy: on_initialize: {d:#?}",
			);

			T::WeightInfo::on_finalize()
		}

		fn on_finalize(n: T::BlockNumber) {
		}
	}

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
		#[pallet::weight(100)]
		pub fn authorities_change(origin: OriginFor<T>, new_authorities: Vec<AuthorityId>) -> DispatchResult {
			// NOTE: does not make any different.
			frame_system::ensure_signed(origin)?;
			<NewAuthorities<Runtime>>::put(new_authorities.to_vec());
			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(100)]
		pub fn transfer(origin: OriginFor<T>, transfer: Transfer, signature: AccountSignature, exhaust_resources_when_not_first: bool) -> DispatchResult {
			log::trace!("xxxxxxx -> transfer");
			frame_system::ensure_signed(origin)?;

			//todo do we need to re-verify transfer (signature / nonce / balance)?

			let nonce_key = transfer.from.to_keyed_vec(NONCE_OF);
			let expected_nonce: u64 = storage::hashed::get_or(&blake2_256, &nonce_key, 0);
			// increment nonce in storage
			storage::hashed::put(&blake2_256, &nonce_key, &(expected_nonce + 1));

			// check sender balance
			let from_balance_key = transfer.from.to_keyed_vec(BALANCE_OF);
			let from_balance: u64 = storage::hashed::get_or(&blake2_256, &from_balance_key, 0);

			// enact transfer
			// if transfer.amount > from_balance {
			// 	return Err(InvalidTransaction::Payment.into())
			// }
			let to_balance_key = transfer.to.to_keyed_vec(BALANCE_OF);
			let to_balance: u64 = storage::hashed::get_or(&blake2_256, &to_balance_key, 0);
			storage::hashed::put(&blake2_256, &from_balance_key, &(from_balance - transfer.amount));
			storage::hashed::put(&blake2_256, &to_balance_key, &(to_balance + transfer.amount));
			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(100)]
		pub fn include_data(origin: OriginFor<T>, _data: Vec<u8>) -> DispatchResult {
			log::trace!("xxxxxxx -> include_data");
			frame_system::ensure_signed(origin)?;
			//todo (nothing?)
			Ok(())
		}

		#[pallet::call_index(3)]
		#[pallet::weight(100)]
		pub fn storage_change_unsigned(origin: OriginFor<T>, key: Vec<u8>, value: Option<Vec<u8>>) -> DispatchResult {
			match value {
				Some(value) => storage::unhashed::put_raw(&key, &value),
				None => storage::unhashed::kill(&key),
			}
			Ok(())
		}

		#[pallet::call_index(4)]
		#[pallet::weight(100)]
		pub fn storage_change(origin: OriginFor<T>, key: Vec<u8>, value: Option<Vec<u8>>) -> DispatchResult {
			frame_system::ensure_signed(origin)?;
			match value {
				Some(value) => storage::unhashed::put_raw(&key, &value),
				None => storage::unhashed::kill(&key),
			}
			Ok(())
		}

		#[pallet::call_index(5)]
		#[pallet::weight(100)]
		pub fn offchain_index_set(origin: OriginFor<T>, key: Vec<u8>, value: Vec<u8>) -> DispatchResult {
			frame_system::ensure_signed(origin)?;
			sp_io::offchain_index::set(&key, &value);
			Ok(())
		}

		#[pallet::call_index(6)]
		#[pallet::weight(100)]
		pub fn offchain_index_clear(origin: OriginFor<T>, key: Vec<u8>) -> DispatchResult {
			frame_system::ensure_signed(origin)?;
			sp_io::offchain_index::clear(&key);
			Ok(())
		}

		#[pallet::call_index(7)]
		#[pallet::weight(100)]
		pub fn store(origin: OriginFor<T>, data: Vec<u8>) -> DispatchResult {
			frame_system::ensure_signed(origin)?;
			let content_hash = sp_io::hashing::blake2_256(&data);
			let extrinsic_index: u32 = storage::unhashed::get(well_known_keys::EXTRINSIC_INDEX).unwrap();
			sp_io::transaction_index::index(extrinsic_index, data.len() as u32, content_hash);
			Ok(())
		}

		#[pallet::call_index(8)]
		#[pallet::weight(100)]
		pub fn deposit_log_digest_item(origin: OriginFor<T>, log: sp_runtime::generic::DigestItem) -> DispatchResult {
			<frame_system::Pallet<T>>::deposit_log(log);
			Ok(())
		}


		// #[pallet::call_index(9)]
		// #[pallet::weight(100)]
		// pub fn deposit_log(origin: OriginFor<T>, log: sp_finality_grandpa::ConsensusLog<T::BlockNumber>) -> DispatchResult {
		// 	<frame_system::Pallet<T>>::deposit_log(
		// 	sp_runtime::generic::DigestItem::Consensus(
		// 		sp_finality_grandpa::GRANDPA_ENGINE_ID, log.encode()
		// 	));
        //
		// 	// <frame_system::Pallet<T>>::deposit_log(log);
		// 	Ok(())
		// }
	}


	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		// Inherent call is not validated as unsigned
		fn validate_unsigned(
			_source: TransactionSource,
			call: &Self::Call,
		) -> TransactionValidity {
			log::trace!("xxxxxxx -> validate_unsigned");
			validate_runtime_call(call)
		}
	}
}

pub fn balance_of_key(who: AccountId) -> Vec<u8> {
	who.to_keyed_vec(BALANCE_OF)
}

pub fn balance_of(who: AccountId) -> u64 {
	storage::hashed::get_or(&blake2_256, &balance_of_key(who), 0)
}

//todo: can be removed?
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


use codec::Encode;
use sp_runtime::{
	transaction_validity::{
		InvalidTransaction, TransactionSource, TransactionValidity, TransactionValidityError, ValidTransaction }
};
pub fn validate_runtime_call<T: pallet::Config>(
	call: &pallet::Call<T>,
) -> TransactionValidity {
	log::trace!("xxxxxxx -> validate_runtime_call");
	//todo: this shall return provides tags!
	match call {
		Call::transfer { transfer, signature, exhaust_resources_when_not_first } => {
			let extrinsic_index: u32 = storage::unhashed::get(well_known_keys::EXTRINSIC_INDEX).unwrap_or_default();

			if *exhaust_resources_when_not_first && extrinsic_index != 0 {
				return InvalidTransaction::ExhaustsResources.into()
			}

			// check signature
			if !sp_runtime::verify_encoded_lazy(signature, transfer, &transfer.from) {
				return InvalidTransaction::BadProof.into()
			}

			// check nonce
			let nonce_key = transfer.from.to_keyed_vec(NONCE_OF);
			let expected_nonce: u64 = storage::hashed::get_or(&blake2_256, &nonce_key, 0);
			if transfer.nonce < expected_nonce {
				return InvalidTransaction::Stale.into()
			}

			if transfer.nonce > expected_nonce + 64 {
				return InvalidTransaction::Future.into()
			}

			// check sender balance
			let from_balance_key = transfer.from.to_keyed_vec(BALANCE_OF);
			let from_balance: u64 = storage::hashed::get_or(&blake2_256, &from_balance_key, 0);

			if transfer.amount > from_balance {
				return Err(InvalidTransaction::Payment.into())
			}

			let encode = |from: &AccountId, nonce: u64| (from, nonce).encode();
			let requires = if transfer.nonce != expected_nonce && transfer.nonce > 0 {
				vec![encode(&transfer.from, transfer.nonce - 1)]
			} else {
				vec![]
			};

			let provides = vec![encode(&transfer.from, transfer.nonce)];

			Ok(ValidTransaction {
				priority: transfer.amount,
				requires,
				provides,
				longevity: 64,
				propagate: true,
			})
		},
		_ => Ok(Default::default())
	}
}
