
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
	#[pallet::generate_store(pub(super) trait Store)]
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

			// let from_balance_key = &sp_keyring::AccountKeyring::Charlie.public().to_keyed_vec(BALANCE_OF);
			// let from_balance: u64 = storage::unhashed::get_or(&vec![255, 180, 215, 200, 187, 25, 127, 45, 116, 23, 109, 33, 10, 143, 89, 235, 239, 135, 92, 89, 43, 71, 86, 128, 34, 60, 93, 107, 40, 214, 252, 199], 0);
// 			let x: u64 = storage::hashed::get_or(&blake2_256, &vec!
// [98, 97, 108, 97, 110, 99, 101, 58, 144, 181, 171, 32, 92, 105, 116, 201, 234, 132, 27, 230, 136, 134, 70, 51, 220, 156, 168, 163, 87, 132, 62, 234, 207, 35, 20, 100, 153, 101, 254, 34]
// 				, 0);
// 			log::trace!("xxx: on_finalize 1 {}", x);
// 			let x: u64 = storage::unhashed::get_or(&vec!
// [9, 91, 88, 111, 173, 42, 233, 242, 243, 127, 178, 174, 97, 101, 50, 142, 173, 250, 159, 216, 62, 5, 9, 128, 158, 114, 97, 80, 215, 133, 187, 100,], 0);
// 			log::trace!("xxx: on_finalize 2 {}", x);

			// let sum = storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 42, 251, 169, 39, 142, 48, 204, 246, 166, 206, 179, 168, 182, 227, 54, 183, 0, 104, 240, 69, 198, 102, 242, 231, 244, 249, 204, 95, 71, 219, 137, 114],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 182, 6, 252, 115, 245, 127, 3, 205, 180, 201, 50, 212, 117, 171, 66, 96, 67, 228, 41, 206, 204, 47, 255, 240, 210, 103, 43, 13, 248, 57, 140, 72],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 70, 241, 54, 181, 100, 225, 250, 213, 80, 49, 64, 77, 216, 78, 92, 211, 250, 118, 191, 231, 204, 117, 153, 179, 157, 56, 253, 6, 102, 59, 188, 10],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 132, 97, 127, 87, 83, 114, 237, 181, 163, 109, 133, 192, 76, 223, 46, 70, 153, 249, 111, 227, 62, 181, 249, 74, 40, 192, 65, 184, 142, 57, 141, 12],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 72, 215, 233, 49, 48, 122, 251, 75, 104, 216, 213, 101, 212, 198, 110, 0, 216, 86, 198, 214, 95, 95, 237, 107, 184, 45, 207, 182, 14, 147, 108, 103],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 96, 197, 127, 0, 8, 6, 124, 192, 28, 95, 249, 235, 46, 47, 155, 58, 148, 41, 154, 145, 90, 145, 25, 139, 209, 2, 26, 108, 85, 89, 111, 87],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 66, 17, 183, 158, 52, 238, 128, 114, 234, 181, 6, 237, 212, 185, 58, 123, 133, 161, 76, 154, 5, 229, 205, 208, 86, 217, 142, 125, 188, 168, 119, 48],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 186, 142, 44, 117, 148, 221, 116, 115, 15, 60, 168, 53, 233, 84, 85, 209, 153, 38, 24, 151, 237, 201, 115, 93, 96, 46, 162, 150, 21, 226, 177, 11],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 18, 93, 87, 23, 31, 249, 36, 31, 7, 172, 170, 27, 182, 166, 16, 53, 23, 150, 92, 242, 205, 0, 230, 67, 178, 126, 117, 153, 235, 204, 186, 112],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 18, 198, 207, 214, 99, 32, 62, 161, 105, 104, 89, 79, 36, 105, 3, 56, 190, 253, 144, 104, 86, 196, 210, 244, 239, 50, 218, 213, 120, 219, 162, 12],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 222, 62, 120, 158, 205, 83, 67, 31, 229, 192, 108, 18, 183, 33, 55, 21, 52, 150, 218, 206, 53, 198, 149, 181, 244, 215, 180, 31, 126, 213, 118, 59],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 238, 171, 80, 51, 141, 142, 81, 118, 211, 20, 24, 2, 215, 176, 16, 165, 93, 173, 205, 95, 35, 207, 138, 170, 250, 114, 70, 39, 233, 103, 233, 14],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 46, 61, 67, 183, 176, 208, 78, 119, 110, 105, 231, 190, 53, 36, 124, 236, 218, 198, 85, 4, 197, 121, 25, 87, 49, 234, 246, 75, 121, 64, 150, 110],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 12, 41, 177, 97, 226, 127, 248, 186, 69, 191, 107, 173, 71, 17, 243, 38, 252, 80, 106, 136, 3, 69, 58, 77, 126, 49, 88, 233, 147, 73, 95, 16],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 28, 33, 21, 208, 97, 32, 234, 43, 238, 50, 221, 96, 29, 2, 243, 99, 103, 86, 78, 125, 223, 132, 174, 39, 23, 202, 63, 9, 116, 89, 101, 46],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 252, 60, 55, 69, 157, 155, 220, 97, 245, 138, 94, 188, 1, 233, 226, 48, 90, 25, 211, 144, 192, 84, 61, 199, 51, 134, 30, 195, 207, 29, 224, 31],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 142, 175, 4, 21, 22, 135, 115, 99, 38, 201, 254, 161, 126, 37, 252, 82, 135, 97, 54, 147, 201, 18, 144, 156, 178, 38, 170, 71, 148, 242, 106, 72],0)+
			// 	storage::hashed::get_or(&blake2_256, &vec![98, 97, 108, 97, 110, 99, 101, 58, 144, 181, 171, 32, 92, 105, 116, 201, 234, 132, 27, 230, 136, 134, 70, 51, 220, 156, 168, 163, 87, 132, 62, 234, 207, 35, 20, 100, 153, 101, 254, 34],0);
			// log::trace!("xxx: on_finalize 2 {}", sum);


			use sp_core::storage::StateVersion;
			// // This MUST come after all changes to storage are done. Otherwise we will fail the                  
			// // “Storage root does not match that calculated” assertion.     
			let storage_root = Hash::decode(&mut &sp_io::storage::root(StateVersion::V1)[..])
				.expect("`storage_root` is a valid hash");
			log::trace!("xxx: on_finalize storage_root v1 1: {}", storage_root);
			let storage_root = Hash::decode(&mut &sp_io::storage::root(StateVersion::V1)[..])
				.expect("`storage_root` is a valid hash");
			log::trace!("xxx: on_finalize storage_root v1 2: {}", storage_root);
			let storage_root = Hash::decode(&mut &sp_io::storage::root(StateVersion::V0)[..])
				.expect("`storage_root` is a valid hash");
			log::trace!("xxx: on_finalize storage_root v0 1: {}", storage_root);
			let storage_root = Hash::decode(&mut &sp_io::storage::root(StateVersion::V0)[..])
				.expect("`storage_root` is a valid hash");
			log::trace!("xxx: on_finalize storage_root v0 2: {}", storage_root);
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
