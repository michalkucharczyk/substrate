// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use codec::{Decode, Encode};
use crate::{AccountId, AuthorityId, substrate_test_pallet, RuntimeCall, Signature, SignedExtra, SignedPayload, UncheckedExtrinsic};
#[cfg(feature = "std")]
use crate::sr25519::Pair;
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;
#[cfg(feature = "std")]
use sp_core::crypto::Pair as TraitPair;
use sp_runtime::transaction_validity::{InvalidTransaction,TransactionValidityError};
use sp_std::prelude::*;
use crate::substrate_test_pallet::pallet::Call as PalletCall;


/// Transfer used in test substrate pallet
#[derive(Clone, PartialEq, Eq, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct Transfer {
	pub from: AccountId,
	pub to: AccountId,
	pub amount: u64,
	pub nonce: u64,
}

impl Transfer {
	/// Convert into a signed unchecked extrinsic.
	#[cfg(feature = "std")]
	pub fn into_unchecked_extrinsic(self) -> UncheckedExtrinsic {
		UncheckedExtrinsicBuilder::new_transfer(self).build()
	}

	/// Convert into a signed extrinsic, which will only end up included in the block
	/// if it's the first transaction. Otherwise it will cause `ResourceExhaustion` error
	/// which should be considered as block being full.
	#[cfg(feature = "std")]
	pub fn into_resources_exhausting_unchecked_extrinsic(self) -> UncheckedExtrinsic {
		UncheckedExtrinsicBuilder::new(TransferCallBuilder::new(self).exhaust_resources().build()).build()
	}

	/// If feasible extracts `Transfer` from given `UncheckedExtrinsic`
	pub fn try_from_unchecked_extrinsic(uxt: &UncheckedExtrinsic) -> Option<Self> {
		if let RuntimeCall::SubstrateTest(ref test_pallet_call) = uxt.function {
			if let PalletCall::transfer{transfer,..} = test_pallet_call {
				return Some(transfer.clone())
			}
			return None
		}
		None
	}

	/// Verifies signature and extracts `Transfer` from given `UncheckedExtrinsic`, otherwise returns error
	pub fn check_transfer(uxt: &UncheckedExtrinsic) -> Result<Self, TransactionValidityError> {
		if let RuntimeCall::SubstrateTest(PalletCall::transfer{ref transfer,ref signature, ..}) = uxt.function  {
			if sp_runtime::verify_encoded_lazy(signature, transfer, &transfer.from) {
				Ok(transfer.clone())
			} else {
				Err(InvalidTransaction::BadProof.into())
			}
		} else {
			Err(InvalidTransaction::Call.into())
		}
	}
}

/// Generates `PalletCall::transfer_call`
pub struct TransferCallBuilder {
	transfer: Transfer, 
	signature: Option<Signature>,
	exhaust_resources: bool,
}

impl TransferCallBuilder {
	/// Creates `Self` with given `transfer` value
	pub fn new(transfer: Transfer) -> Self {
		TransferCallBuilder {
			transfer, signature: None, exhaust_resources: false
		}
	}

	/// Signs `transfer` with `signer` and embeds signature into `PalletCall::transfer_call`
	#[cfg(feature = "std")]
	pub fn signer(mut self, signer: Pair) -> Self {
		self.signature = Some(
			signer.sign(&self.transfer.encode())
		);
		self
	}

	/// Embeds given signature into `PalletCall::transfer_call`
	pub fn with_signature(mut self, signature: Signature) -> Self {
		self.signature = Some(signature);
		self
	}

	/// Sets `exhaust_resources` flag of `PalletCall::transfer_call` to true
	pub fn exhaust_resources(mut self) -> Self {
		self.exhaust_resources = true;
		self
	}

	#[cfg(feature = "std")]
	/// Generates instance of `PalletCall::transfer_call`
	pub fn build<T: substrate_test_pallet::Config>(self) -> PalletCall<T> {
		let signature = match self.signature {
			Some(signature) => signature,
			None => {
				sp_keyring::AccountKeyring::from_public(&self.transfer.from)
					.expect("Creates keyring from public key.")
					.sign(&self.transfer.encode())
			}
		};
		PalletCall::transfer { 
			transfer: self.transfer, 
			signature, 
			exhaust_resources_when_not_first: self.exhaust_resources 
		} 
	}

	#[cfg(not(feature = "std"))]
	/// Dummy implementation for `no_std`.
	pub fn build<T: substrate_test_pallet::Config>(self) -> PalletCall<T> {
		unimplemented!()
	}
}


/// Generates `UncheckedExtrinsic`
pub struct UncheckedExtrinsicBuilder {
	function: RuntimeCall,
	is_unsigned: bool,
}

impl UncheckedExtrinsicBuilder {
	/// Creates builder for given `RuntimeCall`
	pub fn new(function: impl Into<RuntimeCall>) -> Self {
		Self {
			function: function.into(),
			is_unsigned: false
		}
	}

	/// Creates builder for given `Transfer`
	pub fn new_transfer(transfer: Transfer) -> Self {
		Self::new(TransferCallBuilder::new(transfer).build())
	}

	/// Creates builder for `PalletCall::authorities_change` call using given parameters
	pub fn new_authorities_change(new_authorities: Vec<AuthorityId>) -> Self {
		Self::new(
			PalletCall::authorities_change{ new_authorities }
		)
	}

	/// Creates builder for `PalletCall::include_data` call using given parameters
	pub fn new_include_data(data: Vec<u8>) -> Self {
		Self::new(
			PalletCall::include_data{ data }
		)
	}

	/// Creates builder for `PalletCall::storage_change` call using given parameters
	pub fn new_storage_change(key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
		Self::new(
			PalletCall::storage_change{ key, value }
		)
	}

	/// Creates builder for `PalletCall::storage_change_unsigned` call using given parameters. Will create
	/// unsigned UncheckedExtrinsic.
	pub fn new_storage_change_unsigned(key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
		Self::new(
			PalletCall::storage_change_unsigned{ key, value }
		)
		.unsigned()
	}

	/// Creates builder for `PalletCall::offchain_index_set` call using given parameters
	pub fn new_offchain_index_set(key: Vec<u8>, value: Vec<u8>) -> Self {
		Self::new(
			PalletCall::offchain_index_set{ key, value }
		)
	}

	/// Creates builder for `PalletCall::offchain_index_clear` call using given parameters
	pub fn new_offchain_index_clear(key: Vec<u8>) -> Self {
		Self::new(
			PalletCall::offchain_index_clear{ key }
		)
	}

	/// Creates builder for `PalletCall::new_store` call using given parameters
	pub fn new_store(data: Vec<u8>) -> Self {
		Self::new(
			PalletCall::store{ data }
		)
	}

	/// Creates builder for `PalletCall::new_deposit_log_digest_item` call using given `log`
	pub fn new_deposit_log_digest_item(log: sp_runtime::generic::DigestItem) -> Self {
		Self::new(
			PalletCall::deposit_log_digest_item{ log }
		)
	}

	/// Unsigned `UncheckedExtrinsic` will be created
	pub fn unsigned(mut self) -> Self {
		self.is_unsigned = true;
		self
	}

	#[cfg(not(feature = "std"))]
	pub fn build(self) -> UncheckedExtrinsic {
		unimplemented!()
	}

	/// Builds `UncheckedExtrinsic` using embedded parameters
	#[cfg(feature = "std")]
	pub fn build(self) -> UncheckedExtrinsic {
		if self.is_unsigned {
			UncheckedExtrinsic::new_unsigned(self.function)
		} else {
			let sender = sp_keyring::AccountKeyring::Alice;
			let extra = SignedExtra{};
			let raw_payload = SignedPayload::from_raw(
				self.function.clone(),
				extra,
				()
			);
			let signature = raw_payload.using_encoded(|e| sender.sign(e));

			UncheckedExtrinsic::new_signed(
				self.function,
				sender.public(),
				signature,
				extra,
			)
		}
	}
}
