use schemars::JsonSchema;
use sov_bank::{Amount, IntoPayable};
use sov_modules_api::macros::{config_value, serialize, UniversalWallet};
use sov_modules_api::registration_lib::RegistrationError;
use sov_modules_api::{Context, DaSpec, EventEmitter, ModuleInfo, Spec, TxState};

use crate::{
    gas_coins, BalanceState, CustomError, Event, KnownSequencer, SequencerRegistry,
    SequencerRegistryError,
};

/// This enumeration represents the available call messages for interacting with
/// the `sov-sequencer-registry` module.
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary, proptest_derive::Arbitrary)
)]
#[derive(Debug, PartialEq, Eq, Clone, JsonSchema, UniversalWallet)]
#[serialize(Borsh, Serde)]
#[schemars(bound = "S: Spec", rename = "CallMessage")]
#[serde(rename_all = "snake_case")]
pub enum CallMessage<S: Spec> {
    /// Add a new sequencer to the sequencer registry.
    Register {
        /// The Da address of the sequencer you're registering.
        da_address: <S::Da as DaSpec>::Address,
        /// The initial balance of the sequencer.
        amount: Amount,
    },
    /// Increases the balance of the sequencer, transferring the funds from the sequencer account
    /// to the rollup.
    Deposit {
        /// The DA address of the sequencer.
        da_address: <S::Da as DaSpec>::Address,
        /// The amount to increase.
        amount: Amount,
    },
    /// Initiate a withdrawal of a sequencer's balance.
    InitiateWithdrawal {
        /// The DA address of the sequencer you're removing.
        da_address: <S::Da as DaSpec>::Address,
    },
    /// Withdraw a sequencer's balance after waiting for the withdrawal period.
    Withdraw {
        /// The DA address of the sequencer you're removing.
        da_address: <S::Da as DaSpec>::Address,
    },
    /// Rotates the sequencer's DA address without unstaking.
    ///
    /// Authorized by the rollup key (`context.sender()`) — the intended
    /// recovery path when a DA signing key is compromised but the rollup
    /// key is safe. Preserves `balance`, `balance_state`, and the
    /// `preferred_sequencer` pointer (atomically moved to `new_da_address`
    /// if the caller was the preferred sequencer).
    ///
    /// After this call lands on-chain, the sequencer node operator must
    /// restart their binary with the new DA signer keys. The registry
    /// cannot enforce this from state.
    UpdateDaAddress {
        /// The sequencer's current DA address (the one being rotated away from).
        old_da_address: <S::Da as DaSpec>::Address,
        /// The new DA address. Must not already be registered.
        new_da_address: <S::Da as DaSpec>::Address,
    },
}

impl<S: Spec> SequencerRegistry<S> {
    /// Tries to register a sequencer by staking the provided amount of gas tokens.
    /// This method uses the context's sender as the sequencer's address.
    ///
    /// # Errors
    /// Will error
    ///
    /// - If the provided amount is below the minimum required to register a sequencer.
    /// - If the minimum bond is not set.
    /// - If the sender's account does not have enough funds to register itself as a sequencer.
    /// - If the sequencer is already registered.
    pub(crate) fn register<ST: TxState<S>>(
        &mut self,
        da_address: &<S::Da as DaSpec>::Address,
        amount: Amount,
        context: &Context<S>,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        self.register_staker(da_address, amount, *context.sender(), state)?;

        Ok(())
    }

    pub(crate) fn register_staker<ST: TxState<S>>(
        &mut self,
        da_address: &<S::Da as DaSpec>::Address,
        amount: Amount,
        address: S::Address,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        if let Some(existing_sequencer) = self.known_sequencers.get(da_address, state)? {
            return Err(RegistrationError::AlreadyRegistered(
                existing_sequencer.address,
            ));
        }

        let Some(minimum_bond) = self.minimum_bond.get(state)? else {
            return Err(SequencerRegistryError::<S, ST>::NoMinimumBondSet);
        };

        if amount < minimum_bond {
            return Err(SequencerRegistryError::<S, ST>::InsufficientStakeAmount {
                address,
                bond_amount: amount,
                minimum_bond_amount: minimum_bond,
            });
        }

        self.bank
            .transfer_from(
                &address,
                self.id().clone().to_payable(),
                gas_coins(amount),
                state,
            )
            .map_err(
                |_| SequencerRegistryError::<S, ST>::InsufficientFundsToRegister {
                    address,
                    amount,
                },
            )?;
        let new_sequencer = KnownSequencer {
            address,
            balance: amount,
            balance_state: BalanceState::Active,
        };
        self.known_sequencers
            .set(da_address, &new_sequencer, state)?;

        self.emit_event(
            state,
            Event::<S>::Registered {
                sequencer: address,
                amount,
            },
        );
        Ok(())
    }

    pub(crate) fn deposit<ST: TxState<S>>(
        &mut self,
        da_address: &<S::Da as DaSpec>::Address,
        amount: Amount,
        context: &Context<S>,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        self.validate_sender(da_address, context.sender(), state)?;
        let Some(mut existing_sequencer) = self.known_sequencers.get(da_address, state)? else {
            return Err(RegistrationError::IsNotRegistered(*da_address));
        };
        let address = existing_sequencer.address;
        existing_sequencer.balance = existing_sequencer.balance.checked_add(amount).ok_or(
            SequencerRegistryError::<S, ST>::ToppingAccountMakesBalanceOverflow {
                address,
                existing_balance: existing_sequencer.balance,
                amount_to_add: amount,
            },
        )?;
        // Depositing re-activates the account if inactive.
        existing_sequencer.balance_state = BalanceState::Active;

        self.bank
            .transfer_from(
                &address,
                self.id().clone().to_payable(),
                gas_coins(amount),
                state,
            )
            .map_err(
                |_| SequencerRegistryError::<S, ST>::InsufficientFundsToTopUpAccount {
                    address,
                    amount_to_add: amount,
                },
            )?;

        self.known_sequencers
            .set(da_address, &existing_sequencer, state)?;

        self.emit_event(
            state,
            Event::<S>::Deposited {
                sequencer: address,
                amount: amount.0,
            },
        );

        Ok(())
    }

    /// Tries to remove a sequencer by unstaking the provided amount of gas tokens.
    /// This method uses the context's sender as the sequencer's address.
    ///
    /// # Errors
    /// Will error
    ///
    /// - If the sequencer is not registered.
    /// - If the sequencer tries to unregister itself during the execution of its own batch.
    /// - If the supplied `da_address` does not match the transaction sender.
    /// - If the module balance is not high enough to refund the sequencer's staked amount (this is a bug).
    pub(crate) fn initiate_withdrawal<ST: TxState<S>>(
        &mut self,
        da_address: &<S::Da as DaSpec>::Address,
        context: &Context<S>,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        self.validate_sender(da_address, context.sender(), state)?;
        let Some(mut existing_sequencer) = self.known_sequencers.get(da_address, state)? else {
            return Err(RegistrationError::IsNotRegistered(*da_address));
        };

        if &existing_sequencer.address == context.sequencer() {
            return Err(RegistrationError::Custom(
                CustomError::CannotUnregisterDuringOwnBatch(*da_address),
            ));
        }
        if existing_sequencer.balance_state != BalanceState::Active {
            return Err(RegistrationError::WithdrawalAlreadyPending(
                existing_sequencer.address,
            ));
        }

        // We force the sequencer to wait to withdraw until all of their pending blobs will have been selected for processing or dropped.
        // In the worst case, this could take up to `DEFERRED_SLOTS_COUNT` slots, so wait until the slot after that.
        existing_sequencer.balance_state = BalanceState::PendingWithdrawal {
            ready_at: state
                .current_visible_slot_number()
                .advance(config_value!("DEFERRED_SLOTS_COUNT") + 1),
        };
        self.known_sequencers
            .set(da_address, &existing_sequencer, state)?;

        self.emit_event(
            state,
            Event::<S>::InitiatedWithdrawal {
                sequencer: existing_sequencer.address,
            },
        );
        Ok(())
    }

    pub(crate) fn withdraw<ST: TxState<S>>(
        &mut self,
        da_address: &<S::Da as DaSpec>::Address,
        context: &Context<S>,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        self.validate_sender(da_address, context.sender(), state)?;
        let Some(existing_sequencer) = self.known_sequencers.get(da_address, state)? else {
            return Err(RegistrationError::IsNotRegistered(*da_address));
        };
        let BalanceState::PendingWithdrawal { ready_at } = existing_sequencer.balance_state else {
            return Err(RegistrationError::Custom(
                CustomError::WithdrawalNotInitiated(*da_address),
            ));
        };
        if ready_at > state.current_visible_slot_number() {
            return Err(RegistrationError::Custom(CustomError::WithdrawalNotReady {
                sequencer: *da_address,
                current_visible_height: state.current_visible_slot_number(),
                ready_at,
            }));
        }
        self.known_sequencers.delete(da_address, state)?;
        self.bank
            .transfer_from(
                self.id().clone().to_payable(),
                &existing_sequencer.address,
                gas_coins(existing_sequencer.balance),
                state,
            )
            .expect("Failed to withdraw a sequencer balance. This indicates a bug in accounting!");

        self.emit_event(
            state,
            Event::<S>::Withdrew {
                sequencer: existing_sequencer.address,
                amount_withdrawn: existing_sequencer.balance,
            },
        );

        Ok(())
    }

    /// Rotates a sequencer's DA address while preserving their stake and state.
    ///
    /// Authorized by the caller's rollup key: `validate_sender` checks that
    /// `context.sender()` matches the rollup address stored under `old_da_address`,
    /// which blocks impersonation of another sequencer's DA.
    ///
    /// # Errors
    /// - If `old_da_address` is not registered.
    /// - If the caller's rollup key does not own the entry at `old_da_address`.
    /// - If `new_da_address` equals `old_da_address`.
    /// - If `new_da_address` is already registered.
    /// - TODO: Address this some-how: End Batch Hook, or something like it.
    ///   If the caller is the active batch producer for this slot
    ///   (`CannotUnregisterDuringOwnBatch`): `blob-storage` reads
    ///   `preferred_sequencer` / `known_sequencers` live during slot processing,
    ///   so flipping them mid-own-batch creates intra-slot inconsistency.
    ///
    pub(crate) fn update_da_address<ST: TxState<S>>(
        &mut self,
        old_da_address: &<S::Da as DaSpec>::Address,
        new_da_address: &<S::Da as DaSpec>::Address,
        context: &Context<S>,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        self.validate_sender(old_da_address, context.sender(), state)?;

        if old_da_address == new_da_address {
            return Err(RegistrationError::Custom(
                CustomError::NewDaAddressSameAsOld(*old_da_address),
            ));
        }

        if let Some(conflict) = self.known_sequencers.get(new_da_address, state)? {
            return Err(RegistrationError::AlreadyRegistered(conflict.address));
        }

        let existing_sequencer = self
            .known_sequencers
            .get(old_da_address, state)?
            .expect("validate_sender guarantees old_da_address is registered");

        if &existing_sequencer.address == context.sequencer() {
            return Err(RegistrationError::Custom(
                CustomError::CannotUnregisterDuringOwnBatch(*old_da_address),
            ));
        }

        let rollup_address = existing_sequencer.address;

        self.known_sequencers.delete(old_da_address, state)?;
        self.known_sequencers
            .set(new_da_address, &existing_sequencer, state)?;

        if let Some(preferred) = self.preferred_sequencer.get(state)? {
            if &preferred == old_da_address {
                self.preferred_sequencer.set(new_da_address, state)?;
            }
        }

        self.emit_event(
            state,
            Event::<S>::DaAddressUpdated {
                sequencer: rollup_address,
                old_da_address: *old_da_address,
                new_da_address: *new_da_address,
            },
        );
        Ok(())
    }

    fn validate_sender<ST: TxState<S>>(
        &self,
        da_address: &<S::Da as DaSpec>::Address,
        sender: &S::Address,
        state: &mut ST,
    ) -> Result<(), SequencerRegistryError<S, ST>> {
        let belongs_to = self
            .known_sequencers
            .get_or_err(da_address, state)?
            .map_err(|_| RegistrationError::IsNotRegistered(*da_address))?
            .address;

        if sender != &belongs_to {
            return Err(RegistrationError::Custom(
                CustomError::SuppliedAddressDoesNotMatchTxSender {
                    parameter: belongs_to,
                    sender: *sender,
                },
            ));
        }

        Ok(())
    }
}
