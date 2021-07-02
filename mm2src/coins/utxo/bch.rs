use super::*;
use crate::utxo::rpc_clients::UtxoRpcFut;
use crate::utxo::slp::{parse_slp_script, SlpTransaction};
use crate::{CanRefundHtlc, CoinBalance, NegotiateSwapContractAddrErr, SwapOps, TradePreimageValue,
            ValidateAddressResult, WithdrawFut};
use common::log::warn;
use common::mm_metrics::MetricsArc;
use common::mm_number::MmNumber;
use futures::{FutureExt, TryFutureExt};
use keys::NetworkPrefix as CashAddrPrefix;
use serialization::{deserialize, CoinVariant};

#[derive(Clone, Debug)]
pub struct BchCoin {
    utxo_arc: UtxoArc,
    slp_addr_prefix: CashAddrPrefix,
}

pub enum IsSlpUtxoError {
    Rpc(UtxoRpcError),
    TxDeserialization(serialization::Error),
}

impl From<UtxoRpcError> for IsSlpUtxoError {
    fn from(err: UtxoRpcError) -> IsSlpUtxoError { IsSlpUtxoError::Rpc(err) }
}

impl From<serialization::Error> for IsSlpUtxoError {
    fn from(err: serialization::Error) -> IsSlpUtxoError { IsSlpUtxoError::TxDeserialization(err) }
}

impl BchCoin {
    pub fn slp_prefix(&self) -> CashAddrPrefix { self.slp_addr_prefix }

    async fn should_skip_utxo(&self, utxo: &UnspentInfo) -> Result<bool, MmError<UtxoRpcError>> {
        // zero output is reserved for OP_RETURN in the SLP protocol so it can be used right away
        if utxo.outpoint.index == 0 {
            return Ok(false);
        }

        let previous_tx = self
            .get_verbose_transaction_from_cache_or_rpc(utxo.outpoint.hash.reversed().into())
            .compat()
            .await?
            .into_inner();

        let prev_tx: UtxoTx = deserialize(previous_tx.hex.as_slice())?;
        if prev_tx.outputs.is_empty() {
            return Ok(false);
        }

        match parse_slp_script(&prev_tx.outputs[0].script_pubkey) {
            Ok(slp_details) => match slp_details.transaction {
                SlpTransaction::Send { amounts, .. } => Ok(utxo.outpoint.index <= amounts.len() as u32),
                SlpTransaction::Genesis { mint_baton_vout, .. } => {
                    let is_genesis = utxo.outpoint.index == 1;
                    let is_baton = Some(utxo.outpoint.index) == mint_baton_vout.map(|baton| baton as u32);
                    Ok(is_genesis || is_baton)
                },
                SlpTransaction::Mint { mint_baton_vout, .. } => {
                    let is_mint = utxo.outpoint.index == 1;
                    let is_baton = Some(utxo.outpoint.index) == mint_baton_vout.map(|baton| baton as u32);
                    Ok(is_mint || is_baton)
                },
            },
            Err(e) => {
                let script: Script = prev_tx.outputs[0].script_pubkey.clone().into();
                let should_skip = !(script.is_pay_to_public_key_hash()
                    || script.is_pay_to_public_key()
                    || script.is_pay_to_script_hash());
                if should_skip {
                    warn!(
                        "Skipping UTXO {:?}, failed to parse script as SLP ({}) and script is not standard",
                        utxo, e
                    );
                }
                Ok(should_skip)
            },
        }
    }
}

impl AsRef<UtxoCoinFields> for BchCoin {
    fn as_ref(&self) -> &UtxoCoinFields { &self.utxo_arc }
}

pub async fn bch_coin_from_conf_and_request(
    ctx: &MmArc,
    ticker: &str,
    conf: &Json,
    req: &Json,
    slp_addr_prefix: CashAddrPrefix,
    priv_key: &[u8],
) -> Result<BchCoin, String> {
    let constructor = move |utxo_arc| BchCoin {
        utxo_arc,
        slp_addr_prefix,
    };
    let coin: BchCoin =
        try_s!(utxo_common::utxo_arc_from_conf_and_request(ctx, ticker, conf, req, priv_key, constructor).await);
    Ok(coin)
}

// if mockable is placed before async_trait there is `munmap_chunk(): invalid pointer` error on async fn mocking attempt
#[async_trait]
#[cfg_attr(test, mockable)]
impl UtxoCommonOps for BchCoin {
    async fn get_tx_fee(&self) -> Result<ActualTxFee, JsonRpcError> { utxo_common::get_tx_fee(&self.utxo_arc).await }

    async fn get_htlc_spend_fee(&self) -> UtxoRpcResult<u64> { utxo_common::get_htlc_spend_fee(self).await }

    fn addresses_from_script(&self, script: &Script) -> Result<Vec<Address>, String> {
        utxo_common::addresses_from_script(&self.utxo_arc, script)
    }

    fn denominate_satoshis(&self, satoshi: i64) -> f64 { utxo_common::denominate_satoshis(&self.utxo_arc, satoshi) }

    fn my_public_key(&self) -> &Public { self.utxo_arc.key_pair.public() }

    fn address_from_str(&self, address: &str) -> Result<Address, String> {
        utxo_common::checked_address_from_str(&self.utxo_arc, address)
    }

    async fn get_current_mtp(&self) -> UtxoRpcResult<u32> {
        utxo_common::get_current_mtp(&self.utxo_arc, CoinVariant::Standard).await
    }

    fn is_unspent_mature(&self, output: &RpcTransaction) -> bool {
        utxo_common::is_unspent_mature(self.utxo_arc.conf.mature_confirmations, output)
    }

    async fn calc_interest_if_required(
        &self,
        unsigned: TransactionInputSigner,
        data: AdditionalTxData,
        my_script_pub: Bytes,
    ) -> UtxoRpcResult<(TransactionInputSigner, AdditionalTxData)> {
        utxo_common::calc_interest_if_required(self, unsigned, data, my_script_pub).await
    }

    async fn calc_interest_of_tx(&self, tx: &UtxoTx, input_transactions: &mut HistoryUtxoTxMap) -> UtxoRpcResult<u64> {
        utxo_common::calc_interest_of_tx(self, tx, input_transactions).await
    }

    async fn get_mut_verbose_transaction_from_map_or_rpc<'a, 'b>(
        &'a self,
        tx_hash: H256Json,
        utxo_tx_map: &'b mut HistoryUtxoTxMap,
    ) -> UtxoRpcResult<&'b mut HistoryUtxoTx> {
        utxo_common::get_mut_verbose_transaction_from_map_or_rpc(self, tx_hash, utxo_tx_map).await
    }

    async fn p2sh_spending_tx(
        &self,
        prev_transaction: UtxoTx,
        redeem_script: Bytes,
        outputs: Vec<TransactionOutput>,
        script_data: Script,
        sequence: u32,
        lock_time: u32,
    ) -> Result<UtxoTx, String> {
        utxo_common::p2sh_spending_tx(
            self,
            prev_transaction,
            redeem_script,
            outputs,
            script_data,
            sequence,
            lock_time,
        )
        .await
    }

    async fn ordered_mature_unspents<'a>(
        &'a self,
        address: &Address,
    ) -> UtxoRpcResult<(Vec<UnspentInfo>, AsyncMutexGuard<'a, RecentlySpentOutPoints>)> {
        self.list_unspent_ordered(address).await
    }

    fn get_verbose_transaction_from_cache_or_rpc(&self, txid: H256Json) -> UtxoRpcFut<VerboseTransactionFrom> {
        let selfi = self.clone();
        let fut = async move { utxo_common::get_verbose_transaction_from_cache_or_rpc(&selfi.utxo_arc, txid).await };
        Box::new(fut.boxed().compat())
    }

    async fn cache_transaction_if_possible(&self, tx: &RpcTransaction) -> Result<(), String> {
        utxo_common::cache_transaction_if_possible(&self.utxo_arc, tx).await
    }

    async fn list_unspent_ordered<'a>(
        &'a self,
        address: &Address,
    ) -> UtxoRpcResult<(Vec<UnspentInfo>, AsyncMutexGuard<'a, RecentlySpentOutPoints>)> {
        let (all_unspents, recently_spent) = utxo_common::list_unspent_ordered(self, address).await?;
        let mut filtered_unspents = Vec::with_capacity(all_unspents.len());
        for unspent in all_unspents {
            if !self.should_skip_utxo(&unspent).await? {
                filtered_unspents.push(unspent);
            }
        }
        Ok((filtered_unspents, recently_spent))
    }

    async fn preimage_trade_fee_required_to_send_outputs(
        &self,
        outputs: Vec<TransactionOutput>,
        fee_policy: FeePolicy,
        gas_fee: Option<u64>,
        stage: &FeeApproxStage,
    ) -> TradePreimageResult<BigDecimal> {
        utxo_common::preimage_trade_fee_required_to_send_outputs(self, outputs, fee_policy, gas_fee, stage).await
    }

    fn increase_dynamic_fee_by_stage(&self, dynamic_fee: u64, stage: &FeeApproxStage) -> u64 {
        utxo_common::increase_dynamic_fee_by_stage(self, dynamic_fee, stage)
    }

    async fn p2sh_tx_locktime(&self, htlc_locktime: u32) -> Result<u32, MmError<UtxoRpcError>> {
        utxo_common::p2sh_tx_locktime(self, &self.utxo_arc.conf.ticker, htlc_locktime).await
    }
}

impl SwapOps for BchCoin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: BigDecimal) -> TransactionFut {
        utxo_common::send_taker_fee(self.clone(), fee_addr, amount)
    }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::send_maker_payment(self.clone(), time_lock, taker_pub, secret_hash, amount)
    }

    fn send_taker_payment(
        &self,
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::send_taker_payment(self.clone(), time_lock, maker_pub, secret_hash, amount)
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::send_maker_spends_taker_payment(self.clone(), taker_payment_tx, time_lock, taker_pub, secret)
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::send_taker_spends_maker_payment(self.clone(), maker_payment_tx, time_lock, maker_pub, secret)
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::send_taker_refunds_payment(self.clone(), taker_payment_tx, time_lock, maker_pub, secret_hash)
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::send_maker_refunds_payment(self.clone(), maker_payment_tx, time_lock, taker_pub, secret_hash)
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        expected_sender: &[u8],
        fee_addr: &[u8],
        amount: &BigDecimal,
        min_block_number: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        let tx = match fee_tx {
            TransactionEnum::UtxoTx(tx) => tx.clone(),
            _ => panic!(),
        };
        utxo_common::validate_fee(
            self.clone(),
            tx,
            utxo_common::DEFAULT_FEE_VOUT,
            expected_sender,
            amount,
            min_block_number,
            fee_addr,
        )
    }

    fn validate_maker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::validate_maker_payment(self, payment_tx, time_lock, maker_pub, priv_bn_hash, amount)
    }

    fn validate_taker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::validate_taker_payment(self, payment_tx, time_lock, taker_pub, priv_bn_hash, amount)
    }

    fn check_if_my_payment_sent(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        utxo_common::check_if_my_payment_sent(self.clone(), time_lock, other_pub, secret_hash)
    }

    fn search_for_swap_tx_spend_my(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_my(
            &self.utxo_arc,
            time_lock,
            other_pub,
            secret_hash,
            tx,
            utxo_common::DEFAULT_SWAP_VOUT,
            search_from_block,
        )
    }

    fn search_for_swap_tx_spend_other(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        utxo_common::search_for_swap_tx_spend_other(
            &self.utxo_arc,
            time_lock,
            other_pub,
            secret_hash,
            tx,
            utxo_common::DEFAULT_SWAP_VOUT,
            search_from_block,
        )
    }

    fn extract_secret(&self, secret_hash: &[u8], spend_tx: &[u8]) -> Result<Vec<u8>, String> {
        utxo_common::extract_secret(secret_hash, spend_tx)
    }

    fn can_refund_htlc(&self, locktime: u64) -> Box<dyn Future<Item = CanRefundHtlc, Error = String> + Send + '_> {
        Box::new(
            utxo_common::can_refund_htlc(self, locktime)
                .boxed()
                .map_err(|e| ERRL!("{}", e))
                .compat(),
        )
    }

    fn negotiate_swap_contract_addr(
        &self,
        _other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        Ok(None)
    }
}

impl MarketCoinOps for BchCoin {
    fn ticker(&self) -> &str { &self.utxo_arc.conf.ticker }

    fn my_address(&self) -> Result<String, String> { utxo_common::my_address(self) }

    fn my_balance(&self) -> BalanceFut<CoinBalance> { utxo_common::my_balance(&self.utxo_arc) }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { utxo_common::base_coin_balance(self) }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        utxo_common::send_raw_tx(&self.utxo_arc, tx)
    }

    fn wait_for_confirmations(
        &self,
        tx: &[u8],
        confirmations: u64,
        requires_nota: bool,
        wait_until: u64,
        check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        utxo_common::wait_for_confirmations(
            &self.utxo_arc,
            tx,
            confirmations,
            requires_nota,
            wait_until,
            check_every,
        )
    }

    fn wait_for_tx_spend(
        &self,
        transaction: &[u8],
        wait_until: u64,
        from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        utxo_common::wait_for_output_spend(
            &self.utxo_arc,
            transaction,
            utxo_common::DEFAULT_SWAP_VOUT,
            from_block,
            wait_until,
        )
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        utxo_common::tx_enum_from_bytes(self.as_ref(), bytes)
    }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> {
        utxo_common::current_block(&self.utxo_arc)
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        utxo_common::display_address_from_pubkey_str(self, pubkey)
    }

    fn display_priv_key(&self) -> String { utxo_common::display_priv_key(&self.utxo_arc) }

    fn min_tx_amount(&self) -> BigDecimal { utxo_common::min_tx_amount(self.as_ref()) }

    fn min_trading_vol(&self) -> MmNumber { utxo_common::min_trading_vol(self.as_ref()) }
}

#[async_trait]
impl UtxoStandardOps for BchCoin {
    async fn tx_details_by_hash(
        &self,
        hash: &[u8],
        input_transactions: &mut HistoryUtxoTxMap,
    ) -> Result<TransactionDetails, String> {
        utxo_common::tx_details_by_hash(self, hash, input_transactions).await
    }

    async fn request_tx_history(&self, metrics: MetricsArc) -> RequestTxHistoryResult {
        utxo_common::request_tx_history(self, metrics).await
    }

    async fn update_kmd_rewards(
        &self,
        tx_details: &mut TransactionDetails,
        input_transactions: &mut HistoryUtxoTxMap,
    ) -> UtxoRpcResult<()> {
        utxo_common::update_kmd_rewards(self, tx_details, input_transactions).await
    }
}

impl MmCoin for BchCoin {
    fn is_asset_chain(&self) -> bool { utxo_common::is_asset_chain(&self.utxo_arc) }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut {
        Box::new(utxo_common::withdraw(self.clone(), req).boxed().compat())
    }

    fn decimals(&self) -> u8 { utxo_common::decimals(&self.utxo_arc) }

    fn convert_to_address(&self, from: &str, to_address_format: Json) -> Result<String, String> {
        utxo_common::convert_to_address(self, from, to_address_format)
    }

    fn validate_address(&self, address: &str) -> ValidateAddressResult { utxo_common::validate_address(self, address) }

    fn process_history_loop(&self, ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        Box::new(
            utxo_common::process_history_loop(self.clone(), ctx)
                .map(|_| Ok(()))
                .boxed()
                .compat(),
        )
    }

    fn history_sync_status(&self) -> HistorySyncState { utxo_common::history_sync_status(&self.utxo_arc) }

    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> {
        utxo_common::get_trade_fee(self.clone())
    }

    fn get_sender_trade_fee(&self, value: TradePreimageValue, stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        utxo_common::get_sender_trade_fee(self.clone(), value, stage)
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        utxo_common::get_receiver_trade_fee(self.clone())
    }

    fn get_fee_to_send_taker_fee(
        &self,
        dex_fee_amount: BigDecimal,
        stage: FeeApproxStage,
    ) -> TradePreimageFut<TradeFee> {
        utxo_common::get_fee_to_send_taker_fee(self.clone(), dex_fee_amount, stage)
    }

    fn required_confirmations(&self) -> u64 { utxo_common::required_confirmations(&self.utxo_arc) }

    fn requires_notarization(&self) -> bool { utxo_common::requires_notarization(&self.utxo_arc) }

    fn set_required_confirmations(&self, confirmations: u64) {
        utxo_common::set_required_confirmations(&self.utxo_arc, confirmations)
    }

    fn set_requires_notarization(&self, requires_nota: bool) {
        utxo_common::set_requires_notarization(&self.utxo_arc, requires_nota)
    }

    fn swap_contract_address(&self) -> Option<BytesJson> { utxo_common::swap_contract_address() }

    fn mature_confirmations(&self) -> Option<u32> { Some(self.utxo_arc.conf.mature_confirmations) }
}

// testnet
#[cfg(test)]
pub fn tbch_coin_for_test() -> BchCoin {
    use common::block_on;
    use common::mm_ctx::MmCtxBuilder;
    use common::privkey::key_pair_from_seed;

    let ctx = MmCtxBuilder::default().into_mm_arc();
    let keypair = key_pair_from_seed("BCH SLP test").unwrap();

    let conf = json!({"coin":"BCH","pubtype":0,"p2shtype":5,"mm2":1,"fork_id":"0x40","protocol":{"type":"UTXO"},
         "address_format":{"format":"cashaddress","network":"bchtest"}});
    let req = json!({
        "method": "electrum",
        "coin": "BCH",
        "servers": [{"url":"blackie.c3-soft.com:60001"},{"url":"testnet.imaginary.cash:50001"},{"url":"tbch.loping.net:60001"}],
    });
    block_on(bch_coin_from_conf_and_request(
        &ctx,
        "BCH",
        &conf,
        &req,
        CashAddrPrefix::SlpTest,
        &*keypair.private().secret,
    ))
    .unwrap()
}

// mainnet
#[cfg(test)]
pub fn bch_coin_for_test() -> BchCoin {
    use common::block_on;
    use common::mm_ctx::MmCtxBuilder;
    use common::privkey::key_pair_from_seed;

    let ctx = MmCtxBuilder::default().into_mm_arc();
    let keypair = key_pair_from_seed("BCH SLP test").unwrap();

    let conf = json!({"coin":"BCH","pubtype":0,"p2shtype":5,"mm2":1,"fork_id":"0x40","protocol":{"type":"UTXO"},
         "address_format":{"format":"cashaddress","network":"bitcoincash"}});
    let req = json!({
        "method": "electrum",
        "coin": "BCH",
        "servers": [{"url":"electrum1.cipig.net:10055"},{"url":"electrum2.cipig.net:10055"},{"url":"electrum3.cipig.net:10055"}],
    });
    block_on(bch_coin_from_conf_and_request(
        &ctx,
        "BCH",
        &conf,
        &req,
        CashAddrPrefix::SimpleLedger,
        &*keypair.private().secret,
    ))
    .unwrap()
}

#[cfg(test)]
mod bch_tests {
    use super::{bch_coin_for_test, tbch_coin_for_test};
    use crate::utxo::rpc_clients::UnspentInfo;
    use chain::OutPoint;
    use common::block_on;
    use keys::hash::H256;

    #[test]
    fn test_is_slp_utxo() {
        let tbch = tbch_coin_for_test();
        let unspent_zero_index = UnspentInfo {
            outpoint: OutPoint::default(),
            value: 0,
            height: None,
        };

        let is_slp = block_on(tbch.should_skip_utxo(&unspent_zero_index)).unwrap();
        assert!(!is_slp);

        let unspent_is_slp = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("e935160bfb5b45007a0fc6f8fbe8da618f28df6573731f1ffb54d9560abb49b2"),
                index: 1,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(tbch.should_skip_utxo(&unspent_is_slp)).unwrap();
        assert!(is_slp);

        let unspent_is_slp_change = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("e935160bfb5b45007a0fc6f8fbe8da618f28df6573731f1ffb54d9560abb49b2"),
                index: 2,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(tbch.should_skip_utxo(&unspent_is_slp_change)).unwrap();
        assert!(is_slp);

        let unspent_is_bch_change = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("e935160bfb5b45007a0fc6f8fbe8da618f28df6573731f1ffb54d9560abb49b2"),
                index: 3,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(tbch.should_skip_utxo(&unspent_is_bch_change)).unwrap();
        assert!(!is_slp);

        let fusd_genesis = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("bb309e48930671582bea508f9a1d9b491e49b69be3d6f372dc08da2ac6e90eb7"),
                index: 1,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(tbch.should_skip_utxo(&fusd_genesis)).unwrap();
        assert!(is_slp);

        let bch_main = bch_coin_for_test();
        let usdt_genesis = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35"),
                index: 1,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(bch_main.should_skip_utxo(&usdt_genesis)).unwrap();
        assert!(is_slp);

        let usdt_baton = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35"),
                index: 2,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(bch_main.should_skip_utxo(&usdt_baton)).unwrap();
        assert!(is_slp);

        let usdt_bch_change = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("550d19eb820e616a54b8a73372c4420b5a0567d8dc00f613b71c5234dc884b35"),
                index: 3,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(bch_main.should_skip_utxo(&usdt_bch_change)).unwrap();
        assert!(!is_slp);

        let usdt_mint = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("b36b0c7485ad569b98cc9b9614dc68a5208495f22ec3b00effcf963b135a5215"),
                index: 1,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(bch_main.should_skip_utxo(&usdt_mint)).unwrap();
        assert!(is_slp);

        let usdt_mint_baton = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("b36b0c7485ad569b98cc9b9614dc68a5208495f22ec3b00effcf963b135a5215"),
                index: 2,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(bch_main.should_skip_utxo(&usdt_mint_baton)).unwrap();
        assert!(is_slp);

        let usdt_mint_bch_change = UnspentInfo {
            outpoint: OutPoint {
                hash: H256::from_reversed_str("b36b0c7485ad569b98cc9b9614dc68a5208495f22ec3b00effcf963b135a5215"),
                index: 3,
            },
            value: 0,
            height: None,
        };

        let is_slp = block_on(bch_main.should_skip_utxo(&usdt_mint_bch_change)).unwrap();
        assert!(!is_slp);
    }
}
