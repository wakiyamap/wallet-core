
// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "TWTestUtilities.h"

#include "Bitcoin/OutPoint.h"
#include "Bitcoin/TransactionBuilder.h"
#include "Bitcoin/TransactionSigner.h"
#include "HexCoding.h"
#include "PublicKey.h"

#include <TrustWalletCore/TWBitcoinScript.h>
#include <TrustWalletCore/TWHDWallet.h>

#include <gtest/gtest.h>

using namespace TW;
using namespace Bitcoin;

TEST(RavencoinTransaction, SignTransaction) {
    /*
        https://iancoleman.io/bip39/
        Mnemonic - raccoon slide close budget swarm benefit remind hard october coffee smoke whip
        m/44'/22'/0'/0/0 Address - M8aShwteMWyAbUw4SGS4EHLqfo1EfnKHcM
        m/44'/22'/0'/0/0 Private key in Base58 encoding - T6qjeygF1RubAq6wvd36U3hqgoBbW96tJEfTgEiGdEpWmwCuc5Lr
        m/44'/22'/0'/0/0 Private key in bytes - 3e2ef03dbc272adea81284a9c12034e878f3bb5a95e08f4c06639f000374d79c
        utxo - https://blockbook.electrum-mona.org/tx/3e2ef03dbc272adea81284a9c12034e878f3bb5a95e08f4c06639f000374d79c
        tx - https://blockbook.electrum-mona.org/tx/79ebdce15e4ac933328e62dbe92302fc8b4833786e46df8a4f18295cb824fb67
    */

    const int64_t utxo_amount = 100000000;
    const int64_t amount = 50000000;
    const int64_t fee = 40000;

    auto input = Bitcoin::Proto::SigningInput();
    input.set_hash_type(TWSignatureHashTypeAll);
    input.set_amount(amount);
    input.set_byte_fee(1);
    input.set_to_address("M9xFZzZdZhCDxpx42cM8bQHnLwaeX1aNja");
    input.set_change_address("M8aShwteMWyAbUw4SGS4EHLqfo1EfnKHcM");
    input.set_coin_type(TWCoinTypeMonacoin);

    auto hash0 = DATA("9cd77403009f63064c8fe0955abbf378e83420c1a98412a8de2a27bc3df02e3e");
    auto utxo0 = input.add_utxo();
    utxo0->mutable_out_point()->set_hash(TWDataBytes(hash0.get()), TWDataSize(hash0.get()));
    utxo0->mutable_out_point()->set_index(0);
    utxo0->mutable_out_point()->set_sequence(UINT32_MAX);
    utxo0->set_amount(utxo_amount);
    auto script0 = parse_hex("76a9141685f46de8e94513da024c36c42cb6a9b5704ef188ac");
    utxo0->set_script(script0.data(), script0.size());

    auto utxoKey0 = DATA("3e2ef03dbc272adea81284a9c12034e878f3bb5a95e08f4c06639f000374d79c");
    input.add_private_key(TWDataBytes(utxoKey0.get()), TWDataSize(utxoKey0.get()));

    auto plan = Bitcoin::TransactionBuilder::plan(input);
    plan.amount = amount;
    plan.fee = fee;
    plan.change = utxo_amount - amount - fee;

    // Sign
    auto signer = TW::Bitcoin::TransactionSigner<TW::Bitcoin::Transaction>(std::move(input), plan);
    auto result = signer.sign();
    auto signedTx = result.payload();

    ASSERT_TRUE(result);
    ASSERT_EQ(fee, signer.plan.fee);

    Data serialized;
    signedTx.encode(false, serialized);
    ASSERT_EQ(
        hex(serialized),
        "02000000019cd77403009f63064c8fe0955abbf378e83420c1a98412a8de2a27bc3df02e3e000000006a473044022003ecf5c1d603743c5941684535fe1e9f6f4c15012c0193f22c4c77d758aea0e802205e9b675485adcee5d77260d69ad818a7b375f91738dffc3fc44ff2f6b2b0b8b7012102a5ab59fed49c92b5fe6f46e445ad9a6ac1410d7114d31917b286e65c942f3239feffffff024054fa02000000001976a914076df984229a2731cbf465ec8fbd35b8da94380f88ac80f0fa02000000001976a9141685f46de8e94513da024c36c42cb6a9b5704ef188ac5ef91900"
    ); 
}

TEST(RavencoinTransaction, LockScripts) {
    // P2PKH    
    // https://blockbook.electrum-mona.org/tx/79ebdce15e4ac933328e62dbe92302fc8b4833786e46df8a4f18295cb824fb67
    
    auto script = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("M8aShwteMWyAbUw4SGS4EHLqfo1EfnKHcM").get(), TWCoinTypeMonacoin));
    auto scriptData = WRAPD(TWBitcoinScriptData(script.get()));
    assertHexEqual(scriptData, "76a914076df984229a2731cbf465ec8fbd35b8da94380f88ac");

    // P2SH
    // https://blockbook.electrum-mona.org/tx/726ae7d5179bfd8c7d51a5b956c3d6a262fe5190c36ed7bcb3799dc5759d5830
    
    auto script2 = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("P91UYtoBS4XAD39fEzaeMaq7YmMa42FFNd").get(), TWCoinTypeMonacoin));
    auto scriptData2 = WRAPD(TWBitcoinScriptData(script2.get()));
    assertHexEqual(scriptData2, "a914049880fc73bb6a5e0140404713cabe2592fb2c5587");

    // P2WPKH
    // https://blockbook.electrum-mona.org/tx/6d7ebe444cc12c14625fa526ed9d81058b04d2f0c3b5dad2fb0032eeec3ba511
    
    auto script2 = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("mona1qytnqzjknvv03jwfgrsmzt0ycmwqgl0asju3qmd").get(), TWCoinTypeMonacoin));
    auto scriptData2 = WRAPD(TWBitcoinScriptData(script2.get()));
    assertHexEqual(scriptData2, "001422e6014ad3631f1939281c3625bc98db808fbfb0");
}
