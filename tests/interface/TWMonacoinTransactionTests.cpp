
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
#include <iostream>
#include <TrustWalletCore/TWBitcoinScript.h>
#include <TrustWalletCore/TWHDWallet.h>

#include <gtest/gtest.h>

using namespace TW;
using namespace Bitcoin;

TEST(MonacoinTransaction, SignTransaction) {
    /*
        https://iancoleman.io/bip39/
        Mnemonic - perfect runway tissue hover click expire orbit subway insane joy husband circle
        m/44'/22'/0'/0/0 Address - MX7ZpcMMN4GVDeUvCjAYwfRyMgfBzYNr3E
        m/44'/22'/0'/0/0 Private key in Base58 encoding - T8XV834egE6ZsgsQFPnBcYbNdFKNiGKiNj21mRjGx2scGNQh3ypZ
        m/44'/22'/0'/0/0 Private key in bytes - a356a193a24c73c657e0c7bbf4e876964984a2dcba986ea1ea1fca7b025218f3
        utxo - https://blockbook.electrum-mona.org/tx/167b642212c700a529d5d5fedd8ff9ec8641cb55a1806c007095102793b43286
        tx - https://blockbook.electrum-mona.org/tx/cc01c378c9ce1c8218b1c311796eabc2c89b59fe535cd50d645ddb99eeba5593
    */

    const int64_t utxo_amount = 100000000;
    const int64_t amount = 50000000;
    const int64_t fee = 448000;

    auto input = Bitcoin::Proto::SigningInput();
    input.set_hash_type(TWSignatureHashTypeAll);
    input.set_amount(amount);
    input.set_byte_fee(1);
    input.set_to_address("M8aShwteMWyAbUw4SGS4EHLqfo1EfnKHcM");
    input.set_change_address("PDYLyFayFWSTjZZnxRKGDmmrrEpkpN1Nfq");
    input.set_coin_type(TWCoinTypeMonacoin);

    auto hash0 = DATA("8632b49327109570006c80a155cb4186ecf98fddfed5d529a500c71222647b16");
    auto utxo0 = input.add_utxo();
    utxo0->mutable_out_point()->set_hash(TWDataBytes(hash0.get()), TWDataSize(hash0.get()));
    utxo0->mutable_out_point()->set_index(0);
    utxo0->mutable_out_point()->set_sequence(UINT32_MAX);
    utxo0->set_amount(utxo_amount);
    auto script0 = parse_hex("76a914076df984229a2731cbf465ec8fbd35b8da94380f88ac");
    utxo0->set_script(script0.data(), script0.size());

    auto utxoKey0 = DATA("a356a193a24c73c657e0c7bbf4e876964984a2dcba986ea1ea1fca7b025218f3");
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
        "02000000018632b49327109570006c80a155cb4186ecf98fddfed5d529a500c71222647b16000000006a47304402200511e81368a1c2f78815b4b6c531f88d238db7581daea67b0c55db145a7f2067022017647df16b3ea0434182bbcaa06c7bc397c933351bdcf25ae4a68dc4c58ade09012102fc08693599fda741558613cd44a50fc65953b1be797637f8790a495b85554f3efeffffff0280f0fa02000000001976a914076df984229a2731cbf465ec8fbd35b8da94380f88ac801af4020000000017a914364f93064cc3bd63811b540fc7a93562acef49b987fcf91900"
    ); 
}

TEST(MonacoinTransaction, LockScripts) {
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

    // BECH32
    // https://blockbook.electrum-mona.org/tx/6d7ebe444cc12c14625fa526ed9d81058b04d2f0c3b5dad2fb0032eeec3ba511
    
    auto script3 = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("mona1qytnqzjknvv03jwfgrsmzt0ycmwqgl0asju3qmd").get(), TWCoinTypeMonacoin));
    auto scriptData3 = WRAPD(TWBitcoinScriptData(script3.get()));
    assertHexEqual(scriptData3, "001422e6014ad3631f1939281c3625bc98db808fbfb0");
}
