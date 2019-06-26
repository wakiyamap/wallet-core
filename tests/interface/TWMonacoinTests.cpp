// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "TWTestUtilities.h"

#include <TrustWalletCore/TWSegwitAddress.h>
#include <TrustWalletCore/TWBitcoinAddress.h>
#include <TrustWalletCore/TWBitcoinScript.h>
#include <TrustWalletCore/TWHash.h>
#include <TrustWalletCore/TWHDWallet.h>
#include <TrustWalletCore/TWHRP.h>
#include <TrustWalletCore/TWPrivateKey.h>

#include <gtest/gtest.h>

TEST(Monacoin, LegacyAddress) {
    auto privateKey = WRAP(TWPrivateKey, TWPrivateKeyCreateWithData(DATA("a22ddec5c567b4488bb00f69b6146c50da2ee883e2c096db098726394d585730").get()));
    auto publicKey = TWPrivateKeyGetPublicKeySecp256k1(privateKey.get(), true);
    auto address = TWBitcoinAddressCreateWithPublicKey(publicKey, TWCoinTypeP2pkhPrefix(TWCoinTypeMonacoin));
    auto addressString = WRAPS(TWBitcoinAddressDescription(address));
    assertStringsEqual(addressString, "MHnYTL9e1s8zNR2qzzJ3mMHfgjnUzyMscd");
}

TEST(Monacoin, Address) {
    auto privateKey = WRAP(TWPrivateKey, TWPrivateKeyCreateWithData(DATA("55f9cbb0376c422946fa28397c1219933ac60b312ede41bfacaf701ecd546625").get()));
    auto publicKey = TWPrivateKeyGetPublicKeySecp256k1(privateKey.get(), true);
    auto address = WRAP(TWSegwitAddress, TWSegwitAddressCreateWithPublicKey(TWHRPMonacoin, publicKey));
    auto string = WRAPS(TWSegwitAddressDescription(address.get()));

    assertStringsEqual(string, "mona1qytnqzjknvv03jwfgrsmzt0ycmwqgl0asju3qmd");
}

TEST(Monacoin, BuildForAddressM) {
    auto script = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("MFMy9FwJsV6HiN5eZDqDETw4pw52q3UGrb").get(), TWCoinTypeMonacoin));
    auto scriptData = WRAPD(TWBitcoinScriptData(script.get()));
    assertHexEqual(scriptData, "76a91451dadacc7021440cbe4ca148a5db563b329b4c0388ac");
}

TEST(Monacoin, BuildForAddressP) {
    auto script = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("PHjTKtgYLTJ9D2Bzw2f6xBB41KBm2HeGfg").get(), TWCoinTypeMonacoin));
    auto scriptData = WRAPD(TWBitcoinScriptData(script.get()));
    assertHexEqual(scriptData, "a9146449f568c9cd2378138f2636e1567112a184a9e887");
}

TEST(Monacoin, ExtendedKeys) {
    auto wallet = WRAP(TWHDWallet, TWHDWalletCreateWithMnemonic(
        STRING("ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal").get(),
        STRING("TREZOR").get()
    ));

    // .bip44
    auto xprv = WRAPS(TWHDWalletGetExtendedPrivateKey(wallet.get(), TWPurposeBIP44, TWCoinTypeMonacoin, TWHDVersionXPRV));
    auto xpub = WRAPS(TWHDWalletGetExtendedPublicKey(wallet.get(), TWPurposeBIP44, TWCoinTypeMonacoin, TWHDVersionXPUB));

    assertStringsEqual(xprv, "xprv9yZ9qiUHr5eCpSp87jUR4KBHA1rhLx8fqSMGHK9CTfUgwt1QwYdwh9Csf7BsUWT53CDWdcYVFaqYF79QDYJ9NsoM6RE5nTz9VvLBCntdbTQ");
    assertStringsEqual(xpub, "xpub6CYWFE1BgTCW2vtbDm1RRT81i3hBkQrXCfGs5hYp211fpgLZV5xCEwXMWPAL3LgaBA9koXpLZSUo7rTyJ8q1JwqKhvzVpdzBKRGyyGb31KF");

    // .bip49
    auto yprv = WRAPS(TWHDWalletGetExtendedPrivateKey(wallet.get(), TWPurposeBIP49, TWCoinTypeMonacoin, TWHDVersionYPRV));
    auto ypub = WRAPS(TWHDWalletGetExtendedPublicKey(wallet.get(), TWPurposeBIP49, TWCoinTypeMonacoin, TWHDVersionYPUB));

    assertStringsEqual(yprv, "yprvAKLGJBFEsPizw5w8vvS1cVjuYd9am9nL8E1sd5NaaiSkDZ7sLfA7W3cRiGywGEBy51nFmn3pbmHvUyn1sqD2ZXx3xgXvEd22LnBAPaTJtz4");
    assertStringsEqual(ypub, "ypub6YKchgn8hmHJ9a1c2wy1ydge6ez5AcWBVSwURTnC93yj6MT1tCUN3qvuZZPsA1CwZVh5qEGhMWhDZEK43jQqWtHBzME91ws9KD6WU9n8Nau");

    // .bip84
    auto zprv = WRAPS(TWHDWalletGetExtendedPrivateKey(wallet.get(), TWPurposeBIP84, TWCoinTypeMonacoin, TWHDVersionZPRV));
    auto zpub = WRAPS(TWHDWalletGetExtendedPublicKey(wallet.get(), TWPurposeBIP84, TWCoinTypeMonacoin, TWHDVersionZPUB));
    assertStringsEqual(zprv, "zprvAdQQxghvhQnbhhP6sAymw5uMrU8hAmcp8JB9cFkvLDhBNY64Sxuw4EAZEAdMgD7hiEXxwhr7zGqoPWYd2f6zCABBCv6UpXsp6dTJgpckG95");
    assertStringsEqual(zpub, "zpub6rPmNCEpXnLtvBTZyCWnJDr6QVyBaELfVX6kQeAXtZEAFLRCzWEBc2V35UHUQKJh1SpSNCtAtCx8KhRg5AWFnKrMCsxX4J2Zee21FQ5YS4n");
}

TEST(Monacoin, DeriveFromZpub) {
    auto zpub = STRING("zpub6sCFp8chadVDXVt7GRmQFpq8B7W8wMLdFDto1hXu2jLZtvkFhRnwScXARNfrGSeyhR8DBLJnaUUkBbkmB2GwUYkecEAMUcbUpFQV4v7PXcs");
    auto pubKey4 = TWHDWalletGetPublicKeyFromExtended(zpub.get(), STRING("m/44'/22'/0'/0/4").get());
    auto pubKey11 = TWHDWalletGetPublicKeyFromExtended(zpub.get(), STRING("m/44'/22'/0'/0/11").get());

    auto address4 = WRAP(TWSegwitAddress, TWSegwitAddressCreateWithPublicKey(TWHRPMonacoin, pubKey4));
    auto address4String = WRAPS(TWSegwitAddressDescription(address4.get()));

    auto address11 = WRAP(TWSegwitAddress, TWSegwitAddressCreateWithPublicKey(TWHRPMonacoin, pubKey11));
    auto address11String = WRAPS(TWSegwitAddressDescription(address11.get()));

    assertStringsEqual(address4String, "mona1qcgnevr9rp7aazy62m4gen0tfzlssa52axpgd7t");
    assertStringsEqual(address11String, "mona1qy072y8968nzp6mz3j292h8lp72d678fcm5uuew");
}

TEST(Monacoin, LockScripts) {
    auto script = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("mona1qw508d6qejxtdg4y5r3zarvary0c5xw7kg5lnx5").get(), TWCoinTypeMonacoin));
    auto scriptData = WRAPD(TWBitcoinScriptData(script.get()));
    assertHexEqual(scriptData, "0014751e76e8199196d454941c45d1b3a323f1433bd6");

    auto script2 = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("PCTzdjWauNipkYtToRZEHDMXb2adj9Evp8").get(), TWCoinTypeMonacoin));
    auto scriptData2 = WRAPD(TWBitcoinScriptData(script2.get()));
    assertHexEqual(scriptData2, "a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487");

    auto script3 = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("MBamfEqEFDy5dsLWwu48BCizM1zpCoKw3U").get(), TWCoinTypeMonacoin));
    auto scriptData3 = WRAPD(TWBitcoinScriptData(script3.get()));
    assertHexEqual(scriptData3, "76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac");
}
