package org.hyperledger.besu.ethereum.privacy.storage;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

public interface ExtendedPrivacyStorage {
  Optional<Bytes> getPrivateSetByContractAddress(Bytes contractAddress);
  Optional<Bytes> getBetaByContractAddress_Beta(Bytes contractAddress_Beta);
  Optional<Bytes> getAliceAddressByContractAddress_Alice(Bytes contractAddress_Alice);

  Updater updater();

  interface Updater {

    Updater putPrivateSetByContractAddress(
            Bytes contractAddress, Bytes privateArgs);

    Updater putBetaByContractAddress_Beta(
            Bytes contractAddress_Beta, Bytes beta);

    Updater putAliceAddressByContractAddress_Alice(
            Bytes contractAddress_Alice, Bytes aliceAddress);

    void commit();

    void rollback();

    void remove(final Bytes key);

  }
}
