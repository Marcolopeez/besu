package org.hyperledger.besu.ethereum.privacy.storage;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;

public interface ExtendedPrivacyStorage {
  Optional<Bytes> getPrivateArgsByPmt(Bytes pmt);
  Optional<Bytes> getPmtByContractAddress(Bytes contractAddress);

  Updater updater();

  interface Updater {

    Updater putPrivateArgsByPmt(
            Bytes pmt, Bytes privateArgs);

    Updater putPmtByContractAddress(
            Bytes contractAddress, Bytes pmt);

    void commit();

    void rollback();

    void remove(final Bytes key);

  }
}
