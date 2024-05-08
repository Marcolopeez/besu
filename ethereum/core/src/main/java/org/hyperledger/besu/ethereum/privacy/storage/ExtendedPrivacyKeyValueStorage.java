package org.hyperledger.besu.ethereum.privacy.storage;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorage;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorageTransaction;

public class ExtendedPrivacyKeyValueStorage implements ExtendedPrivacyStorage {
  private final KeyValueStorage keyValueStorage;

  public ExtendedPrivacyKeyValueStorage(final KeyValueStorage keyValueStorage) {
    this.keyValueStorage = keyValueStorage;
  }

  @Override
  public Optional<Bytes> getPrivateArgsByPmt(final Bytes pmt) {
    return get(pmt);
  }

  @Override
  public Optional<Bytes> getPmtByContractAddress(final Bytes contractAddress) {
    return get(contractAddress);
  }

  @Override
  public Optional<Bytes> getBetaByContractAddress_Beta(final Bytes contractAddress_Beta) {
    return get(contractAddress_Beta);
  }

  private Optional<Bytes> get(final Bytes key) {
    return keyValueStorage.get(key.toArray()).map(Bytes::wrap);
  }

  @Override
  public ExtendedPrivacyStorage.Updater updater() {
    return new ExtendedPrivacyKeyValueStorage.Updater(keyValueStorage.startTransaction());
  }

  public static class Updater implements ExtendedPrivacyStorage.Updater {

    private final KeyValueStorageTransaction transaction;

    private Updater(final KeyValueStorageTransaction transaction) {
      this.transaction = transaction;
    }

    @Override
    public ExtendedPrivacyStorage.Updater putPrivateArgsByPmt(
            final Bytes pmt, final Bytes privateArgs) {
      set(pmt, privateArgs);
      return this;
    }

    @Override
    public ExtendedPrivacyStorage.Updater putPmtByContractAddress(
            final Bytes contractAddress, final Bytes pmt) {
      set(contractAddress, pmt);
      return this;
    }

    @Override
    public ExtendedPrivacyStorage.Updater putBetaByContractAddress_Beta(
            final Bytes contractAddress_Beta, final Bytes beta) {
      set(contractAddress_Beta, beta);
      return this;
    }

    @Override
    public void commit() {
      transaction.commit();
    }

    @Override
    public void rollback() {
      transaction.rollback();
    }

    private void set(final Bytes key, final Bytes value) {
      transaction.put(key.toArray(), value.toArray());
    }

    @Override
    public void remove(final Bytes key) {
      transaction.remove(key.toArray());
    }

  }

}