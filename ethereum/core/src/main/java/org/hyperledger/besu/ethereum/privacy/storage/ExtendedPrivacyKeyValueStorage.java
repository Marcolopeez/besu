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
  public Optional<Bytes> getPrivateSetByContractAddress(final Bytes contractAddress) {
    return get(contractAddress);
  }

  @Override
  public Optional<Bytes> getBetaByContractAddress_Beta(final Bytes contractAddress_Beta) {
    return get(contractAddress_Beta);
  }

  @Override
  public Optional<Bytes> getAliceAddressByContractAddress_Alice(final Bytes contractAddress_Alice) {
    return get(contractAddress_Alice);
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
    public ExtendedPrivacyStorage.Updater putPrivateSetByContractAddress(
            final Bytes contractAddress, final Bytes privateSet) {
      set(contractAddress, privateSet);
      return this;
    }

    @Override
    public ExtendedPrivacyStorage.Updater putBetaByContractAddress_Beta(
            final Bytes contractAddress_Beta, final Bytes beta) {
      set(contractAddress_Beta, beta);
      return this;
    }

    @Override
    public ExtendedPrivacyStorage.Updater putAliceAddressByContractAddress_Alice(
            final Bytes contractAddress_Alice, final Bytes aliceAddress) {
      set(contractAddress_Alice, aliceAddress);
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