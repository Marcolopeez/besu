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
  public Optional<Bytes> getPrivateArgs(final Bytes key) {
    return get(key);
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
    public ExtendedPrivacyStorage.Updater putPrivateArgs(
            final Bytes key, final Bytes privateArgs) {
      set(key, privateArgs);
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

    private void set(final Bytes key, final Bytes privateArgs) {
      transaction.put(key.toArray(), privateArgs.toArray());
    }

    @Override
    public void remove(final Bytes key) {
      transaction.remove(key.toArray());
    }

  }

}