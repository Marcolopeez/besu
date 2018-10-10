package net.consensys.pantheon.controller;

import net.consensys.pantheon.crypto.SECP256K1;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyPairUtil {
  private static final Logger LOG = LogManager.getLogger();

  public static SECP256K1.KeyPair loadKeyPair(final Path home) throws IOException {
    final File keyFile = home.resolve("key").toFile();
    final SECP256K1.KeyPair key;
    if (keyFile.exists()) {
      key = SECP256K1.KeyPair.load(keyFile);
      LOG.info("Loaded key {} from {}", key.getPublicKey().toString(), keyFile.getAbsolutePath());
    } else {
      key = SECP256K1.KeyPair.generate();
      key.getPrivateKey().store(keyFile);
      LOG.info(
          "Generated new key key {} and stored it to {}",
          key.getPublicKey().toString(),
          keyFile.getAbsolutePath());
    }
    return key;
  }
}
