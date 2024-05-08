/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.mainnet.precompiles.privacy;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import static org.hyperledger.besu.datatypes.Hash.fromPlugin;
import static org.hyperledger.besu.ethereum.mainnet.PrivateStateUtils.KEY_IS_PERSISTING_PRIVATE_STATE;
import static org.hyperledger.besu.ethereum.mainnet.PrivateStateUtils.KEY_PRIVATE_METADATA_UPDATER;
import static org.hyperledger.besu.ethereum.mainnet.PrivateStateUtils.KEY_TRANSACTION_HASH;
import static org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver.EMPTY_ROOT_HASH;

import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.EnclaveClientException;
import org.hyperledger.besu.enclave.EnclaveConfigurationException;
import org.hyperledger.besu.enclave.EnclaveIOException;
import org.hyperledger.besu.enclave.EnclaveServerException;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.ProcessableBlockHeader;
import org.hyperledger.besu.ethereum.privacy.PrivateStateGenesisAllocator;
import org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionProcessor;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionReceipt;
import org.hyperledger.besu.ethereum.privacy.storage.ExtendedPrivacyStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateMetadataUpdater;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;
import org.hyperledger.besu.evm.Gas;
import org.hyperledger.besu.evm.account.EvmAccount;
import org.hyperledger.besu.evm.account.MutableAccount;
import org.hyperledger.besu.evm.frame.BlockValues;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.AbstractPrecompiledContract;
import org.hyperledger.besu.evm.tracing.OperationTracer;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.plugin.data.Hash;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.google.common.base.Splitter;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PrivacyPrecompiledContract extends AbstractPrecompiledContract {
  private final Enclave enclave;
  final WorldStateArchive privateWorldStateArchive;
  final PrivateStateRootResolver privateStateRootResolver;
  private final PrivateStateGenesisAllocator privateStateGenesisAllocator;
  PrivateTransactionProcessor privateTransactionProcessor;

  private final ExtendedPrivacyStorage extendedPrivacyStorage;
  private PrivateTransaction lastPrivateTransaction;

  private static final Logger LOG = LoggerFactory.getLogger(PrivacyPrecompiledContract.class);

  public PrivacyPrecompiledContract(
      final GasCalculator gasCalculator,
      final PrivacyParameters privacyParameters,
      final String name) {
    this(
        gasCalculator,
        privacyParameters.getEnclave(),
        privacyParameters.getPrivateWorldStateArchive(),
        privacyParameters.getPrivateStateRootResolver(),
        privacyParameters.getPrivateStateGenesisAllocator(),
        name,
        privacyParameters.getExtendedPrivacyStorage());
  }

  protected PrivacyPrecompiledContract(
      final GasCalculator gasCalculator,
      final Enclave enclave,
      final WorldStateArchive worldStateArchive,
      final PrivateStateRootResolver privateStateRootResolver,
      final PrivateStateGenesisAllocator privateStateGenesisAllocator,
      final String name) {
    super(name, gasCalculator);
    this.enclave = enclave;
    this.privateWorldStateArchive = worldStateArchive;
    this.privateStateRootResolver = privateStateRootResolver;
    this.privateStateGenesisAllocator = privateStateGenesisAllocator;
    this.extendedPrivacyStorage = null;
    lastPrivateTransaction = new PrivateTransaction.Builder().build();
  }

  protected PrivacyPrecompiledContract(
          final GasCalculator gasCalculator,
          final Enclave enclave,
          final WorldStateArchive worldStateArchive,
          final PrivateStateRootResolver privateStateRootResolver,
          final PrivateStateGenesisAllocator privateStateGenesisAllocator,
          final String name,
          final ExtendedPrivacyStorage extendedPrivacyStorage) {
    super(name, gasCalculator);
    this.enclave = enclave;
    this.privateWorldStateArchive = worldStateArchive;
    this.privateStateRootResolver = privateStateRootResolver;
    this.privateStateGenesisAllocator = privateStateGenesisAllocator;
    this.extendedPrivacyStorage = extendedPrivacyStorage;
  }

  public void setPrivateTransactionProcessor(
      final PrivateTransactionProcessor privateTransactionProcessor) {
    this.privateTransactionProcessor = privateTransactionProcessor;
  }

  @Override
  public Gas gasRequirement(final Bytes input) {
    return Gas.of(0L);
  }

  @Override
  public Bytes compute(final Bytes input, final MessageFrame messageFrame) {
    if (skipContractExecution(messageFrame)) {
      return Bytes.EMPTY;
    }

    final org.hyperledger.besu.plugin.data.Hash pmtHash =
        messageFrame.getContextVariable(KEY_TRANSACTION_HASH);

    final String key = input.toBase64String();
    final ReceiveResponse receiveResponse;
    try {
      receiveResponse = getReceiveResponse(key);
    } catch (final EnclaveClientException e) {
      LOG.debug("Can not fetch private transaction payload with key {}", key, e);
      return Bytes.EMPTY;
    }

    final BytesValueRLPInput bytesValueRLPInput =
        new BytesValueRLPInput(
            Bytes.wrap(Base64.getDecoder().decode(receiveResponse.getPayload())), false);
    final PrivateTransaction privateTransaction =
        PrivateTransaction.readFrom(bytesValueRLPInput.readAsRlp());

    final Bytes privateFrom = privateTransaction.getPrivateFrom();
    if (!privateFromMatchesSenderKey(privateFrom, receiveResponse.getSenderKey())) {
      return Bytes.EMPTY;
    }

    final Bytes32 privacyGroupId =
        Bytes32.wrap(Bytes.fromBase64String(receiveResponse.getPrivacyGroupId()));

    try {
      if (privateTransaction.getPrivateFor().isEmpty()
          && !enclave
              .retrievePrivacyGroup(privacyGroupId.toBase64String())
              .getMembers()
              .contains(privateFrom.toBase64String())) {
        return Bytes.EMPTY;
      }
    } catch (final EnclaveClientException e) {
      // This exception is thrown when the privacy group can not be found
      return Bytes.EMPTY;
    } catch (final EnclaveServerException e) {
      throw new IllegalStateException(
          "Enclave is responding with an error, perhaps it has a misconfiguration?", e);
    } catch (final EnclaveIOException e) {
      throw new IllegalStateException("Can not communicate with enclave, is it up?", e);
    }

    LOG.debug("Processing private transaction {} in privacy group {}", pmtHash, privacyGroupId);

    final PrivateMetadataUpdater privateMetadataUpdater =
        messageFrame.getContextVariable(KEY_PRIVATE_METADATA_UPDATER);
    final Hash lastRootHash =
        privateStateRootResolver.resolveLastStateRoot(privacyGroupId, privateMetadataUpdater);

    final MutableWorldState disposablePrivateState =
        privateWorldStateArchive.getMutable(fromPlugin(lastRootHash), null).get();

    final WorldUpdater privateWorldStateUpdater = disposablePrivateState.updater();

    maybeApplyGenesisToPrivateWorldState(
        lastRootHash,
        disposablePrivateState,
        privateWorldStateUpdater,
        privacyGroupId,
        messageFrame.getBlockValues().getNumber());

    if (privateTransaction.hasExtendedPrivacy()) {
      if(!privateTransaction.equals(lastPrivateTransaction)){
        lastPrivateTransaction = privateTransaction;
        String extendedPrivacy = privateTransaction.getExtendedPrivacy().get().toHexString();
        LOG.info("[PrivacyPrecompileContract] Transaction hasExtendedPrivacy: {}", extendedPrivacy);
        Optional<Bytes> privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(Bytes.wrap(key.getBytes(Charset.forName("UTF-8"))));

        if(extendedPrivacy.equals("0x01")){
          if (privateTransaction.isContractCreation() && privArgs.isPresent()) {
            // Client deploying contract
            final Address privateContractAddress = getPrivateContractAddress(privateTransaction.getSender(), privateWorldStateUpdater, privacyGroupId);
            ExtendedPrivacyStorage.Updater updater = extendedPrivacyStorage.updater();
            updater.putPmtByContractAddress(privateContractAddress, Bytes.wrap(key.getBytes(Charset.forName("UTF-8"))));
            updater.commit();
            //LOG.info("[PrivacyPrecompiledContract] Contract-Key: ({}, {})", privateContractAddress.toString(), key);
          } else if (!privateTransaction.isContractCreation()) {
            if (privArgs.isPresent()) {
              // Server
              privateTransactionProcessor.processExtendedTransaction(input, privateTransaction, messageFrame);
            } else {
              // Client
              final Bytes result = privateTransactionProcessor.processExtendedTransaction(input, privateTransaction, messageFrame);
              LOG.info("[PrivacyPrecompiledContract] Intersection: {}", new String(result.toArray(), Charset.forName("UTF-8")));
            }
          }
        }else if(extendedPrivacy.equals("0x02")) {
          if (privateTransaction.isContractCreation() && privArgs.isPresent()) {
            // Load && Client
            final Bytes result = privateTransactionProcessor.processExtendedTransaction(input, privateTransaction, messageFrame);
            List<String> results = Splitter.on('|').splitToList(new String(result.toArray(), Charset.forName("UTF-8")));

            try {
              Path filePath = Paths.get("hyBeta.txt");
              BufferedWriter writer = Files.newBufferedWriter(filePath, StandardCharsets.UTF_8);

              writer.write("hyBeta: " + results.get(1));
              writer.newLine(); // Nueva línea

              // Cerrar el BufferedWriter
              writer.close();
            } catch (IOException e) {
              LOG.info("[PrivacyPrecompiledContract] Error al escribir en el archivo: {}", e.getMessage());
              e.printStackTrace();
            }

            final Address privateContractAddress = getPrivateContractAddress(privateTransaction.getSender(), privateWorldStateUpdater, privacyGroupId);
            ExtendedPrivacyStorage.Updater updater = extendedPrivacyStorage.updater();
            updater.putBetaByContractAddress_Beta(Bytes.concatenate(privateContractAddress, Bytes.wrap("_Beta".getBytes(Charset.forName("UTF-8")))), Bytes.wrap(results.get(0).getBytes(Charset.forName("UTF-8"))));
            updater.commit();

            ExtendedPrivacyStorage.Updater newUpdater = extendedPrivacyStorage.updater();
            newUpdater.putPmtByContractAddress(privateContractAddress, Bytes.wrap(key.getBytes(Charset.forName("UTF-8"))));
            newUpdater.commit();
          } else if (privArgs.isPresent()) {
            // Consume && sever
            final Bytes result = privateTransactionProcessor.processExtendedTransaction(input, privateTransaction, messageFrame);
            List<String> results = Splitter.on('|').splitToList(new String(result.toArray(), Charset.forName("UTF-8")));

            try {
              Path alphaFilePath = Paths.get("alpha.txt");
              BufferedWriter alphaWriter = Files.newBufferedWriter(alphaFilePath, StandardCharsets.UTF_8);
              alphaWriter.write("alpha: " + results.get(0));
              alphaWriter.newLine(); // Nueva línea
              alphaWriter.close();


              Path peqtFilePath = Paths.get("peqt.txt");
              BufferedWriter peqtWriter = Files.newBufferedWriter(peqtFilePath, StandardCharsets.UTF_8);
              peqtWriter.write("peqt: " + results.get(1));
              peqtWriter.newLine(); // Nueva línea
              peqtWriter.close();
            } catch (IOException e) {
              LOG.info("[PrivacyPrecompiledContract] Error al escribir en el archivo: {}", e.getMessage());
              e.printStackTrace();
            }
          }else {
            LOG.info("[PrivacyPrecompiledContract] Private args are not present");
          }
        }else if(extendedPrivacy.equals("0x03")){
          final Address privateContractAddress = privateTransaction.getTo().get();

          Optional<Bytes> beta = extendedPrivacyStorage.getBetaByContractAddress_Beta(Bytes.concatenate(privateContractAddress, Bytes.wrap("_Beta".getBytes(Charset.forName("UTF-8")))));
          if (beta.isPresent()) {
            final Bytes result = privateTransactionProcessor.processExtendedTransaction(input, privateTransaction, messageFrame);
            LOG.info("[PrivacyPrecompiledContract] Result: {}", new String(result.toArray(), Charset.forName("UTF-8")));
          }else{
            LOG.info("[PrivacyPrecompiledContract] Beta is not present");
          }

        }else{
          LOG.info("[PrivacyPrecompiledContract] Unrecognised Private Transaction Extension");
        }
      }else{
        LOG.info("[PrivacyPrecompiledContract] Extended Private transaction has already been computed");
      }
    }

    final TransactionProcessingResult result =
        processPrivateTransaction(
            messageFrame, privateTransaction, privacyGroupId, privateWorldStateUpdater);

    if (result.isInvalid() || !result.isSuccessful()) {
      LOG.error(
          "Failed to process private transaction {}: {}",
          pmtHash,
          result.getValidationResult().getErrorMessage());

      privateMetadataUpdater.putTransactionReceipt(pmtHash, new PrivateTransactionReceipt(result));

      return Bytes.EMPTY;
    }

    if (messageFrame.getContextVariable(KEY_IS_PERSISTING_PRIVATE_STATE, false)) {
      privateWorldStateUpdater.commit();
      disposablePrivateState.persist(null);

      storePrivateMetadata(
          pmtHash, privacyGroupId, disposablePrivateState, privateMetadataUpdater, result);
    }

    return result.getOutput();
  }

  Address getPrivateContractAddress(final Address senderAddress,
                                    final WorldUpdater privateWorldStateUpdater,
                                    final Bytes32 privacyGroupId) {
    final EvmAccount maybePrivateSender = privateWorldStateUpdater.getAccount(senderAddress);
    final MutableAccount sender =
            maybePrivateSender != null
                    ? maybePrivateSender.getMutable()
                    : privateWorldStateUpdater.createAccount(senderAddress, 0, Wei.ZERO).getMutable();
    final long nonce = sender.getNonce();

    final Address privateContractAddress =
            Address.privateContractAddress(senderAddress, nonce, privacyGroupId);

    LOG.info(
            "[PrivacyPrecompileContract] Calculated contract address {} from sender {} with nonce {} and privacy group {}",
            privateContractAddress.toString(),
            senderAddress,
            nonce,
            privacyGroupId.toString());

    return privateContractAddress;
  }

  protected void maybeApplyGenesisToPrivateWorldState(
      final Hash lastRootHash,
      final MutableWorldState disposablePrivateState,
      final WorldUpdater privateWorldStateUpdater,
      final Bytes32 privacyGroupId,
      final long blockNumber) {
    if (lastRootHash.equals(EMPTY_ROOT_HASH)) {
      this.privateStateGenesisAllocator.applyGenesisToPrivateWorldState(
          disposablePrivateState, privateWorldStateUpdater, privacyGroupId, blockNumber);
    }
  }

  void storePrivateMetadata(
      final org.hyperledger.besu.plugin.data.Hash commitmentHash,
      final Bytes32 privacyGroupId,
      final MutableWorldState disposablePrivateState,
      final PrivateMetadataUpdater privateMetadataUpdater,
      final TransactionProcessingResult result) {

    final int txStatus =
        result.getStatus() == TransactionProcessingResult.Status.SUCCESSFUL ? 1 : 0;

    final PrivateTransactionReceipt privateTransactionReceipt =
        new PrivateTransactionReceipt(
            txStatus, result.getLogs(), result.getOutput(), result.getRevertReason());

    privateMetadataUpdater.putTransactionReceipt(commitmentHash, privateTransactionReceipt);
    privateMetadataUpdater.updatePrivacyGroupHeadBlockMap(privacyGroupId);
    privateMetadataUpdater.addPrivateTransactionMetadata(
        privacyGroupId,
        new PrivateTransactionMetadata(
            fromPlugin(commitmentHash), disposablePrivateState.rootHash()));
  }

  TransactionProcessingResult processPrivateTransaction(
      final MessageFrame messageFrame,
      final PrivateTransaction privateTransaction,
      final Bytes32 privacyGroupId,
      final WorldUpdater privateWorldStateUpdater) {

    return privateTransactionProcessor.processTransaction(
        messageFrame.getWorldUpdater(),
        privateWorldStateUpdater,
        (ProcessableBlockHeader) messageFrame.getBlockValues(),
        messageFrame.getContextVariable(KEY_TRANSACTION_HASH),
        privateTransaction,
        messageFrame.getMiningBeneficiary(),
        OperationTracer.NO_TRACING,
        messageFrame.getBlockHashLookup(),
        privacyGroupId);
  }

  ReceiveResponse getReceiveResponse(final String key) {
    final ReceiveResponse receiveResponse;
    try {
      receiveResponse = enclave.receive(key);
    } catch (final EnclaveServerException e) {
      throw new IllegalStateException(
          "Enclave is responding with an error, perhaps it has a misconfiguration?", e);
    } catch (final EnclaveIOException e) {
      throw new IllegalStateException("Can not communicate with enclave is it up?", e);
    }
    return receiveResponse;
  }

  boolean skipContractExecution(final MessageFrame messageFrame) {
    return isSimulatingPMT(messageFrame) || isMining(messageFrame);
  }

  boolean isSimulatingPMT(final MessageFrame messageFrame) {
    // If there's no PrivateMetadataUpdater, the precompile has not been called through the
    // PrivacyBlockProcessor. This indicates the PMT is being simulated and execution of the
    // precompile is not required.
    return !messageFrame.hasContextVariable(KEY_PRIVATE_METADATA_UPDATER);
  }

  boolean isMining(final MessageFrame messageFrame) {
    boolean isMining = false;
    final BlockValues currentBlockHeader = messageFrame.getBlockValues();
    if (!BlockHeader.class.isAssignableFrom(currentBlockHeader.getClass())) {
      if (messageFrame.getContextVariable(KEY_IS_PERSISTING_PRIVATE_STATE, false)) {
        throw new IllegalArgumentException(
            "The MessageFrame contains an illegal block header type. Cannot persist private block"
                + " metadata without current block hash.");
      } else {
        isMining = true;
      }
    }
    return isMining;
  }

  protected boolean privateFromMatchesSenderKey(
      final Bytes transactionPrivateFrom, final String payloadSenderKey) {
    if (payloadSenderKey == null) {
      LOG.warn(
          "Missing sender key from Orion response. Upgrade Orion to 1.6 to enforce privateFrom check.");
      throw new EnclaveConfigurationException(
          "Incompatible Orion version. Orion version must be 1.6.0 or greater.");
    }

    if (transactionPrivateFrom == null || transactionPrivateFrom.isEmpty()) {
      LOG.warn("Private transaction is missing privateFrom");
      return false;
    }

    if (!payloadSenderKey.equals(transactionPrivateFrom.toBase64String())) {
      LOG.warn("Private transaction privateFrom doesn't match payload sender key");
      return false;
    }

    return true;
  }
}
