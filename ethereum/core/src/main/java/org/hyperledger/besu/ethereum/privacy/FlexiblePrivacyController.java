/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.ethereum.privacy;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.besu.ethereum.core.PrivacyParameters.FLEXIBLE_PRIVACY_PROXY;
import static org.hyperledger.besu.ethereum.privacy.group.FlexibleGroupManagement.GET_PARTICIPANTS_METHOD_SIGNATURE;
import static org.hyperledger.besu.ethereum.privacy.group.FlexibleGroupManagement.GET_VERSION_METHOD_SIGNATURE;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.types.PrivacyGroup;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.enclave.types.SendResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.privacy.storage.ExtendedPrivacyStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.transaction.CallParameter;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.google.common.annotations.VisibleForTesting;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FlexiblePrivacyController extends AbstractRestrictedPrivacyController {

  private static final Logger LOG = LoggerFactory.getLogger(FlexiblePrivacyController.class);

  private final ExtendedPrivacyStorage extendedPrivacyStorage;

  private FlexiblePrivacyGroupContract flexiblePrivacyGroupContract;

  public FlexiblePrivacyController(
      final Blockchain blockchain,
      final PrivacyParameters privacyParameters,
      final Optional<BigInteger> chainId,
      final PrivateTransactionSimulator privateTransactionSimulator,
      final PrivateNonceProvider privateNonceProvider,
      final PrivateWorldStateReader privateWorldStateReader) {
    this(
        blockchain,
        privacyParameters.getPrivateStateStorage(),
        privacyParameters.getEnclave(),
        new PrivateTransactionValidator(chainId),
        privateTransactionSimulator,
        privateNonceProvider,
        privateWorldStateReader,
        privacyParameters.getPrivateStateRootResolver(),
        privacyParameters.getExtendedPrivacyStorage());
  }

  public FlexiblePrivacyController(
      final Blockchain blockchain,
      final PrivateStateStorage privateStateStorage,
      final Enclave enclave,
      final PrivateTransactionValidator privateTransactionValidator,
      final PrivateTransactionSimulator privateTransactionSimulator,
      final PrivateNonceProvider privateNonceProvider,
      final PrivateWorldStateReader privateWorldStateReader,
      final PrivateStateRootResolver privateStateRootResolver,
      final ExtendedPrivacyStorage extendedPrivacyStorage) {
    super(
        blockchain,
        privateStateStorage,
        enclave,
        privateTransactionValidator,
        privateTransactionSimulator,
        privateNonceProvider,
        privateWorldStateReader,
        privateStateRootResolver);

    this.extendedPrivacyStorage = extendedPrivacyStorage;

    flexiblePrivacyGroupContract = new FlexiblePrivacyGroupContract(privateTransactionSimulator);
  }

  @Override
  public String createPrivateMarkerTransactionPayload(
      final PrivateTransaction privateTransaction,
      final String privacyUserId,
      final Optional<PrivacyGroup> privacyGroup) {
    if(privateTransaction.hasExtendedPrivacy() && privateTransaction.isContractCreation()){
      putAliceAddressInExtendedStorage(Address.privateContractAddress(privateTransaction.getSender(), privateTransaction.getNonce(), privateTransaction.determinePrivacyGroupId()), privateTransaction.getSender());
    }
    PrivateTransaction toSendTransaction;
    if(privateTransaction.hasExtendedPrivacy() && privateTransaction.getPrivateArgs().isPresent()){
      // set privateArgs to 0x00
      toSendTransaction = blindPrivateTransaction(privateTransaction);
      if(isExtendedPrivacy(privateTransaction, "0x02")) {
        Bytes privateSet = extractPrivateSetFromPrivateArgs(privateTransaction);
        final Bytes privateContractAddress = privateTransaction.getTo().get();
        Optional<Bytes> existingPrivateSet = getPrivateSetFromExtendedStorage(privateContractAddress);
        Bytes newPrivateSet;
        if(existingPrivateSet.isPresent()){
          newPrivateSet = Bytes.concatenate(existingPrivateSet.get(), privateSet);
        }else{
          newPrivateSet = privateSet;
        }
        putPrivateSetInExtendedStorage(privateContractAddress, newPrivateSet);
      }
    } else {
      toSendTransaction = privateTransaction;
    }
    LOG.trace("Storing private transaction in enclave");
    final SendResponse sendResponse = sendRequest(toSendTransaction, privacyGroup);
    final String firstPart = sendResponse.getKey();
    final Optional<String> optionalSecondPart =
        buildAndSendAddPayload(
            toSendTransaction,
            Bytes32.wrap(toSendTransaction.getPrivacyGroupId().orElseThrow()),
            privacyUserId);

    return buildCompoundLookupId(firstPart, optionalSecondPart);
  }

  private void putAliceAddressInExtendedStorage(final Address privateContractAddress, final Address AliceAddress) {
    final ExtendedPrivacyStorage.Updater updater = extendedPrivacyStorage.updater();
    updater.putAliceAddressByContractAddress_Alice(
            Bytes.concatenate(privateContractAddress, Bytes.wrap("_Alice".getBytes(Charset.forName("UTF-8")))),
            AliceAddress);
    updater.commit();
  }
  private Optional<Bytes> getPrivateSetFromExtendedStorage(final Bytes privateContractAddress) {
    return extendedPrivacyStorage.getPrivateSetByContractAddress(privateContractAddress);
  }
  private void putPrivateSetInExtendedStorage(final Bytes privateContractAddress, final Bytes newPrivateSet) {
    LOG.info("Saving into extendedStorage: ({})", newPrivateSet);
    ExtendedPrivacyStorage.Updater updater = extendedPrivacyStorage.updater();
    updater.putPrivateSetByContractAddress(privateContractAddress, newPrivateSet);
    updater.commit();
  }
  private boolean isExtendedPrivacy(final PrivateTransaction privateTransaction, final String extendedPrivacyType) {
    return privateTransaction.getExtendedPrivacy().get().toHexString().equals(extendedPrivacyType);
  }
  private Bytes extractPrivateSetFromPrivateArgs(final PrivateTransaction privateTransaction) {
    Bytes privateArgs = privateTransaction.getPrivateArgs().get();
    final int REFERENCE_LENGTH = 64;
    // Convert the Bytes to a hex string without the "0x" prefix
    String hexString = privateArgs.toHexString().substring(2);
    // Split the hex string into chunks of REFERENCE_LENGTH
    List<String> chunks = splitHexString(hexString, REFERENCE_LENGTH);
    // Extract the length of the private set from the second chunk
    int privateSetLength = Integer.parseInt(chunks.get(1));
    // Extract the result list from the subsequent chunks
    List<String> privateSetChunks = chunks.subList(2, 2 + privateSetLength);
    // Concatenate the result chunks with "0x" prefix
    String privateSetHexString = "0x" + String.join("", privateSetChunks);
    return Bytes.fromHexString(privateSetHexString);
  }
  // Helper method to split a hex string into chunks of a specified length
  private List<String> splitHexString(final String hexString, final int chunkLength) {
    List<String> chunks = new ArrayList<>();
    for (int i = 0; i < hexString.length(); i += chunkLength) {
      chunks.add(hexString.substring(i, Math.min(i + chunkLength, hexString.length())));
    }
    return chunks;
  }
  private PrivateTransaction blindPrivateTransaction(final PrivateTransaction privateTransaction) {
    Bytes privateArgs = privateTransaction.getPrivateArgs().get();
    byte[] byteArgs = new byte[privateArgs.toArray().length];
    for (int i = 0; i < privateArgs.toArray().length; i++) {
      byteArgs[i] = 0;
    }
    Bytes blindedPrivateArgs = Bytes.of(byteArgs);
    PrivateTransaction.Builder builder = PrivateTransaction.builder()
            .gasLimit(privateTransaction.getGasLimit())
            .gasPrice(privateTransaction.getGasPrice())
            .nonce(privateTransaction.getNonce())
            .payload(privateTransaction.getPayload())
            .privateFrom(privateTransaction.getPrivateFrom())
            .restriction(privateTransaction.getRestriction())
            .sender(privateTransaction.getSender())
            .signature(privateTransaction.getSignature())
            .value(privateTransaction.getValue());
    privateTransaction.getChainId().ifPresent(builder::chainId);
    privateTransaction.getPrivacyGroupId().ifPresent(builder::privacyGroupId);
    privateTransaction.getPrivateFor().ifPresent(builder::privateFor);
    privateTransaction.getTo().ifPresent(builder::to);
    privateTransaction.getExtendedPrivacy().ifPresent(builder::extendedPrivacy);
    builder.privateArgs(blindedPrivateArgs);
    PrivateTransaction blindedTransaction = builder.build();
    return blindedTransaction;
  }

  @Override
  public Optional<PrivacyGroup> findPrivacyGroupByGroupId(
      final String privacyGroupId, final String enclaveKey) {
    // get the privateFor list from the management contract
    final Optional<TransactionProcessingResult> privateTransactionSimulatorResultOptional =
        privateTransactionSimulator.process(
            privacyGroupId, buildCallParams(GET_PARTICIPANTS_METHOD_SIGNATURE));

    if (privateTransactionSimulatorResultOptional.isPresent()
        && privateTransactionSimulatorResultOptional.get().isSuccessful()) {
      final RLPInput rlpInput =
          RLP.input(privateTransactionSimulatorResultOptional.get().getOutput());
      if (rlpInput.nextSize() > 0) {
        return Optional.of(
            new PrivacyGroup(
                privacyGroupId,
                PrivacyGroup.Type.FLEXIBLE,
                "",
                "",
                FlexibleUtil.decodeList(rlpInput.raw())));
      }
    }
    return Optional.empty();
  }

  @Override
  public PrivacyGroup[] findPrivacyGroupByMembers(
      final List<String> addresses, final String privacyUserId) {
    final ArrayList<PrivacyGroup> privacyGroups = new ArrayList<>();
    final PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        privateStateStorage
            .getPrivacyGroupHeadBlockMap(blockchain.getChainHeadHash())
            .orElse(PrivacyGroupHeadBlockMap.empty());
    privacyGroupHeadBlockMap
        .keySet()
        .forEach(
            c -> {
              final Optional<PrivacyGroup> maybePrivacyGroup =
                  findPrivacyGroupByGroupId(c.toBase64String(), privacyUserId);
              if (maybePrivacyGroup.isPresent()
                  && maybePrivacyGroup.get().getMembers().containsAll(addresses)) {
                privacyGroups.add(maybePrivacyGroup.get());
              }
            });
    return privacyGroups.toArray(new PrivacyGroup[0]);
  }

  @Override
  public PrivacyGroup createPrivacyGroup(
      final List<String> addresses,
      final String name,
      final String description,
      final String privacyUserId) {
    throw new PrivacyConfigurationNotSupportedException(
        "Method not supported when using flexible privacy");
  }

  @Override
  public String deletePrivacyGroup(final String privacyGroupId, final String privacyUserId) {
    throw new PrivacyConfigurationNotSupportedException(
        "Method not supported when using flexible privacy");
  }

  @Override
  public void verifyPrivacyGroupContainsPrivacyUserId(
      final String privacyGroupId, final String privacyUserId) {
    verifyPrivacyGroupContainsPrivacyUserId(privacyGroupId, privacyUserId, Optional.empty());
  }

  @Override
  public void verifyPrivacyGroupContainsPrivacyUserId(
      final String privacyGroupId, final String privacyUserId, final Optional<Long> blockNumber) {
    final Optional<PrivacyGroup> maybePrivacyGroup =
        flexiblePrivacyGroupContract.getPrivacyGroupByIdAndBlockNumber(privacyGroupId, blockNumber);
    // IF the group exists, check member
    // ELSE member is valid if the group doesn't exist yet - this is normal for flexible privacy
    // groups
    maybePrivacyGroup.ifPresent(
        group -> {
          if (!group.getMembers().contains(privacyUserId)) {
            throw new MultiTenancyValidationException(
                "Privacy group must contain the enclave public key");
          }
        });
  }

  private List<PrivateTransactionMetadata> buildTransactionMetadataList(
      final Bytes privacyGroupId) {
    final List<PrivateTransactionMetadata> pmtHashes = new ArrayList<>();
    PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        privateStateStorage
            .getPrivacyGroupHeadBlockMap(blockchain.getChainHeadHash())
            .orElse(PrivacyGroupHeadBlockMap.empty());
    if (privacyGroupHeadBlockMap.containsKey(privacyGroupId)) {
      Hash blockHash = privacyGroupHeadBlockMap.get(privacyGroupId);
      while (blockHash != null) {
        pmtHashes.addAll(
            0,
            privateStateStorage
                .getPrivateBlockMetadata(blockHash, Bytes32.wrap(privacyGroupId))
                .orElseThrow()
                .getPrivateTransactionMetadataList());
        blockHash = blockchain.getBlockHeader(blockHash).orElseThrow().getParentHash();
        privacyGroupHeadBlockMap =
            privateStateStorage
                .getPrivacyGroupHeadBlockMap(blockHash)
                .orElse(PrivacyGroupHeadBlockMap.empty());
        if (privacyGroupHeadBlockMap.containsKey(privacyGroupId)) {
          blockHash = privacyGroupHeadBlockMap.get(privacyGroupId);
        } else {
          break;
        }
      }
    }
    return pmtHashes;
  }

  private List<PrivateTransactionWithMetadata> retrievePrivateTransactions(
      final Bytes32 privacyGroupId,
      final List<PrivateTransactionMetadata> privateTransactionMetadataList,
      final String privacyUserId) {
    final ArrayList<PrivateTransactionWithMetadata> privateTransactions = new ArrayList<>();
    privateStateStorage
        .getAddDataKey(privacyGroupId)
        .ifPresent(key -> privateTransactions.addAll(retrieveAddBlob(key.toBase64String())));
    for (int i = privateTransactions.size(); i < privateTransactionMetadataList.size(); i++) {
      final PrivateTransactionMetadata privateTransactionMetadata =
          privateTransactionMetadataList.get(i);
      final Transaction privateMarkerTransaction =
          blockchain
              .getTransactionByHash(privateTransactionMetadata.getPrivateMarkerTransactionHash())
              .orElseThrow();
      final ReceiveResponse receiveResponse =
          retrieveTransaction(
              privateMarkerTransaction.getPayload().slice(0, 32).toBase64String(), privacyUserId);
      final BytesValueRLPInput input =
          new BytesValueRLPInput(
              Bytes.fromBase64String(new String(receiveResponse.getPayload(), UTF_8)), false);
      input.enterList();
      privateTransactions.add(
          new PrivateTransactionWithMetadata(
              PrivateTransaction.readFrom(input), privateTransactionMetadata));
      input.leaveListLenient();
    }

    return privateTransactions;
  }

  private List<PrivateTransactionWithMetadata> retrieveAddBlob(final String addDataKey) {
    final ReceiveResponse addReceiveResponse = enclave.receive(addDataKey);
    return PrivateTransactionWithMetadata.readListFromPayload(
        Bytes.wrap(Base64.getDecoder().decode(addReceiveResponse.getPayload())));
  }

  private Optional<String> buildAndSendAddPayload(
      final PrivateTransaction privateTransaction,
      final Bytes32 privacyGroupId,
      final String privacyUserId) {
    if (FlexibleUtil.isGroupAdditionTransaction(privateTransaction)) {
      final List<PrivateTransactionMetadata> privateTransactionMetadataList =
          buildTransactionMetadataList(privacyGroupId);
      if (!privateTransactionMetadataList.isEmpty()) {
        final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList =
            retrievePrivateTransactions(
                privacyGroupId, privateTransactionMetadataList, privacyUserId);
        final Bytes bytes = serializeAddToGroupPayload(privateTransactionWithMetadataList);
        final List<String> privateFor =
            FlexibleUtil.getParticipantsFromParameter(privateTransaction.getPayload());
        return Optional.of(
            enclave.send(bytes.toBase64String(), privacyUserId, privateFor).getKey());
      }
    }

    return Optional.empty();
  }

  private String buildCompoundLookupId(
      final String privateTransactionLookupId,
      final Optional<String> maybePrivateTransactionLookupId) {
    return maybePrivateTransactionLookupId.isPresent()
        ? Bytes.concatenate(
                Bytes.fromBase64String(privateTransactionLookupId),
                Bytes.fromBase64String(maybePrivateTransactionLookupId.get()))
            .toBase64String()
        : privateTransactionLookupId;
  }

  private Bytes serializeAddToGroupPayload(
      final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList) {

    final BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();
    rlpOutput.startList();
    privateTransactionWithMetadataList.forEach(
        privateTransactionWithMetadata -> privateTransactionWithMetadata.writeTo(rlpOutput));
    rlpOutput.endList();

    return rlpOutput.encoded();
  }

  private SendResponse sendRequest(
      final PrivateTransaction privateTransaction, final Optional<PrivacyGroup> maybePrivacyGroup) {
    final BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();

    final PrivacyGroup privacyGroup = maybePrivacyGroup.orElseThrow();
    final Optional<TransactionProcessingResult> version =
        privateTransactionSimulator.process(
            privateTransaction.getPrivacyGroupId().orElseThrow().toBase64String(),
            buildCallParams(GET_VERSION_METHOD_SIGNATURE));
    new VersionedPrivateTransaction(privateTransaction, version).writeTo(rlpOutput);
    final List<String> flexiblePrivateFor = privacyGroup.getMembers();
    return enclave.send(
        rlpOutput.encoded().toBase64String(),
        privateTransaction.getPrivateFrom().toBase64String(),
        flexiblePrivateFor);
  }

  CallParameter buildCallParams(final Bytes methodCall) {
    return new CallParameter(
        Address.ZERO, FLEXIBLE_PRIVACY_PROXY, 3000000, Wei.of(1000), Wei.ZERO, methodCall);
  }

  ReceiveResponse retrieveTransaction(final String enclaveKey, final String privacyUserId) {
    return enclave.receive(enclaveKey, privacyUserId);
  }

  @VisibleForTesting
  public void setFlexiblePrivacyGroupContract(
      final FlexiblePrivacyGroupContract flexiblePrivacyGroupContract) {
    this.flexiblePrivacyGroupContract = flexiblePrivacyGroupContract;
  }
}
