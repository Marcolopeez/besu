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
package org.hyperledger.besu.ethereum.privacy;

import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.types.PrivacyGroup;
import org.hyperledger.besu.enclave.types.SendResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.tuweni.bytes.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RestrictedDefaultPrivacyController extends AbstractRestrictedPrivacyController {

  private static final Logger LOG =
      LoggerFactory.getLogger(RestrictedDefaultPrivacyController.class);

  public RestrictedDefaultPrivacyController(
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
        privacyParameters.getPrivateStateRootResolver());
  }

  public RestrictedDefaultPrivacyController(
      final Blockchain blockchain,
      final PrivateStateStorage privateStateStorage,
      final Enclave enclave,
      final PrivateTransactionValidator privateTransactionValidator,
      final PrivateTransactionSimulator privateTransactionSimulator,
      final PrivateNonceProvider privateNonceProvider,
      final PrivateWorldStateReader privateWorldStateReader,
      final PrivateStateRootResolver privateStateRootResolver) {
    super(
        blockchain,
        privateStateStorage,
        enclave,
        privateTransactionValidator,
        privateTransactionSimulator,
        privateNonceProvider,
        privateWorldStateReader,
        privateStateRootResolver);
  }

  @Override
  public String createPrivateMarkerTransactionPayload(
      final PrivateTransaction privateTransaction,
      final String privacyUserId,
      final Optional<PrivacyGroup> maybePrivacyGroup) {
    PrivateTransaction toSendTransaction;

    if(privateTransaction.hasExtendedPrivacy()){
      // set privateArgs to 0x00
      toSendTransaction = blindPrivateTransaction(privateTransaction);
    } else {
      toSendTransaction = privateTransaction;
    }

    LOG.trace("Storing private transaction in enclave");
    final SendResponse sendResponse =
        sendRequest(toSendTransaction, privacyUserId, maybePrivacyGroup);

    String key = sendResponse.getKey();

    if(privateTransaction.hasExtendedPrivacy()) {
      Bytes privateArgs = privateTransaction.getPrivateArgs().get();
      LOG.info("Saving into privateStorage ({}, {})", key, privateArgs.toHexString());
      // TODO: save into storage (key, privateArgs)
    }

    return key;
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
  public PrivacyGroup createPrivacyGroup(
      final List<String> addresses,
      final String name,
      final String description,
      final String privacyUserId) {
    return enclave.createPrivacyGroup(addresses, privacyUserId, name, description);
  }

  @Override
  public String deletePrivacyGroup(final String privacyGroupId, final String privacyUserId) {
    return enclave.deletePrivacyGroup(privacyGroupId, privacyUserId);
  }

  @Override
  public PrivacyGroup[] findPrivacyGroupByMembers(
      final List<String> addresses, final String privacyUserId) {
    return enclave.findPrivacyGroup(addresses);
  }

  @Override
  public Optional<PrivacyGroup> findPrivacyGroupByGroupId(
      final String privacyGroupId, final String privacyUserId) {
    return Optional.ofNullable(enclave.retrievePrivacyGroup(privacyGroupId));
  }

  private SendResponse sendRequest(
      final PrivateTransaction privateTransaction,
      final String privacyUserId,
      final Optional<PrivacyGroup> maybePrivacyGroup) {
    final BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();

    if (maybePrivacyGroup.isPresent()) {
      final PrivacyGroup privacyGroup = maybePrivacyGroup.get();
      if (privacyGroup.getType() == PrivacyGroup.Type.PANTHEON) {
        // offchain privacy group
        privateTransaction.writeTo(rlpOutput);
        return enclave.send(
            rlpOutput.encoded().toBase64String(),
            privacyUserId,
            privateTransaction.getPrivacyGroupId().get().toBase64String());
      } else {
        // this should not happen
        throw new IllegalArgumentException(
            "Wrong privacy group type "
                + privacyGroup.getType()
                + " when "
                + PrivacyGroup.Type.PANTHEON
                + "was expected.");
      }
    }
    // legacy transaction
    final List<String> privateFor = resolveLegacyPrivateFor(privateTransaction);
    if (privateFor.isEmpty()) {
      privateFor.add(privateTransaction.getPrivateFrom().toBase64String());
    }
    privateTransaction.writeTo(rlpOutput);
    final String payload = rlpOutput.encoded().toBase64String();

    return enclave.send(payload, privateTransaction.getPrivateFrom().toBase64String(), privateFor);
  }

  private List<String> resolveLegacyPrivateFor(final PrivateTransaction privateTransaction) {
    final ArrayList<String> privateFor = new ArrayList<>();
    final boolean isLegacyTransaction = privateTransaction.getPrivateFor().isPresent();
    if (isLegacyTransaction) {
      privateFor.addAll(
          privateTransaction.getPrivateFor().get().stream()
              .map(Bytes::toBase64String)
              .collect(Collectors.toList()));
    }
    return privateFor;
  }

  @Override
  public void verifyPrivacyGroupContainsPrivacyUserId(
      final String privacyGroupId, final String privacyUserId) {
    final PrivacyGroup offchainPrivacyGroup = enclave.retrievePrivacyGroup(privacyGroupId);
    if (!offchainPrivacyGroup.getMembers().contains(privacyUserId)) {
      throw new MultiTenancyValidationException(
          "Privacy group must contain the enclave public key");
    }
  }

  @Override
  public void verifyPrivacyGroupContainsPrivacyUserId(
      final String privacyGroupId, final String privacyUserId, final Optional<Long> blockNumber) {
    verifyPrivacyGroupContainsPrivacyUserId(privacyGroupId, privacyUserId);
  }
}
