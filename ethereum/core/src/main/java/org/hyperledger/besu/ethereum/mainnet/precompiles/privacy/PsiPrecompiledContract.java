package org.hyperledger.besu.ethereum.mainnet.precompiles.privacy;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import static org.hyperledger.besu.ethereum.mainnet.PrivateStateUtils.KEY_IS_PERSISTING_PRIVATE_STATE;
import static org.hyperledger.besu.ethereum.mainnet.PrivateStateUtils.KEY_PRIVATE_METADATA_UPDATER;
import static org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver.EMPTY_ROOT_HASH;
import org.hyperledger.besu.datatypes.Wei;
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
import org.hyperledger.besu.ethereum.privacy.VersionedPrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.storage.ExtendedPrivacyStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateMetadataUpdater;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.frame.BlockValues;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.AbstractPrecompiledContract;
import org.hyperledger.besu.evm.tracing.OperationTracer;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.plugin.data.Restriction;

import java.math.BigInteger;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Base64;
import java.util.Optional;
import javax.annotation.Nonnull;
import com.google.common.base.Splitter;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.psi.PsiMain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PsiPrecompiledContract extends AbstractPrecompiledContract{
    private final Enclave enclave;
    final WorldStateArchive privateWorldStateArchive;
    final PrivateStateRootResolver privateStateRootResolver;
    private final PrivateStateGenesisAllocator privateStateGenesisAllocator;
    final boolean alwaysIncrementPrivateNonce;
    PrivateTransactionProcessor privateTransactionProcessor;
    private final ExtendedPrivacyStorage extendedPrivacyStorage;
    private static final String ALICE_METADATA_SIGNATURE = "0xd8e32925";
    private static final String BOB_METADATA_SIGNATURE = "0xa676cc06";
    private static final String ALICE_COMPLETED_SET_LOADING_SIGNATURE = "0xe461725a";
    private static final String BOB_COMPLETED_SET_LOADING_SIGNATURE = "0xfc04cda7";
    private static final String CONSUME_SIGNATURE = "0x1dedc6f7";
    private static final String ALICE_SET_LENGTH_SIGNATURE = "0xe6491f90";
    private static final String BOB_SET_LENGTH_SIGNATURE = "0x23c1455c";
    private static final Supplier<SignatureAlgorithm> SIGNATURE_ALGORITHM =
            Suppliers.memoize(SignatureAlgorithmFactory::getInstance);
    // Dummy signature for transactions to not fail being processed.
    private static final SECPSignature FAKE_SIGNATURE =
            SIGNATURE_ALGORITHM
                    .get()
                    .createSignature(
                            SIGNATURE_ALGORITHM.get().getHalfCurveOrder(),
                            SIGNATURE_ALGORITHM.get().getHalfCurveOrder(),
                            (byte) 0);
    private static final Logger LOG = LoggerFactory.getLogger(PsiPrecompiledContract.class);
    static final PrecompileContractResult NO_RESULT =
            new PrecompileContractResult(
                    Bytes.EMPTY, true, MessageFrame.State.CODE_EXECUTING, Optional.empty());
    public PsiPrecompiledContract(
            final GasCalculator gasCalculator,
            final PrivacyParameters privacyParameters,
            final String name) {
        this(
                gasCalculator,
                privacyParameters.getEnclave(),
                privacyParameters.getPrivateWorldStateArchive(),
                privacyParameters.getPrivateStateRootResolver(),
                privacyParameters.getPrivateStateGenesisAllocator(),
                privacyParameters.isPrivateNonceAlwaysIncrementsEnabled(),
                name,
                privacyParameters.getExtendedPrivacyStorage());
    }
    protected PsiPrecompiledContract(
            final GasCalculator gasCalculator,
            final Enclave enclave,
            final WorldStateArchive worldStateArchive,
            final PrivateStateRootResolver privateStateRootResolver,
            final PrivateStateGenesisAllocator privateStateGenesisAllocator,
            final boolean alwaysIncrementPrivateNonce,
            final String name,
            final ExtendedPrivacyStorage extendedPrivacyStorage) {
        super(name, gasCalculator);
        this.enclave = enclave;
        this.privateWorldStateArchive = worldStateArchive;
        this.privateStateRootResolver = privateStateRootResolver;
        this.privateStateGenesisAllocator = privateStateGenesisAllocator;
        this.alwaysIncrementPrivateNonce = alwaysIncrementPrivateNonce;
        this.extendedPrivacyStorage = extendedPrivacyStorage;
    }
    public void setPrivateTransactionProcessor(
            final PrivateTransactionProcessor privateTransactionProcessor) {
        this.privateTransactionProcessor = privateTransactionProcessor;
    }
    @Override
    public long gasRequirement(final Bytes input) {
        return 0L;
    }
    @Nonnull
    @Override
    public PrecompileContractResult computePrecompile(final Bytes input, @Nonnull final MessageFrame messageFrame) {
        if (skipContractExecution(messageFrame)) {
            return NO_RESULT;
        }
        if (input == null || (input.size() != 32 && input.size() != 64)) {
            LOG.error("Can not fetch private transaction payload with key of invalid length {}", input);
            return NO_RESULT;
        }
        final String key = input.slice(0, 32).toBase64String();
        final ReceiveResponse receiveResponse;
        try {
            receiveResponse = getReceiveResponse(key);
        } catch (final EnclaveClientException e) {
            LOG.debug("Can not fetch private transaction payload with key {}", key, e);
            return NO_RESULT;
        }
        final BytesValueRLPInput bytesValueRLPInput =
                new BytesValueRLPInput(
                        Bytes.wrap(Base64.getDecoder().decode(receiveResponse.getPayload())), false);
        final VersionedPrivateTransaction versionedPrivateTransaction =
                VersionedPrivateTransaction.readFrom(bytesValueRLPInput);
        final PrivateTransaction privateTransaction =
                versionedPrivateTransaction.getPrivateTransaction();
        final Bytes privateFrom = privateTransaction.getPrivateFrom();
        if (!privateFromMatchesSenderKey(privateFrom, receiveResponse.getSenderKey())) {
            return NO_RESULT;
        }
        final Optional<Bytes> maybeGroupId = privateTransaction.getPrivacyGroupId();
        if (maybeGroupId.isEmpty()) {
            return NO_RESULT;
        }
        final Bytes32 privacyGroupId = Bytes32.wrap(maybeGroupId.get());
        final PrivateMetadataUpdater privateMetadataUpdater =
                messageFrame.getContextVariable(KEY_PRIVATE_METADATA_UPDATER);
        final Hash lastRootHash =
                privateStateRootResolver.resolveLastStateRoot(privacyGroupId, privateMetadataUpdater);
        final MutableWorldState disposablePrivateState =
                privateWorldStateArchive.getMutable(lastRootHash, null).get();
        final WorldUpdater privateWorldStateUpdater = disposablePrivateState.updater();
        maybeApplyGenesisToPrivateWorldState(
                lastRootHash,
                disposablePrivateState,
                privateWorldStateUpdater,
                privacyGroupId,
                messageFrame.getBlockValues().getNumber());
        return processPrivateTransaction(privateTransaction, disposablePrivateState, privacyGroupId, messageFrame, privateWorldStateUpdater);
    }
    private PrecompileContractResult processPrivateTransaction(
            final PrivateTransaction privateTransaction,
            final MutableWorldState disposablePrivateState,
            final Bytes32 privacyGroupId,
            final MessageFrame messageFrame,
            final WorldUpdater privateWorldStateUpdater) {
        if (isExtendedPrivacy(privateTransaction, "0x03")) {
            final Address privateContractAddress = privateTransaction.getTo().get();
            final Optional<Bytes> aliceAddress = getAliceAddressFromExtendedStorage(privateContractAddress);
            final Bytes methodCalled = privateTransaction.getPayload().slice(0, 4);
            if (isAliceSetIsReadyMethod(methodCalled, aliceAddress)) {
                return handleAliceSetIsReady(privateTransaction, disposablePrivateState, privacyGroupId, messageFrame, privateWorldStateUpdater, privateContractAddress);
            } else if (isBobSetIsReadyMethod(methodCalled, aliceAddress)) {
                return handleBobSetIsReady(privateTransaction, disposablePrivateState, privacyGroupId, messageFrame, privateWorldStateUpdater, privateContractAddress);
            } else if (isConsumeMethod(methodCalled, aliceAddress)) {
                return handleConsume(privateTransaction, disposablePrivateState, privacyGroupId, messageFrame, privateWorldStateUpdater, privateContractAddress);
            }
        }
        return NO_RESULT;
    }
    private PrecompileContractResult handleAliceSetIsReady(
            final PrivateTransaction privateTransaction,
            final MutableWorldState disposablePrivateState,
            final Bytes32 privacyGroupId,
            final MessageFrame messageFrame,
            final WorldUpdater privateWorldStateUpdater,
            final Address privateContractAddress) {
        final TransactionProcessingResult bobSetLength_CallResult =
                transactionCall(privateTransaction, disposablePrivateState, privacyGroupId,
                        privateTransactionProcessor, messageFrame,
                        privateWorldStateUpdater, privateContractAddress,
                        BOB_SET_LENGTH_SIGNATURE);

        if (bobSetLength_CallResult.isSuccessful()) {
            final int bobSetLength = getSetLength(bobSetLength_CallResult);

            final Optional<Bytes> privateSet = getPrivateSetFromExtendedStorage(privateContractAddress);
            if (privateSet.isPresent()) {
                try {
                    final String[] results = PsiMain.executeClient1("HFH99_ECC_COMPRESS", privateSet.get().toHexString(), bobSetLength);

                    putBetaInExtendedStorage(privateContractAddress, results[0]);
                    writeToFile("hyBeta.txt", results[1]);

                    String concatenatedResult = results[0] + "|" + results[1];
                    Bytes result = Bytes.wrap(concatenatedResult.getBytes(Charset.forName("UTF-8")));
                    new PrecompileContractResult(
                            result, true, MessageFrame.State.CODE_SUCCESS, Optional.empty());
                } catch (Exception e) {
                    LOG.error("Error processing PSI: {}", e.getMessage(), e);
                    return NO_RESULT;
                }
            }
        }
        return NO_RESULT;
    }
    private PrecompileContractResult handleBobSetIsReady(
            final PrivateTransaction privateTransaction,
            final MutableWorldState disposablePrivateState,
            final Bytes32 privacyGroupId,
            final MessageFrame messageFrame,
            final WorldUpdater privateWorldStateUpdater,
            final Address privateContractAddress) {
        final TransactionProcessingResult aliceSetLength_CallResult =
                transactionCall(privateTransaction, disposablePrivateState, privacyGroupId,
                        privateTransactionProcessor, messageFrame,
                        privateWorldStateUpdater, privateContractAddress,
                        ALICE_SET_LENGTH_SIGNATURE);
        final TransactionProcessingResult aliceMetadata_CallResult =
                transactionCall(privateTransaction, disposablePrivateState, privacyGroupId,
                        privateTransactionProcessor, messageFrame,
                        privateWorldStateUpdater, privateContractAddress,
                        ALICE_METADATA_SIGNATURE);

        if (aliceSetLength_CallResult.isSuccessful() && aliceMetadata_CallResult.isSuccessful()) {
            final int aliceSetLength = getSetLength(aliceSetLength_CallResult);

            final Optional<Bytes> privateSet = getPrivateSetFromExtendedStorage(privateContractAddress);
            if (privateSet.isPresent()) {
                String hyBetaString = decodeHexString(aliceMetadata_CallResult.getOutput().toHexString());
                try {
                    final String[] results = PsiMain.executeServer("HFH99_ECC_COMPRESS", privateSet.get().toHexString(), hyBetaString, aliceSetLength);

                    writeToFile("hxAlpha.txt", results[0]);
                    writeToFile("peqt.txt", results[1]);

                    String concatenatedResult = results[0] + "|" + results[1];
                    Bytes result = Bytes.wrap(concatenatedResult.getBytes(Charset.forName("UTF-8")));
                    new PrecompileContractResult(
                            result, true, MessageFrame.State.CODE_SUCCESS, Optional.empty());
                } catch (Exception e) {
                    LOG.error("Error processing PSI: {}", e.getMessage(), e);
                    return NO_RESULT;
                }
            }
        }
        return NO_RESULT;
    }
    private PrecompileContractResult handleConsume(
            final PrivateTransaction privateTransaction,
            final MutableWorldState disposablePrivateState,
            final Bytes32 privacyGroupId,
            final MessageFrame messageFrame,
            final WorldUpdater privateWorldStateUpdater,
            final Address privateContractAddress) {
        Optional<Bytes> beta = getBetaFromExtendedStorage(privateContractAddress);
        if (beta.isPresent()) {
            byte[] byteArray = beta.get().toArray();
            String betaString = new String(byteArray, StandardCharsets.UTF_8);
            final Optional<Bytes> privateSet = getPrivateSetFromExtendedStorage(privateContractAddress);
            if (privateSet.isPresent()) {
                final TransactionProcessingResult bobMetadata_CallResult =
                        transactionCall(privateTransaction, disposablePrivateState, privacyGroupId,
                                privateTransactionProcessor, messageFrame,
                                privateWorldStateUpdater, privateContractAddress,
                                BOB_METADATA_SIGNATURE);
                final TransactionProcessingResult bobSetLength_CallResult  =
                        transactionCall(privateTransaction, disposablePrivateState, privacyGroupId,
                                privateTransactionProcessor, messageFrame,
                                privateWorldStateUpdater, privateContractAddress,
                                BOB_SET_LENGTH_SIGNATURE);

                if(bobMetadata_CallResult.isSuccessful() && bobSetLength_CallResult.isSuccessful()){
                    final int bobSetLength = getSetLength(bobSetLength_CallResult);
                    List<String> bobMetadataDecode = Splitter.on('|').splitToList(decodeHexString(bobMetadata_CallResult.getOutput().toHexString()));
                    String hxAlphaString = bobMetadataDecode.get(0);
                    String peqtString = bobMetadataDecode.get(1);
                    try {
                        final String[] results = PsiMain.executeClient2("HFH99_ECC_COMPRESS", privateSet.get().toHexString(), hxAlphaString, peqtString, betaString, bobSetLength);

                        LOG.info("Intersection: {}", results[0]);
                        Bytes result = Bytes.wrap(results[0].getBytes(Charset.forName("UTF-8")));
                        new PrecompileContractResult(
                                result, true, MessageFrame.State.CODE_SUCCESS, Optional.empty());
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return NO_RESULT;
    }
    private boolean isExtendedPrivacy(final PrivateTransaction privateTransaction, final String extendedPrivacyType) {
        return privateTransaction.getExtendedPrivacy().get().toHexString().equals(extendedPrivacyType);
    }
    private Optional<Bytes> getAliceAddressFromExtendedStorage(final Address privateContractAddress) {
        return extendedPrivacyStorage.getAliceAddressByContractAddress_Alice(
                Bytes.concatenate(privateContractAddress, Bytes.wrap("_Alice".getBytes(Charset.forName("UTF-8")))));
    }
    private Optional<Bytes> getPrivateSetFromExtendedStorage(final Address privateContractAddress) {
        return extendedPrivacyStorage.getPrivateSetByContractAddress(privateContractAddress);
    }
    private Optional<Bytes> getBetaFromExtendedStorage(final Address privateContractAddress) {
        return extendedPrivacyStorage.getBetaByContractAddress_Beta(
                Bytes.concatenate(privateContractAddress, Bytes.wrap("_Beta".getBytes(Charset.forName("UTF-8")))));
    }
    private void putBetaInExtendedStorage(final Address privateContractAddress, final String Beta) {
        final ExtendedPrivacyStorage.Updater updater = extendedPrivacyStorage.updater();
        updater.putBetaByContractAddress_Beta(
                Bytes.concatenate(privateContractAddress, Bytes.wrap("_Beta".getBytes(Charset.forName("UTF-8")))),
                Bytes.wrap(Beta.getBytes(Charset.forName("UTF-8"))));
        updater.commit();
    }
    private boolean isAliceSetIsReadyMethod(final Bytes methodCalled, final Optional<Bytes> aliceAddress) {
        return methodCalled.equals(Bytes.fromHexString(ALICE_COMPLETED_SET_LOADING_SIGNATURE)) && aliceAddress.isPresent();
    }
    private boolean isBobSetIsReadyMethod(final Bytes methodCalled, final Optional<Bytes> aliceAddress) {
        return methodCalled.equals(Bytes.fromHexString(BOB_COMPLETED_SET_LOADING_SIGNATURE)) && !aliceAddress.isPresent();
    }
    private boolean isConsumeMethod(final Bytes methodCalled, final Optional<Bytes> aliceAddress) {
        return methodCalled.equals(Bytes.fromHexString(CONSUME_SIGNATURE)) && aliceAddress.isPresent();
    }
    private int getSetLength(final TransactionProcessingResult result) {
        return new BigInteger(1, result.getOutput().slice(28, 4).toArray()).intValue();
    }
    private void writeToFile(final String fileName, final String content) {
        try {
            final Path filePath = Paths.get(fileName);
            final BufferedWriter writer = Files.newBufferedWriter(filePath, StandardCharsets.UTF_8);
            writer.write(content);
            writer.close();
        } catch (IOException e) {
            LOG.info("Error writing to file {}: {}", fileName, e.getMessage());
        }
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
    public static String decodeHexString(final String inputHex) {
        // Remove the '0x' prefix
        String hex = inputHex.substring(2);
        // Extract the length part (byte offset 32)
        String lengthHex = hex.substring(64, 128);
        BigInteger lengthBigInt = new BigInteger(lengthHex, 16);
        int length = lengthBigInt.intValue();
        // Extract the actual string data
        String dataHex = hex.substring(128, 128 + (length * 2)); // length * 2 because each byte is represented by 2 hex characters
        // Convert the string data from hexadecimal to readable text
        StringBuilder decodedString = new StringBuilder();
        for (int i = 0; i < dataHex.length(); i += 2) {
            String hexPair = dataHex.substring(i, i + 2);
            char decodedChar = (char) Integer.parseInt(hexPair, 16);
            decodedString.append(decodedChar);
        }
        return decodedString.toString();
    }
    public static TransactionProcessingResult transactionCall(final PrivateTransaction privateTransaction, final MutableWorldState disposablePrivateState, final Bytes32 privacyGroupId, final PrivateTransactionProcessor privateTransactionProcessor, final MessageFrame messageFrame, final WorldUpdater privateWorldStateUpdater, final Address to, final String methodSignature) {
        final Account sender = disposablePrivateState.get(privateTransaction.getSender());
        final long nonce = sender != null ? sender.getNonce() : 0L;
        final PrivateTransaction callTransaction =
                PrivateTransaction.builder()
                        .privateFrom(Bytes.EMPTY)
                        .privacyGroupId(privacyGroupId)
                        .restriction(Restriction.RESTRICTED)
                        .nonce(nonce)
                        .gasPrice(Wei.ZERO)
                        .gasLimit(privateTransaction.getGasLimit())
                        .to(to)
                        .sender(privateTransaction.getSender())
                        .value(Wei.ZERO)
                        .payload(Bytes.fromHexString(methodSignature))
                        .signature(FAKE_SIGNATURE)
                        .build();
        final TransactionProcessingResult callResult =
                privateTransactionProcessor.processTransaction(
                        messageFrame.getWorldUpdater(),
                        privateWorldStateUpdater,
                        (ProcessableBlockHeader) messageFrame.getBlockValues(),
                        Hash.ZERO, // Corresponding PMT hash not needed as this private transaction doesn't exist
                        callTransaction,
                        messageFrame.getMiningBeneficiary(),
                        OperationTracer.NO_TRACING,
                        messageFrame.getBlockHashLookup(),
                        privacyGroupId);
        return callResult;
    }
}