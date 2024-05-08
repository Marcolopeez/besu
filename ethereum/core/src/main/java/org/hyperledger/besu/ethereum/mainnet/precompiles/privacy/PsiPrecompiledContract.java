package org.hyperledger.besu.ethereum.mainnet.precompiles.privacy;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import org.hyperledger.besu.crypto.SECPSignature;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import static org.hyperledger.besu.datatypes.Hash.fromPlugin;
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
import org.hyperledger.besu.ethereum.privacy.storage.ExtendedPrivacyStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateMetadataUpdater;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;
import org.hyperledger.besu.evm.Gas;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.frame.BlockValues;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.AbstractPrecompiledContract;
import org.hyperledger.besu.evm.tracing.OperationTracer;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.plugin.data.Restriction;
import org.hyperledger.besu.psi.PsiMain;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.psi.PsiMain2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PsiPrecompiledContract extends AbstractPrecompiledContract{
    private final Enclave enclave;
    final WorldStateArchive privateWorldStateArchive;
    final PrivateStateRootResolver privateStateRootResolver;
    private final PrivateStateGenesisAllocator privateStateGenesisAllocator;
    PrivateTransactionProcessor privateTransactionProcessor;
    private final ExtendedPrivacyStorage extendedPrivacyStorage;

    private static final String HY_BETA_SIGNATURE = "0x9faa3c91";
    private static final String HX_ALPHA_SIGNATURE = "0xdb1d0fd5";
    private static final String PEQT_SIGNATURE = "0x9fc14a35";

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
                name,
                privacyParameters.getExtendedPrivacyStorage());
    }

    protected PsiPrecompiledContract(
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
        LOG.info("[PsiPrecompiledContract] -> created");
    }

    protected PsiPrecompiledContract(
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

        AtomicReference<Bytes> result = new AtomicReference<>(Bytes.EMPTY);
        String extendedPrivacy = privateTransaction.getExtendedPrivacy().get().toHexString();
        if(extendedPrivacy.equals("0x01")){
            if(!privateTransaction.isContractCreation()) {
                Optional<Bytes> privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(Bytes.wrap(key.getBytes(Charset.forName("UTF-8"))));
                if (privArgs.isPresent()) {
                    LOG.info("[PrivacyPrecompiledContract] SERVER privateArgs: ({}, {})", key, privArgs.get().toHexString());
                    LOG.info("[PsiPrecompiledContract] -> executing psi");
                    try {
                        String psiType = "HFH99_ECC_COMPRESS";
                        String serverSet = privArgs.get().toHexString();
                        String clientSet = "";
                        String[] psiMainArgs = {psiType, serverSet, clientSet};

                        Set<ByteBuffer> intersectionSet = PsiMain.main(psiMainArgs);

                        String intersection = setToString(intersectionSet);
                        result.set(Bytes.wrap(intersection.getBytes(Charset.forName("UTF-8"))));
                    } catch (Exception e) {
                        LOG.error("[PsiPrecompiledContract] -> Error: " + e.getMessage(), e);
                    }
                    LOG.info("[PsiPrecompiledContract] -> psi done");
                } else {
                    Optional<Bytes> retrievedKey = extendedPrivacyStorage.getPmtByContractAddress(privateTransaction.getTo().get());
                    if (retrievedKey.isPresent()) {
                        privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(retrievedKey.get());
                        if (privArgs.isPresent()) {
                            LOG.info("[PsiPrecompiledContract] CLIENT executing psi - privateArgs: ({}, {})", new String(retrievedKey.get().toArray(), Charset.forName("UTF-8")), privArgs.get().toHexString());
                            try {
                                String psiType = "HFH99_ECC_COMPRESS";
                                String serverSet = "";
                                String clientSet = privArgs.get().toHexString();
                                String[] psiMainArgs = {psiType, serverSet, clientSet};

                                Set<ByteBuffer> intersectionSet = PsiMain.main(psiMainArgs);

                                String intersection = setToString(intersectionSet);
                                result.set(Bytes.wrap(intersection.getBytes(Charset.forName("UTF-8"))));
                            } catch (Exception e) {
                                LOG.error("[PsiPrecompiledContract] -> Error: " + e.getMessage(), e);
                            }
                        } else {
                            LOG.info("[PsiPrecompiledContract] privateArgs from key: {}, NOT PRESENT)", new String(retrievedKey.get().toArray(), Charset.forName("UTF-8")));
                        }
                    } else {
                        LOG.info("[PsiPrecompiledContract] Key from privateContractAddress: {}, NOT PRESENT", key);
                    }
                }
            }
        }else if(extendedPrivacy.equals("0x02")){
            Optional<Bytes> privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(Bytes.wrap(key.getBytes(Charset.forName("UTF-8"))));
            if(privateTransaction.isContractCreation() && privArgs.isPresent()){
                LOG.info("[PsiPrecompiledContract] CLIENT executing psi load - privateArgs: ({}, {})", key, privArgs.get().toHexString());
                try {
                    String psiType = "HFH99_ECC_COMPRESS";
                    String clientSet = privArgs.get().toHexString();
                    String[] psiMainArgs = {psiType, "", clientSet, "", "", "", ""};

                    String[] results = PsiMain2.main(psiMainArgs);
                    String concatenatedResult = results[0] + "|" + results[1];
                    result.set(Bytes.wrap(concatenatedResult.getBytes(Charset.forName("UTF-8"))));
                } catch (Exception e) {
                    LOG.error("[PsiPrecompiledContract] -> Error: " + e.getMessage(), e);
                }
            }else if(privArgs.isPresent()){
                LOG.info("[PsiPrecompiledContract] SERVER loading set - privateArgs: ({}, {})", key, privArgs.get().toHexString());
                Optional<Address> optionalTo = privateTransaction.getTo();
                if(optionalTo.isPresent()){
                    TransactionProcessingResult callResult = transactionCall(privateTransaction, disposablePrivateState, privacyGroupId, privateTransactionProcessor, messageFrame, privateWorldStateUpdater, optionalTo.get(), HY_BETA_SIGNATURE);

                    String psiType = "HFH99_ECC_COMPRESS";
                    String serverSet = privArgs.get().toHexString();
                    String hyBetaString = decodeHexString(callResult.getOutput().toHexString());
                    String[] psiMainArgs = {psiType, serverSet, "", hyBetaString, "", "", ""};

                    String[] results = new String[0];
                    try {
                        results = PsiMain2.main(psiMainArgs);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    String concatenatedResult = results[0] + "|" + results[1];
                    result.set(Bytes.wrap(concatenatedResult.getBytes(Charset.forName("UTF-8"))));
                }
            }
        }else if(extendedPrivacy.equals("0x03")){
            final Address privateContractAddress = privateTransaction.getTo().get();

            Optional<Bytes> beta = extendedPrivacyStorage.getBetaByContractAddress_Beta(Bytes.concatenate(privateContractAddress, Bytes.wrap("_Beta".getBytes(Charset.forName("UTF-8")))));
            if (beta.isPresent()) {
                byte[] byteArray = beta.get().toArray();
                String betaString = new String(byteArray, StandardCharsets.UTF_8);
                Optional<Bytes> retrievedKey = extendedPrivacyStorage.getPmtByContractAddress(privateContractAddress);
                if (retrievedKey.isPresent()) {
                    Optional<Bytes> privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(retrievedKey.get());
                    if (privArgs.isPresent()) {
                        TransactionProcessingResult alphaCallResult = transactionCall(privateTransaction, disposablePrivateState, privacyGroupId, privateTransactionProcessor, messageFrame, privateWorldStateUpdater, privateContractAddress, HX_ALPHA_SIGNATURE);
                        TransactionProcessingResult peqtCallResult = transactionCall(privateTransaction, disposablePrivateState, privacyGroupId, privateTransactionProcessor, messageFrame, privateWorldStateUpdater, privateContractAddress, PEQT_SIGNATURE);


                        LOG.info("[PsiPrecompiledContract] CLIENT executing psi 2 - beta: {}, privateArgs: {}, alpha: {}, peqt: {}", betaString, privArgs.get().toHexString(), decodeHexString(alphaCallResult.getOutput().toHexString()), decodeHexString(peqtCallResult.getOutput().toHexString()));

                        String psiType = "HFH99_ECC_COMPRESS";
                        String clientSet = privArgs.get().toHexString();
                        String alphaString = decodeHexString(alphaCallResult.getOutput().toHexString());
                        String peqtString = decodeHexString(peqtCallResult.getOutput().toHexString());
                        String[] psiMainArgs = {psiType, "", clientSet, "", alphaString, peqtString, betaString};

                        String[] results = new String[0];
                        try {
                            results = PsiMain2.main(psiMainArgs);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                        result.set(Bytes.wrap(results[0].getBytes(Charset.forName("UTF-8"))));
                    }
                }
            }
        }

        return result.get();
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

    private static String setToString(final Set<ByteBuffer> set) {
        StringBuilder hexString = new StringBuilder("0x");
        for (ByteBuffer byteBuffer : set) {
            // Crear un array de bytes para almacenar los datos del ByteBuffer
            byte[] bytes = new byte[byteBuffer.limit()];

            // Rebobinar el ByteBuffer para leer desde el principio
            byteBuffer.rewind();

            // Copiar los datos del ByteBuffer al array de bytes
            byteBuffer.get(bytes);

            // Convertir el array de bytes a una cadena en formato hexadecimal
            for (byte b : bytes) {
                hexString.append(String.format("%02X", b));
            }
        }
        return hexString.toString().trim();
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