package org.hyperledger.besu.ethereum.mainnet.precompiles.privacy;

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
import org.hyperledger.besu.evm.frame.BlockValues;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.precompile.AbstractPrecompiledContract;
import org.hyperledger.besu.evm.tracing.OperationTracer;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
import org.hyperledger.besu.plugin.data.Hash;
import org.hyperledger.besu.psi.PsiMain;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class PsiPrecompiledContract extends AbstractPrecompiledContract{
    private final Enclave enclave;
    final WorldStateArchive privateWorldStateArchive;
    final PrivateStateRootResolver privateStateRootResolver;
    private final PrivateStateGenesisAllocator privateStateGenesisAllocator;
    PrivateTransactionProcessor privateTransactionProcessor;
    private final ExtendedPrivacyStorage extendedPrivacyStorage;
    private PrivateTransaction lastPrivateTransaction;

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
        lastPrivateTransaction = new PrivateTransaction.Builder().build();
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

        Bytes result = Bytes.EMPTY;
        if(!privateTransaction.isContractCreation()) {
            Optional<Bytes> privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(Bytes.wrap(key.getBytes(Charset.forName("UTF-8"))));
            if ((privArgs.isPresent()) && (!privateTransaction.equals(lastPrivateTransaction))) {
                //LOG.info("[PrivacyPrecompiledContract] CLIENT privateArgs: ({}, {})", key, privArgs.get().toHexString());
                LOG.info("[PsiPrecompiledContract] -> executing psi");
                try {
                    String psiType = "HFH99_ECC_COMPRESS";
                    String serverSet = "";
                    String clientSet = privArgs.get().toHexString();
                    String[] psiMainArgs = {psiType, serverSet, clientSet};

                    Set<ByteBuffer> intersectionSet = PsiMain.main(psiMainArgs);

                    String intersection = setToString(intersectionSet);
                    //LOG.info("[PsiPrecompiledContract] -> SET INTERSECTION: {}", intersection);
                    result = Bytes.wrap(intersection.getBytes(Charset.forName("UTF-8")));
                } catch (Exception e) {
                    LOG.error("[PsiPrecompiledContract] -> Error: " + e.getMessage(), e);
                }
                LOG.info("[PsiPrecompiledContract] -> psi done");
                lastPrivateTransaction = privateTransaction;
            } else {
                Optional<Bytes> retrievedKey = extendedPrivacyStorage.getPmtByContractAddress(privateTransaction.getTo().get());
                if (retrievedKey.isPresent()) {
                    privArgs = extendedPrivacyStorage.getPrivateArgsByPmt(retrievedKey.get());
                    if (privArgs.isPresent()) {
                        if(!privateTransaction.equals(lastPrivateTransaction)){
                            //LOG.info("[PsiPrecompiledContract] SERVER executing psi - privateArgs: ({}, {})", new String(retrievedKey.get().toArray(), Charset.forName("UTF-8")), privArgs.get().toHexString());
                            try {
                                String psiType = "HFH99_ECC_COMPRESS";
                                String serverSet = privArgs.get().toHexString();
                                String clientSet = "";
                                String[] psiMainArgs = {psiType, serverSet, clientSet};

                                Set<ByteBuffer> intersectionSet = PsiMain.main(psiMainArgs);

                                String intersection = setToString(intersectionSet);
                                //LOG.info("[PsiPrecompiledContract] -> SET INTERSECTION: {}", intersection);
                                result = Bytes.wrap(intersection.getBytes(Charset.forName("UTF-8")));
                            } catch (Exception e) {
                                LOG.error("[PsiPrecompiledContract] -> Error: " + e.getMessage(), e);
                            }
                            lastPrivateTransaction = privateTransaction;
                        }else{
                            LOG.info("[PsiPrecompiledContract] Private transaction has already been computed");
                        }
                    } else {
                        LOG.info("[PsiPrecompiledContract] privateArgs from key: {}, NOT PRESENT)", new String(retrievedKey.get().toArray(), Charset.forName("UTF-8")));
                    }
                } else {
                    LOG.info("[PsiPrecompiledContract] Key from privateContractAddress: {}, NOT PRESENT", key);
                }
            }
        }

        return result;
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
}