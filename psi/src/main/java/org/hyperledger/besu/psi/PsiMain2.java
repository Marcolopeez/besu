package org.hyperledger.besu.psi;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.RpcManager;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory.CuckooHashBinType;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiConfig;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiServer;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiClient;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiFactory;
import edu.alibaba.mpc4j.s2pc.pso.psi.hfh99.Hfh99EccPsiConfig;
import edu.alibaba.mpc4j.s2pc.pso.psi.kkrt16.Kkrt16PsiConfig;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import com.google.common.base.Splitter;


public class PsiMain2 {
    private static final Logger LOGGER = LoggerFactory.getLogger(PsiMain.class);

    public static String[] main(final String[] args) throws Exception {
        Properties log4jProperties = new Properties();
        log4jProperties.load(PsiMain2.class.getResourceAsStream("/log4j.properties"));
        PropertyConfigurator.configure(log4jProperties);

        // Set VM options to link to the native libraries
        setVMOptions();

        PsiConfig config = buildPsiType(args[0]);

        RpcManager rpcManager = new MemoryRpcManager(2);
        Rpc serverRpc = rpcManager.getRpc(0);
        Rpc clientRpc = rpcManager.getRpc(1);
        PsiServer<ByteBuffer> server = PsiFactory.createServer(serverRpc, clientRpc.ownParty(), config);
        PsiClient<ByteBuffer> client = PsiFactory.createClient(clientRpc, serverRpc.ownParty(), config);

        server.setTaskId(5);
        client.setTaskId(5);

        if(args[1].isEmpty()){
            byte[] bytesClientSet = hexStringToByteArray(args[2].substring(2)); // (PrivateArgs without '0x')
            if(args[4].isEmpty()){
                return executeClient1(client, bytesClientSet);
            }else{
                return executeClient2(client, bytesClientSet, args[4], args[5], args[6]); //args[4] should be `alphaHexString`, args[5] should be `peqtHexString`, args[6] should be `betaString`
            }
        }else{
            byte[] bytesServerSet = hexStringToByteArray(args[1].substring(2)); // (PrivateArgs without '0x')
            return executeServer(server, bytesServerSet, args[3]); //args[3] should be `hyBetaString`
        }
    }

    private static String[] executeClient1(final PsiClient<ByteBuffer> client, final byte[] bytesClientSet){
        Set<ByteBuffer> clientSet = convertByteArrayToByteBufferSet(bytesClientSet);
        int serverSetSize = clientSet.size();
        BigInteger beta = client.psi_1(clientSet.size(), serverSetSize, clientSet, serverSetSize);
        List<byte[]> hyBetaPayload = client.psi_2(serverSetSize, clientSet.size());

        String betaString = beta.toString();
        String hyBetaHexString = bytesListToHexString(hyBetaPayload);

        return new String[] {betaString, hyBetaHexString};
    }


    private static String[] executeClient2(final PsiClient<ByteBuffer> client, final byte[] bytesClientSet, final String alphaHexString, final String peqtHexString, final String betaString) {
        Set<ByteBuffer> clientSet = convertByteArrayToByteBufferSet(bytesClientSet);
        int serverSetSize = clientSet.size();
        List<List<byte[]>> reconstructedResult = new ArrayList<>();
        reconstructedResult.add(hexStringToBytesList(alphaHexString));
        reconstructedResult.add(hexStringToBytesList(peqtHexString));

        try {
            Set<ByteBuffer> intersectionSet = client.psi_3(clientSet.size(), serverSetSize, clientSet, serverSetSize, new BigInteger(betaString), reconstructedResult);
            String intersectionSetString = setToString(intersectionSet);
            return new String[] {intersectionSetString};
        } catch (MpcAbortException e) {
            LOGGER.error("Ocurrió un error: " + e.getMessage(), e);
            return new String[0];
        }
    }

    private static String[] executeServer(final PsiServer<ByteBuffer> server, final byte[] bytesServerSet, final String hyBetaHexString) {
        Set<ByteBuffer> serverSet = convertByteArrayToByteBufferSet(bytesServerSet);
        int clientSetSize = serverSet.size();
        List<byte[]> reconstructedBeta = hexStringToBytesList(hyBetaHexString);

        try {
            List<byte[]>[] result = server.psi_1(serverSet.size(), clientSetSize, serverSet, clientSetSize, reconstructedBeta);String alphaHexString = bytesListToHexString(result[0]);
            String peqtHexString = bytesListToHexString(result[1]);
            return new String[] {alphaHexString, peqtHexString};
        } catch (MpcAbortException e) {
            LOGGER.error("Ocurrió un error: " + e.getMessage(), e);
        }
        return new String[0];
    }

    private static void setVMOptions() {
        String libPathTool = "/home/marco/mpc4j-1.0.4/mpc4j/mpc4j-native-tool/cmake-build-release";
        String libPathFhe = "/home/marco/mpc4j-1.0.4/mpc4j/mpc4j-native-fhe/cmake-build-release";

        try {
            // Loading the native library for mpc4j-native-tool and mpc4j-native-fhe
            System.load(libPathTool + "/libmpc4j-native-tool.so");
            System.load(libPathFhe + "/libmpc4j-native-fhe.so");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Error al cargar la biblioteca nativa: " + e.getMessage());
        }
    }

    public static PsiConfig buildPsiType(final String psiType){
        switch (psiType) {
            case "HFH99_ECC_COMPRESS":
                return new Hfh99EccPsiConfig.Builder().setCompressEncode(true).build();
            case "HFH99_ECC_UNCOMPRESS":
                return new Hfh99EccPsiConfig.Builder().setCompressEncode(false).build();
            case "KKRT16":
                return new Kkrt16PsiConfig.Builder().build();
            case "KKRT16_NO_STASH_NAIVE":
                return new Kkrt16PsiConfig.Builder().setCuckooHashBinType(CuckooHashBinType.NO_STASH_NAIVE).build();
            case "KKRT16_NAIVE_4_HASH":
                return new Kkrt16PsiConfig.Builder().setCuckooHashBinType(CuckooHashBinType.NAIVE_4_HASH).build();
            default:
                throw new IllegalArgumentException("Invalid argument. PSI_TYPES valid: HFH99_ECC_COMPRESS, HFH99_ECC_UNCOMPRESS, KKRT16, KKRT16_NO_STASH_NAIVE, KKRT16_NAIVE_4_HASH");
        }
    }

    private static Set<ByteBuffer> convertByteArrayToByteBufferSet(final byte[] byteArray) {
        Set<ByteBuffer> byteBufferSet = new HashSet<>();
        int blockSize = 32;

        for (int i = 0; i < byteArray.length; i += blockSize) {
            int endIndex = Math.min(i + blockSize, byteArray.length);
            byte[] blockBytes = new byte[endIndex - i];
            System.arraycopy(byteArray, i, blockBytes, 0, blockBytes.length);
            ByteBuffer byteBuffer = ByteBuffer.wrap(blockBytes);
            byteBufferSet.add(byteBuffer);
        }

        return byteBufferSet;
    }

    private static byte[] hexStringToByteArray(final String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesListToHexString(final List<byte[]> byteArrayList) {
        String elementDelimiter = ":";
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < byteArrayList.size(); i++) {
            byte[] byteArray = byteArrayList.get(i);
            for (byte b : byteArray) {
                hexString.append(String.format("%02X", b));
            }
            if (i < byteArrayList.size() - 1) {
                hexString.append(elementDelimiter); // Agregar delimitador entre elementos
            }
        }
        return hexString.toString();
    }

    public static List<byte[]> hexStringToBytesList(final String hexString) {
        String elementDelimiter = ":";
        List<byte[]> byteArrayList = new ArrayList<>();

        Iterable<String> elements = Splitter.onPattern(elementDelimiter).split(hexString);
        for (String element : elements) {
            byte[] byteArray = new byte[element.length() / 2];
            for (int i = 0; i < element.length(); i += 2) {
                String hexByte = element.substring(i, i + 2);
                byteArray[i / 2] = (byte) Integer.parseInt(hexByte, 16);
            }
            byteArrayList.add(byteArray);
        }

        return byteArrayList;
    }

    private static String setToString(final Set<ByteBuffer> set) {
        StringBuilder hexString = new StringBuilder("0x");
        for (ByteBuffer byteBuffer : set) {
            byte[] bytes = new byte[byteBuffer.limit()];
            byteBuffer.rewind();
            byteBuffer.get(bytes);
            for (byte b : bytes) {
                hexString.append(String.format("%02X", b));
            }
        }
        return hexString.toString().trim();
    }

}

