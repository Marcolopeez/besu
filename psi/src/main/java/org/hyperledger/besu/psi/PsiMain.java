package org.hyperledger.besu.psi;


import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.RpcManager;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory.CuckooHashBinType;
import edu.alibaba.mpc4j.s2pc.pso.PsoUtils;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiConfig;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiServer;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiClient;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiFactory;
import edu.alibaba.mpc4j.s2pc.pso.psi.hfh99.Hfh99EccPsiConfig;
import edu.alibaba.mpc4j.s2pc.pso.psi.kkrt16.Kkrt16PsiConfig;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.log4j.PropertyConfigurator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;


public class PsiMain {
    private static final Logger LOGGER = LoggerFactory.getLogger(PsiMain.class);

    //private static final int ELEMENT_BYTE_LENGTH = CommonConstants.BLOCK_BYTE_LENGTH;

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

    public static void printIntersection(final Set<ByteBuffer> intersectionSet){
        // Imprimir IntersectionSet
        LOGGER.info("IntersectionSet: {}", setToString(intersectionSet));
    }

    public static Set<ByteBuffer> main(final String[] args) throws Exception {
        // Configurar opciones de VM
        configurarOpcionesVM();

        ResultHolder resultHolder = new ResultHolder();

        PsiConfig config;
        Rpc serverRpc;
        Rpc clientRpc;

        LOGGER.info("read log config");
        Properties log4jProperties = new Properties();
        log4jProperties.load(PsiMain.class.getResourceAsStream("/log4j.properties"));
        PropertyConfigurator.configure(log4jProperties);

        LOGGER.info("create rpc for client and server");
        RpcManager rpcManager = new MemoryRpcManager(2);
        serverRpc = rpcManager.getRpc(0);
        clientRpc = rpcManager.getRpc(1);

        LOGGER.info("build ");

        config = buildPsiType(args[0]);

        PsiServer<ByteBuffer> server = PsiFactory.createServer(serverRpc, clientRpc.ownParty(), config);
        PsiClient<ByteBuffer> client = PsiFactory.createClient(clientRpc, serverRpc.ownParty(), config);

        server.setTaskId(5);
        client.setTaskId(5);

        byte[] bytesServerSet = hexStringToByteArray(args[1].substring(2)); // (PrivateArgs without '0x')
        byte[] bytesClientSet = hexStringToByteArray(args[2].substring(2));

        Set<ByteBuffer> serverSet = convertByteArrayToByteBufferSet(bytesServerSet);
        Set<ByteBuffer> clientSet = convertByteArrayToByteBufferSet(bytesClientSet);

        //LOGGER.info("ServerSet: {}", setToString(serverSet));
        //LOGGER.info("ClientSet: {}", setToString(clientSet));

        try {
            LOGGER.info("-----test {}，server_size = {}，client_size = {}-----",
                    server.getPtoDesc().getPtoName(), serverSet.size(), clientSet.size()
            );

            PsiServerThread serverThread = new PsiServerThread(server, serverSet, clientSet.size());
            PsiClientThread clientThread = new PsiClientThread(client, clientSet, serverSet.size(), resultHolder);
            StopWatch stopWatch = new StopWatch();

            stopWatch.start();
            serverThread.start();
            clientThread.start();

            serverThread.join();
            clientThread.join();
            stopWatch.stop();
            long time = stopWatch.getTime(TimeUnit.MILLISECONDS);

            LOGGER.info("Server data_packet_num = {}, payload_bytes = {}B, send_bytes = {}B, time = {}ms",
                    serverRpc.getSendDataPacketNum(), serverRpc.getPayloadByteLength(), serverRpc.getSendByteLength(),
                    time
            );
            LOGGER.info("Client data_packet_num = {}, payload_bytes = {}B, send_bytes = {}B, time = {}ms",
                    clientRpc.getSendDataPacketNum(), clientRpc.getPayloadByteLength(), clientRpc.getSendByteLength(),
                    time
            );

            //LOGGER.info("Intersection: {}", setToString(resultHolder.getIntersectionSet()));

            serverRpc.reset();
            clientRpc.reset();

            return resultHolder.getIntersectionSet();

        } catch (InterruptedException e) {
            LOGGER.error("Ocurrió un error: " + e.getMessage(), e);
            return new HashSet<>();
        }
    }

    private static void configurarOpcionesVM() {
        String libPathTool = "/home/marco/mpc4j-1.0.4/mpc4j/mpc4j-native-tool/cmake-build-release";
        String libPathFhe = "/home/marco/mpc4j-1.0.4/mpc4j/mpc4j-native-fhe/cmake-build-release";

        try {
            // Cargar la biblioteca nativa para mpc4j-native-tool
            System.load(libPathTool + "/libmpc4j-native-tool.so");

            // Cargar la biblioteca nativa para mpc4j-native-fhe
            System.load(libPathFhe + "/libmpc4j-native-fhe.so");
        } catch (UnsatisfiedLinkError e) {
            // Manejar la excepción si la carga de la biblioteca falla
            System.err.println("Error al cargar la biblioteca nativa: " + e.getMessage());
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
