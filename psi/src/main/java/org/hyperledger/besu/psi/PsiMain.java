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
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;


public class PsiMain {
    private static final Logger LOGGER = LoggerFactory.getLogger(PsiMain.class);

    //private static final SecureRandom SECURE_RANDOM = new SecureRandom();


    private static final int ELEMENT_BYTE_LENGTH = CommonConstants.BLOCK_BYTE_LENGTH;

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

    public static void main(final String[] args) throws Exception {
        // Configurar opciones de VM
        configurarOpcionesVM();

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

        int serverSize = 1;
        int clientSize = 1;

        try {
            LOGGER.info("-----test {}，server_size = {}，client_size = {}-----",
                    server.getPtoDesc().getPtoName(), serverSize, clientSize
            );
            // 生成集合
            ArrayList<Set<ByteBuffer>> sets = PsoUtils.generateBytesSets(serverSize, clientSize, ELEMENT_BYTE_LENGTH);
            Set<ByteBuffer> serverSet = sets.get(0);
            Set<ByteBuffer> clientSet = sets.get(1);

            PsiServerThread serverThread = new PsiServerThread(server, serverSet, clientSet.size());
            PsiClientThread clientThread = new PsiClientThread(client, clientSet, serverSet.size());
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
            serverRpc.reset();
            clientRpc.reset();

        } catch (InterruptedException e) {
            LOGGER.error("Ocurrió un error: " + e.getMessage(), e);
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
}
