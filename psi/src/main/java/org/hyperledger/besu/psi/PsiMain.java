/*
 * Copyright contributors to Besu.
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
package org.hyperledger.besu.psi;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.common.base.Splitter;
import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.RpcManager;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory.CuckooHashBinType;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiClient;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiConfig;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiFactory;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiServer;
import edu.alibaba.mpc4j.s2pc.pso.psi.hfh99.Hfh99EccPsiConfig;
import edu.alibaba.mpc4j.s2pc.pso.psi.kkrt16.Kkrt16PsiConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PsiMain {
  private static final Logger LOGGER = LoggerFactory.getLogger(PsiMain.class);
  private static final String ELEMENT_DELIMITER = ":";
  private static final int BLOCK_SIZE = 32;

  public static String[] executeClient1(
      final String psiType, final String stringClientSet, final int serverSetSize) {
    // Set VM options to link to the native libraries
    setVMOptions();
    PsiConfig config = buildPsiType(psiType);
    PsiClient<ByteBuffer> client = createClient(config);

    byte[] bytesClientSet =
        hexStringToByteArray(stringClientSet.substring(2)); // (PrivateArgs without '0x')
    Set<ByteBuffer> clientSet = convertByteArrayToByteBufferSet(bytesClientSet);

    BigInteger beta = client.psi_1(clientSet.size(), serverSetSize, clientSet, serverSetSize);
    List<byte[]> hyBetaPayload = client.psi_2(serverSetSize, clientSet.size());

    return new String[] {beta.toString(), bytesListToHexString(hyBetaPayload)};
  }

  public static String[] executeClient2(
      final String psiType,
      final String stringClientSet,
      final String hxAlphaHexString,
      final String peqtHexString,
      final String betaString,
      final int serverSetSize) {
    // Set VM options to link to the native libraries
    setVMOptions();
    PsiConfig config = buildPsiType(psiType);
    PsiClient<ByteBuffer> client = createClient(config);

    byte[] bytesClientSet =
        hexStringToByteArray(stringClientSet.substring(2)); // (PrivateArgs without '0x')
    Set<ByteBuffer> clientSet = convertByteArrayToByteBufferSet(bytesClientSet);
    List<List<byte[]>> reconstructedResult = new ArrayList<>();
    reconstructedResult.add(hexStringToBytesList(hxAlphaHexString));
    reconstructedResult.add(hexStringToBytesList(peqtHexString));

    try {
      Set<ByteBuffer> intersectionSet =
          client.psi_3(
              clientSet.size(),
              serverSetSize,
              clientSet,
              serverSetSize,
              new BigInteger(betaString),
              reconstructedResult);
      return new String[] {setToString(intersectionSet)};
    } catch (MpcAbortException e) {
      LOGGER.error("Error durante la ejecución del cliente 2: {}", e.getMessage(), e);
      return new String[0];
    }
  }

  public static String[] executeServer(
      final String psiType,
      final String stringServerSet,
      final String hyBetaHexString,
      final int clientSetSize) {
    // Set VM options to link to the native libraries
    setVMOptions();
    PsiConfig config = buildPsiType(psiType);
    PsiServer<ByteBuffer> server = createServer(config);

    byte[] bytesServerSet =
        hexStringToByteArray(stringServerSet.substring(2)); // (PrivateArgs without '0x')
    Set<ByteBuffer> serverSet = convertByteArrayToByteBufferSet(bytesServerSet);
    List<byte[]> reconstructedBeta = hexStringToBytesList(hyBetaHexString);

    try {
      List<byte[]>[] result =
          server.psi_1(
              serverSet.size(), clientSetSize, serverSet, clientSetSize, reconstructedBeta);
      return new String[] {bytesListToHexString(result[0]), bytesListToHexString(result[1])};
    } catch (MpcAbortException e) {
      LOGGER.error("Error durante la ejecución del servidor: {}", e.getMessage(), e);
      return new String[0];
    }
  }

  private static void setVMOptions() {
    String libPathTool = "/home/marco/mpc4j-1.0.4/mpc4j/mpc4j-native-tool/cmake-build-release";
    String libPathFhe = "/home/marco/mpc4j-1.0.4/mpc4j/mpc4j-native-fhe/cmake-build-release";

    try {
      // Loading the native library for mpc4j-native-tool and mpc4j-native-fhe
      System.load(libPathTool + "/libmpc4j-native-tool.so");
      System.load(libPathFhe + "/libmpc4j-native-fhe.so");
    } catch (UnsatisfiedLinkError e) {
      LOGGER.error("Error al cargar la biblioteca nativa: {}", e.getMessage());
    }
  }

  private static PsiClient<ByteBuffer> createClient(final PsiConfig config) {
    RpcManager rpcManager = new MemoryRpcManager(2);
    Rpc serverRpc = rpcManager.getRpc(0);
    Rpc clientRpc = rpcManager.getRpc(1);
    PsiClient<ByteBuffer> client = PsiFactory.createClient(clientRpc, serverRpc.ownParty(), config);
    client.setTaskId(5);
    return client;
  }

  private static PsiServer<ByteBuffer> createServer(final PsiConfig config) {
    RpcManager rpcManager = new MemoryRpcManager(2);
    Rpc serverRpc = rpcManager.getRpc(0);
    Rpc clientRpc = rpcManager.getRpc(1);
    PsiServer<ByteBuffer> server = PsiFactory.createServer(serverRpc, clientRpc.ownParty(), config);
    server.setTaskId(5);
    return server;
  }

  public static PsiConfig buildPsiType(final String psiType) {
    switch (psiType) {
      case "HFH99_ECC_COMPRESS":
        return new Hfh99EccPsiConfig.Builder().setCompressEncode(true).build();
      case "HFH99_ECC_UNCOMPRESS":
        return new Hfh99EccPsiConfig.Builder().setCompressEncode(false).build();
      case "KKRT16":
        return new Kkrt16PsiConfig.Builder().build();
      case "KKRT16_NO_STASH_NAIVE":
        return new Kkrt16PsiConfig.Builder()
            .setCuckooHashBinType(CuckooHashBinType.NO_STASH_NAIVE)
            .build();
      case "KKRT16_NAIVE_4_HASH":
        return new Kkrt16PsiConfig.Builder()
            .setCuckooHashBinType(CuckooHashBinType.NAIVE_4_HASH)
            .build();
      default:
        throw new IllegalArgumentException(
            "Argumento no válido. Tipos de PSI válidos: HFH99_ECC_COMPRESS, HFH99_ECC_UNCOMPRESS, KKRT16, KKRT16_NO_STASH_NAIVE, KKRT16_NAIVE_4_HASH");
    }
  }

  private static Set<ByteBuffer> convertByteArrayToByteBufferSet(final byte[] byteArray) {
    Set<ByteBuffer> byteBufferSet = new HashSet<>();
    for (int i = 0; i < byteArray.length; i += BLOCK_SIZE) {
      int endIndex = Math.min(i + BLOCK_SIZE, byteArray.length);
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
      data[i / 2] =
          (byte)
              ((Character.digit(hexString.charAt(i), 16) << 4)
                  + Character.digit(hexString.charAt(i + 1), 16));
    }
    return data;
  }

  public static String bytesListToHexString(final List<byte[]> byteArrayList) {
    StringBuilder hexString = new StringBuilder();
    for (int i = 0; i < byteArrayList.size(); i++) {
      byte[] byteArray = byteArrayList.get(i);
      for (byte b : byteArray) {
        hexString.append(String.format("%02X", b));
      }
      if (i < byteArrayList.size() - 1) {
        hexString.append(ELEMENT_DELIMITER); // Agregar delimitador entre elementos
      }
    }
    return hexString.toString();
  }

  public static List<byte[]> hexStringToBytesList(final String hexString) {
    List<byte[]> byteArrayList = new ArrayList<>();

    Iterable<String> elements = Splitter.onPattern(ELEMENT_DELIMITER).split(hexString);
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
      byteBuffer.position(0);
      byteBuffer.get(bytes);
      for (byte b : bytes) {
        hexString.append(String.format("%02X", b));
      }
    }
    return hexString.toString().trim();
  }
}
