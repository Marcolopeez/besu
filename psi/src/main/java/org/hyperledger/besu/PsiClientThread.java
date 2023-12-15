package org.hyperledger.besu;
import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.s2pc.pso.psi.PsiClient;

import java.nio.ByteBuffer;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


class PsiClientThread extends Thread {
    private final PsiClient<ByteBuffer> psiClient;
    private final Set<ByteBuffer> clientElementSet;
    private final int serverElementSize;
    private Set<ByteBuffer> intersectionSet;
    private static final Logger LOGGER = LoggerFactory.getLogger(PsiMain.class);

    PsiClientThread(final PsiClient<ByteBuffer> psiClient, final Set<ByteBuffer> clientElementSet, final int serverElementSize) {
        this.psiClient = psiClient;
        this.clientElementSet = clientElementSet;
        this.serverElementSize = serverElementSize;
    }

    Set<ByteBuffer> getIntersectionSet() {
        return intersectionSet;
    }

    @Override
    public void run() {
        try {
            psiClient.getRpc().connect();
            psiClient.init(clientElementSet.size(), serverElementSize);
            intersectionSet = psiClient.psi(clientElementSet, serverElementSize);
            psiClient.getRpc().disconnect();
        } catch (MpcAbortException e) {
            LOGGER.error("Ocurrió un error: " + e.getMessage(), e);
        }
    }
}
