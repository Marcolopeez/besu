package org.hyperledger.besu.psi;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;


public class ResultHolder {
    private Set<ByteBuffer> intersectionSet;

    public Set<ByteBuffer> getIntersectionSet() {
        return intersectionSet;
    }

    public void setIntersectionSet(final Set<ByteBuffer> intersectionSet) {
        this.intersectionSet = intersectionSet;
    }
}
