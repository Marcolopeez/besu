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
package org.hyperledger.besu.evm.operation;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.account.MutableAccount;
import org.hyperledger.besu.evm.fluent.EVMExecutor;
import org.hyperledger.besu.evm.fluent.EvmSpec;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.toy.ToyWorld;

import java.math.BigInteger;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.jupiter.api.Test;

/**
 * End-to-end execution of SETSELFDELEGATE (EIP-7851, Draft; experimental opcode 0xac) in a Prague
 * EVM, through a raw-bytecode helper reached with DELEGATECALL (besu/PLAN.md §7.1, option A).
 *
 * <p>The account {@code A} is delegated with {@code 0xef0100 || D}. The test runs D's code in the
 * context of A (as a top-level call to A would). D:
 *
 * <ol>
 *   <li>DELEGATECALLs the helper H with calldata P; H runs {@code SETSELFDELEGATE(P)} in A's
 *       context and returns its result, which D stores in slot 0;
 *   <li>CALLs A itself (re-entrant call) and stores the returned word in slot 1. P returns 0x42;
 *   <li>stores EXTCODESIZE(A) in slot 2 and CODESIZE in slot 3;
 *   <li>stops, or reverts in the revert variant.
 * </ol>
 *
 * <p>The world is a {@link ToyWorld}: {@code SimpleWorld} does not propagate code changes from a
 * child updater to its parent ({@code SimpleAccount.commit()} copies only balance, nonce and
 * storage), so a {@code setCode} made inside a call frame would be lost there.
 */
class SetSelfDelegateExecutionTest {

  private static final Address A =
      Address.fromHexString("0x00000000000000000000000000000000000000a1");
  private static final Address D =
      Address.fromHexString("0x00000000000000000000000000000000000000d1");
  private static final Address P =
      Address.fromHexString("0x00000000000000000000000000000000000000b1");
  private static final Address H =
      Address.fromHexString("0x00000000000000000000000000000000000000c1");

  // PUSH0 CALLDATALOAD SETSELFDELEGATE PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
  private static final Bytes HELPER_CODE = Bytes.fromHexString("0x5f35ac5f5260205ff3");
  // PUSH1 0x42 PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
  private static final Bytes P_CODE = Bytes.fromHexString("0x60425f5260205ff3");

  private static final String D_BODY =
      "73"
          + hex(P)
          + "5f52" // mem[0..32] = P
          + "6020"
          + "6020"
          + "6020"
          + "5f"
          + "73"
          + hex(H)
          + "5a"
          + "f4"
          + "50" // DELEGATECALL H
          + "602051"
          + "5f55" // slot0 = helper result (mem[0x20])
          + "6020"
          + "6040"
          + "5f5f5f"
          + "30"
          + "5a"
          + "f1"
          + "50" // CALL A (re-entrant)
          + "604051"
          + "600155" // slot1 = word returned by A (mem[0x40])
          + "303b"
          + "600255" // slot2 = EXTCODESIZE(A)
          + "38"
          + "600355"; // slot3 = CODESIZE (code of the running frame)
  private static final Bytes D_CODE_STOP = Bytes.fromHexString(D_BODY + "00");
  private static final Bytes D_CODE_REVERT = Bytes.fromHexString(D_BODY + "5f5ffd");

  private static String hex(final Address address) {
    return address.getBytes().toUnprefixedHexString();
  }

  private static Bytes indicator(final String prefix, final Address delegate) {
    return Bytes.concatenate(Bytes.fromHexString(prefix), delegate.getBytes());
  }

  private static EvmConfiguration config(final boolean eip7851) {
    return new EvmConfiguration(
        EvmConfiguration.DEFAULT.jumpDestCacheWeightKB(),
        EvmConfiguration.DEFAULT.worldUpdaterMode(),
        EvmConfiguration.DEFAULT.enableOptimizedOpcodes(),
        false,
        eip7851);
  }

  private static ToyWorld world(final Bytes dCode) {
    final ToyWorld world = new ToyWorld();
    final MutableAccount a = world.createAccount(A, 0, Wei.of(1));
    a.setCode(indicator("ef0100", D));
    world.createAccount(D, 1, Wei.ZERO).setCode(dCode);
    world.createAccount(P, 1, Wei.ZERO).setCode(P_CODE);
    world.createAccount(H, 1, Wei.ZERO).setCode(HELPER_CODE);
    return world;
  }

  private static void run(final ToyWorld world, final Bytes dCode, final boolean eip7851) {
    new EVMExecutor(EvmSpec.prague(BigInteger.ONE, config(eip7851)))
        .worldUpdater(world.updater())
        .commitWorldState()
        .gas(1_000_000L)
        .sender(Address.fromHexString("0x00000000000000000000000000000000000000e1"))
        .receiver(A)
        .contract(A)
        .code(dCode)
        .execute();
  }

  private static UInt256 slot(final ToyWorld world, final long key) {
    return world.get(A).getStorageValue(UInt256.valueOf(key));
  }

  @Test
  void retiresEcdsaAndLaterCallsFollowTheNewDelegation() {
    final ToyWorld world = world(D_CODE_STOP);

    run(world, D_CODE_STOP, true);

    assertThat(world.get(A).getCode()).isEqualTo(indicator("ef0101", P));
    assertThat(slot(world, 0)).isEqualTo(UInt256.ONE); // SETSELFDELEGATE returned 1
    assertThat(slot(world, 1)).isEqualTo(UInt256.valueOf(0x42)); // re-entrant call ran P
    assertThat(slot(world, 2)).isEqualTo(UInt256.valueOf(23)); // EXTCODESIZE sees the indicator
    assertThat(slot(world, 3)).isEqualTo(UInt256.valueOf(D_CODE_STOP.size())); // CODESIZE: D
    assertThat(world.get(A).getNonce()).isZero();
    assertThat(world.get(H).getCode()).isEqualTo(HELPER_CODE);
  }

  @Test
  void revertOfTheFrameRestoresTheEnabledDelegation() {
    final ToyWorld world = world(D_CODE_REVERT);

    run(world, D_CODE_REVERT, true);

    assertThat(world.get(A).getCode()).isEqualTo(indicator("ef0100", D));
    assertThat(slot(world, 0)).isEqualTo(UInt256.ZERO);
    assertThat(slot(world, 1)).isEqualTo(UInt256.ZERO);
  }

  @Test
  void withoutTheFlagTheOpcodeIsInvalidAndNothingChanges() {
    final ToyWorld world = world(D_CODE_STOP);

    run(world, D_CODE_STOP, false);

    // the helper halts on the invalid opcode, so DELEGATECALL returns 0 and writes no return data.
    // (The re-entrant call then follows the old delegation and recurses into D until gas runs
    // out; only the code of A and the slot written before that call are checked.)
    assertThat(world.get(A).getCode()).isEqualTo(indicator("ef0100", D));
    assertThat(slot(world, 0)).isEqualTo(UInt256.ZERO);
  }
}
