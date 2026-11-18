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
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.EVM;
import org.hyperledger.besu.evm.MainnetEVMs;
import org.hyperledger.besu.evm.account.MutableAccount;
import org.hyperledger.besu.evm.frame.ExceptionalHaltReason;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.PragueGasCalculator;
import org.hyperledger.besu.evm.internal.EvmConfiguration;
import org.hyperledger.besu.evm.operation.Operation.OperationResult;
import org.hyperledger.besu.evm.testutils.FakeBlockValues;
import org.hyperledger.besu.evm.testutils.TestMessageFrameBuilder;
import org.hyperledger.besu.evm.toy.ToyWorld;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;

import java.math.BigInteger;
import java.util.OptionalInt;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.jupiter.api.Test;

/** Tests for SETSELFDELEGATE (EIP-7851, Draft; experimental opcode 0xac). */
class SetSelfDelegateOperationTest {

  private static final Bytes EF0100 = Bytes.fromHexString("ef0100");
  private static final Bytes EF0101 = Bytes.fromHexString("ef0101");
  private static final Address AUTHORITY =
      Address.fromHexString("0xa11ce00000000000000000000000000000000001");
  private static final Address HELPER =
      Address.fromHexString("0x4e1e900000000000000000000000000000000002");
  private static final Address OLD_DELEGATE =
      Address.fromHexString("0xd000000000000000000000000000000000000001");
  private static final Address NEW_DELEGATE =
      Address.fromHexString("0xd000000000000000000000000000000000000002");
  private static final long GAS = SetSelfDelegateOperation.SETSELFDELEGATE_GAS;

  private final PragueGasCalculator gasCalculator = new PragueGasCalculator();
  private final SetSelfDelegateOperation operation = new SetSelfDelegateOperation(gasCalculator);
  private final ToyWorld world = new ToyWorld();
  private final WorldUpdater updater = world.updater();

  private static Bytes indicator(final Bytes prefix, final Address delegate) {
    return Bytes.concatenate(prefix, delegate.getBytes());
  }

  private static Bytes word(final Address address) {
    return Bytes32.leftPad(address.getBytes());
  }

  private MutableAccount authorityWithCode(final Bytes code) {
    final MutableAccount account = updater.getOrCreate(AUTHORITY);
    account.setBalance(Wei.of(1));
    account.setNonce(7);
    account.setCode(code);
    return account;
  }

  private MessageFrame frame(final Bytes stackItem) {
    return frameBuilder().pushStackItem(stackItem).build();
  }

  private TestMessageFrameBuilder frameBuilder() {
    return new TestMessageFrameBuilder()
        .worldUpdater(updater)
        .blockValues(new FakeBlockValues(1337))
        .address(AUTHORITY)
        .contract(AUTHORITY);
  }

  private static UInt256 top(final MessageFrame frame) {
    return UInt256.fromBytes(frame.getStackItem(0));
  }

  private Bytes codeOf(final Address address) {
    return updater.get(address).getCode();
  }

  // --- Rules (7851 l. 69-71) ---

  @Test
  void fromEnabledDelegationDisablesEcdsaAndSetsDelegate() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isNull();
    assertThat(result.getGasCost()).isEqualTo(GAS);
    assertThat(top(frame)).isEqualTo(UInt256.ONE);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0101, NEW_DELEGATE));
    assertThat(updater.get(AUTHORITY).getNonce()).isEqualTo(7);
  }

  @Test
  void fromDisabledDelegationRedelegatesAndStaysDisabled() {
    authorityWithCode(indicator(EF0101, OLD_DELEGATE));
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isNull();
    assertThat(top(frame)).isEqualTo(UInt256.ONE);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0101, NEW_DELEGATE));
  }

  @Test
  void sameDelegateFromDisabledDelegationStillReturnsOne() {
    authorityWithCode(indicator(EF0101, OLD_DELEGATE));
    final MessageFrame frame = frame(word(OLD_DELEGATE));

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ONE);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0101, OLD_DELEGATE));
  }

  @Test
  void emptyCodeIsNoOp() {
    authorityWithCode(Bytes.EMPTY);
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isNull();
    assertThat(result.getGasCost()).isEqualTo(GAS);
    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(AUTHORITY)).isEqualTo(Bytes.EMPTY);
  }

  @Test
  void nonExistentAuthorityIsNoOp() {
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isNull();
    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(updater.get(AUTHORITY)).isNull();
  }

  @Test
  void regularContractOf23BytesIsNoOp() {
    final Bytes regular = Bytes.concatenate(Bytes.fromHexString("600035"), OLD_DELEGATE.getBytes());
    assertThat(regular.size()).isEqualTo(23);
    authorityWithCode(regular);
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(AUTHORITY)).isEqualTo(regular);
  }

  @Test
  void otherEf01PrefixIsNoOp() {
    final Bytes other = indicator(Bytes.fromHexString("ef0102"), OLD_DELEGATE);
    authorityWithCode(other);
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(AUTHORITY)).isEqualTo(other);
  }

  @Test
  void wrongSizeIndicatorIsNoOp() {
    final Bytes longer = Bytes.concatenate(indicator(EF0100, OLD_DELEGATE), Bytes.of(0));
    authorityWithCode(longer);
    final MessageFrame frame = frame(word(NEW_DELEGATE));

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(AUTHORITY)).isEqualTo(longer);
  }

  @Test
  void zeroDelegateIsNoOp() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame = frame(Bytes32.ZERO);

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isNull();
    assertThat(result.getGasCost()).isEqualTo(GAS);
    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  @Test
  void dirtyHighBitsWithZeroLow160BitsIsNoOp() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final Bytes dirty = UInt256.valueOf(2).pow(UInt256.valueOf(160)); // low 160 bits are zero
    final MessageFrame frame = frame(dirty);

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  @Test
  void dirtyHighBitsUseLow160Bits() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final Bytes dirty =
        UInt256.fromBytes(word(NEW_DELEGATE)).add(UInt256.valueOf(2).pow(UInt256.valueOf(160)));
    final MessageFrame frame = frame(dirty);

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ONE);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0101, NEW_DELEGATE));
  }

  // --- Context (7851 l. 41, 65) ---

  @Test
  void actsOnExecutionContextNotOnCodeAddress() {
    // DELEGATECALL-like frame: recipient (context) is AUTHORITY, code comes from HELPER.
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MutableAccount helper = updater.getOrCreate(HELPER);
    helper.setCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame =
        frameBuilder().contract(HELPER).pushStackItem(word(NEW_DELEGATE)).build();

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ONE);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0101, NEW_DELEGATE));
    assertThat(codeOf(HELPER)).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  @Test
  void calledInItsOwnContextOnAContractIsNoOp() {
    // CALL to the helper: the context is the helper itself, whose code is not an indicator.
    final MutableAccount helper = updater.getOrCreate(HELPER);
    final Bytes helperCode = Bytes.fromHexString("5f35ac5f5260205ff3");
    helper.setCode(helperCode);
    final MessageFrame frame =
        frameBuilder().address(HELPER).contract(HELPER).pushStackItem(word(NEW_DELEGATE)).build();

    operation.execute(frame, null);

    assertThat(top(frame)).isEqualTo(UInt256.ZERO);
    assertThat(codeOf(HELPER)).isEqualTo(helperCode);
  }

  // --- Gas, static context and stack (7851 l. 33, 59, 61) ---

  @Test
  void insufficientGasHaltsWithoutStateChange() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame =
        frameBuilder().initialGas(GAS - 1).pushStackItem(word(NEW_DELEGATE)).build();

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isEqualTo(ExceptionalHaltReason.INSUFFICIENT_GAS);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  @Test
  void exactGasIsEnough() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame =
        frameBuilder().initialGas(GAS).pushStackItem(word(NEW_DELEGATE)).build();

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isNull();
    assertThat(result.getGasCost()).isEqualTo(GAS);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0101, NEW_DELEGATE));
  }

  @Test
  void staticContextHaltsWithoutStateChange() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame =
        frameBuilder().isStatic(true).pushStackItem(word(NEW_DELEGATE)).build();

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isEqualTo(ExceptionalHaltReason.ILLEGAL_STATE_CHANGE);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  @Test
  void emptyStackHalts() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final MessageFrame frame = frameBuilder().build();

    final OperationResult result = operation.execute(frame, null);

    assertThat(result.getHaltReason()).isEqualTo(ExceptionalHaltReason.INSUFFICIENT_STACK_ITEMS);
    assertThat(codeOf(AUTHORITY)).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  // --- Revert (7851 l. 63) ---

  @Test
  void changeIsDiscardedWhenTheFrameUpdaterIsNotCommitted() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    updater.commit();
    final WorldUpdater child = updater.updater();
    final MessageFrame frame =
        new TestMessageFrameBuilder()
            .worldUpdater(child)
            .blockValues(new FakeBlockValues(1337))
            .address(AUTHORITY)
            .contract(AUTHORITY)
            .pushStackItem(word(NEW_DELEGATE))
            .build();

    operation.execute(frame, null);

    assertThat(child.get(AUTHORITY).getCode()).isEqualTo(indicator(EF0101, NEW_DELEGATE));
    // the frame reverts: its updater is dropped without commit
    assertThat(updater.get(AUTHORITY).getCode()).isEqualTo(indicator(EF0100, OLD_DELEGATE));
  }

  // --- Loaded code (7851 l. 65, 73) ---

  @Test
  void loadedCodeIsUnchangedWhileExtCodeSeesTheNewIndicator() {
    authorityWithCode(indicator(EF0100, OLD_DELEGATE));
    final Bytes delegateCode = Bytes.fromHexString("5f35ac5f5260205ff3"); // 9 bytes
    final MessageFrame frame =
        frameBuilder().code(new Code(delegateCode)).pushStackItem(word(NEW_DELEGATE)).build();

    operation.execute(frame, null);
    assertThat(top(frame)).isEqualTo(UInt256.ONE);
    frame.popStackItem();

    new CodeSizeOperation(gasCalculator).execute(frame, null);
    assertThat(top(frame).toInt()).isEqualTo(delegateCode.size());
    frame.popStackItem();

    frame.pushStackItem(word(AUTHORITY));
    new ExtCodeSizeOperation(gasCalculator).execute(frame, null);
    assertThat(top(frame).toInt()).isEqualTo(23);
    frame.popStackItem();

    frame.pushStackItem(word(AUTHORITY));
    new ExtCodeHashOperation(gasCalculator).execute(frame, null);
    assertThat(Bytes32.leftPad(frame.getStackItem(0)))
        .isEqualTo(Hash.hash(indicator(EF0101, NEW_DELEGATE)).getBytes());
  }

  // --- Registration (DV-2) ---

  private static boolean registered(final EVM evm) {
    final Operation op = evm.getOperationsUnsafe()[SetSelfDelegateOperation.OPCODE];
    return op instanceof SetSelfDelegateOperation;
  }

  private static EvmConfiguration eip7851(final boolean enabled) {
    return new EvmConfiguration(
        EvmConfiguration.DEFAULT.jumpDestCacheWeightKB(),
        EvmConfiguration.DEFAULT.worldUpdaterMode(),
        EvmConfiguration.DEFAULT.enableOptimizedOpcodes(),
        false,
        enabled);
  }

  @Test
  void disabledByDefault() {
    assertThat(EvmConfiguration.DEFAULT.enableEip7851()).isFalse();
    assertThat(registered(MainnetEVMs.prague(EvmConfiguration.DEFAULT))).isFalse();
  }

  @Test
  void registeredInPragueAndLaterOnlyWhenEnabled() {
    assertThat(registered(MainnetEVMs.prague(eip7851(false)))).isFalse();
    assertThat(registered(MainnetEVMs.prague(eip7851(true)))).isTrue();
    assertThat(registered(MainnetEVMs.osaka(BigInteger.ONE, eip7851(true)))).isTrue();
    assertThat(registered(MainnetEVMs.cancun(eip7851(true)))).isFalse();
  }

  @Test
  void overridesKeepTheFlag() {
    final EvmConfiguration config =
        eip7851(true).overrides(OptionalInt.empty(), OptionalInt.empty(), OptionalInt.empty());
    assertThat(config.enableEip7851()).isTrue();
  }
}
