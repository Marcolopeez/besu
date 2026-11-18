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

import static org.hyperledger.besu.evm.worldstate.CodeDelegationHelper.ECDSA_DISABLED_DELEGATION_PREFIX;
import static org.hyperledger.besu.evm.worldstate.CodeDelegationHelper.hasCodeDelegation;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.account.MutableAccount;
import org.hyperledger.besu.evm.frame.ExceptionalHaltReason;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.gascalculator.GasCalculator;
import org.hyperledger.besu.evm.internal.Words;

import org.apache.tuweni.bytes.Bytes;

/**
 * SETSELFDELEGATE (EIP-7851, Draft at ethereum/EIPs af5ea766). Experimental realization: the Draft
 * leaves the opcode TBD and this implementation uses {@code 0xac} (deviation DV-1). It is only
 * registered when enabled by configuration (deviation DV-2).
 *
 * <p>The opcode is self-only: {@code authority} is the current execution-context address. It pops
 * one stack item, whose low 160 bits are the delegate address, and pushes {@code 1} on success or
 * {@code 0} when no state change is made. It costs {@link #SETSELFDELEGATE_GAS} for each execution
 * attempt and halts exceptionally in a static context.
 *
 * <ol>
 *   <li>If the delegate address is zero, push 0 and make no state change.
 *   <li>If the raw code of {@code authority} is exactly 23 bytes and starts with {@code 0xef0100}
 *       or {@code 0xef0101}, set it to {@code 0xef0101 || delegate} and push 1.
 *   <li>Otherwise, push 0 and make no state change.
 * </ol>
 *
 * <p>The write goes to the frame's world updater, so it follows normal revert semantics. The nonce
 * is not changed and no other account is touched.
 */
public class SetSelfDelegateOperation extends AbstractFixedCostOperation {

  /** The opcode (deviation DV-1: TBD in the Draft). */
  public static final int OPCODE = 0xac;

  /** The fixed gas cost of each execution attempt (EIP-7851 {@code SETSELFDELEGATE_GAS}). */
  public static final long SETSELFDELEGATE_GAS = 9_500L;

  private final OperationResult illegalStateChange;

  /**
   * Instantiates a new SETSELFDELEGATE operation.
   *
   * @param gasCalculator the gas calculator
   */
  public SetSelfDelegateOperation(final GasCalculator gasCalculator) {
    super(OPCODE, "SETSELFDELEGATE", 1, 1, gasCalculator, SETSELFDELEGATE_GAS);
    illegalStateChange =
        new OperationResult(SETSELFDELEGATE_GAS, ExceptionalHaltReason.ILLEGAL_STATE_CHANGE);
  }

  @Override
  protected OperationResult executeFixedCostOperation(final MessageFrame frame) {
    if (frame.isStatic()) {
      return illegalStateChange;
    }

    final Address delegate = Words.toAddress(frame.popStackItem());
    if (delegate.equals(Address.ZERO)) {
      frame.pushStackItem(Bytes.EMPTY);
      return successResponse;
    }

    final Address authority = frame.getRecipientAddress();
    // Raw code stored in state for authority, not the code being executed by this frame.
    final Account account = getAccount(authority, frame);
    if (account == null || !hasCodeDelegation(account.getCode())) {
      frame.pushStackItem(Bytes.EMPTY);
      return successResponse;
    }

    final MutableAccount mutableAccount = getMutableAccount(authority, frame);
    mutableAccount.setCode(
        Bytes.concatenate(ECDSA_DISABLED_DELEGATION_PREFIX, delegate.getBytes()));
    frame.pushStackItem(BYTES_ONE);
    return successResponse;
  }
}
