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
package org.hyperledger.besu.evm.worldstate;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.evm.account.MutableAccount;
import org.hyperledger.besu.evm.toy.ToyWorld;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/** canSetCodeDelegation, including the EIP-7851 (Draft) skip rule for 0xef0101 authorities. */
class CodeDelegationServiceTest {

  private static final Address AUTHORITY = Address.fromHexString("0xa11ce");
  private static final Address DELEGATE =
      Address.fromHexString("0xd0000000000000000000000000000000000000d1");

  private final CodeDelegationService service = new CodeDelegationService();
  private final WorldUpdater updater = new ToyWorld().updater();

  private MutableAccount accountWithCode(final Bytes code) {
    final MutableAccount account = updater.getOrCreate(AUTHORITY);
    account.setCode(code);
    return account;
  }

  @Test
  void nullAccountCannotSetDelegation() {
    assertThat(service.canSetCodeDelegation(null)).isFalse();
  }

  @Test
  void emptyCodeCanSetDelegation() {
    assertThat(service.canSetCodeDelegation(accountWithCode(Bytes.EMPTY))).isTrue();
  }

  @Test
  void enabledDelegationCanBeChanged() {
    final Bytes code = Bytes.concatenate(Bytes.fromHexString("ef0100"), DELEGATE.getBytes());
    assertThat(service.canSetCodeDelegation(accountWithCode(code))).isTrue();
  }

  @Test
  void ecdsaDisabledDelegationCannotBeChangedByAnAuthorization() {
    final Bytes code = Bytes.concatenate(Bytes.fromHexString("ef0101"), DELEGATE.getBytes());
    assertThat(service.canSetCodeDelegation(accountWithCode(code))).isFalse();
  }

  @Test
  void regularContractCannotSetDelegation() {
    assertThat(service.canSetCodeDelegation(accountWithCode(Bytes.fromHexString("600035"))))
        .isFalse();
  }

  @Test
  void processCodeDelegationStillWritesEnabledIndicator() {
    final MutableAccount account = accountWithCode(Bytes.EMPTY);
    service.processCodeDelegation(account, DELEGATE);
    assertThat(account.getCode())
        .isEqualTo(Bytes.concatenate(Bytes.fromHexString("ef0100"), DELEGATE.getBytes()));
  }
}
