# Plan: C1 en Besu (EIP-7851) y ensayos X1

*17-11-2026. Tarea 4 de `ESTADO.md`. Solo planificación: no se ha escrito código de Besu ni de OTS-C1.*

Referencias: `experimentos/ESPECIFICACION.md` §2 y §4; `fuentes/eips/eip-7851.md` (ethereum/EIPs `af5ea766`); D-18, D-20, D-22 y D-23.

**Toda referencia a Besu es al commit `85a51a11dc7f4768700c9e3897f33b0334c5ec0e`** (rama `research/eip-7851`, igual que `main` del fork), comprobado con `git --no-optional-locks -C besu rev-parse HEAD`; coincide con `FUENTES.md`. Abreviaturas de ruta:

- `evm/…` = `besu/evm/src/main/java/org/hyperledger/besu/evm/…`
- `core/…` = `besu/ethereum/core/src/main/java/org/hyperledger/besu/ethereum/…`
- `eth/…` = `besu/ethereum/eth/src/main/java/org/hyperledger/besu/ethereum/eth/…`

Lo leído en el código y no ejecutado es **D** (D-19). Las estimaciones y todo lo marcado «H» son hipótesis.

---

## 0. Resumen para decidir

- **Compilar aquí no es posible.** Ni la VM ni el entorno en la nube alcanzan `services.gradle.org` ni Maven Central (el proxy responde 403), y Besu exige JDK 25 (§1). Hay que compilar en el Mac del autor o habilitar esos dominios.
- **El cambio en Besu es pequeño y localizado.** Seis archivos de producción y uno nuevo (§3). Casi todo el comportamiento de `0xef0101` sale de ampliar un predicado (`CodeDelegationHelper.hasCodeDelegation`) y añadir dos exclusiones.
- **Opcode propuesto: `0xac`** (§5), registrado como desviación DV-1.
- **Estimación (H):** el camino mínimo (C1 + X1 con V1 y fallos FI-1 a FI-4 y FI-8) cuesta **6,5 días de persona seguros, hasta 9,5**. El completo (con V2, FI-5 a FI-7, redelegación y celdas `hc`/`qr`) cuesta **8 seguros, hasta 13**.
- **Frente al 2-12** quedan 15 días naturales, compartidos con las tareas 2 y 3, que tienen prioridad (D-17, D-18). El X1 completo no cabe con margen. El mínimo cabe solo si se empieza el 19–20-11, se compila en el Mac desde el primer día y se superan los hitos de control G1–G3 (§12). Si falla G1 o G2, se envía la versión reducida.

---

## 1. Comprobaciones previas

| Comprobación | Resultado |
|---|---|
| Commit del submódulo | `85a51a11…` = `FUENTES.md`. Árbol limpio |
| JDK requerido | 25 (`besu/gradle/gradle-daemon-jvm.properties`: `toolchainVersion=25`; `besu/build.gradle` l. 55–61 aborta con otra versión) |
| Gradle | 9.3.1 (`besu/gradle/wrapper/gradle-wrapper.properties`), se descarga de `services.gradle.org` |
| Repositorios | Maven Central, `plugins.gradle.org`, `hyperledger.jfrog.io`, `artifacts.consensys.net` y `splunk.jfrog.io` (`besu/build.gradle` l. 176–190; `besu/settings.gradle` l. 19–23) |
| Memoria de Gradle | `-Xmx4g` (`besu/gradle.properties`) |
| **VM (device_bash)** | aarch64, 4 núcleos, **3 GB de RAM**, 8,3 GB libres, **JDK 11**. `github.com` accesible; los ocho dominios de Gradle, Maven y JDK, **no** (17-11, `curl`) |
| **Entorno en la nube** | x86_64, 2 núcleos, 7 GB, JDK 21. Los mismos dominios, **rechazados por el proxy con 403** |
| Conclusión | **No se puede compilar ni ejecutar tests de Besu desde ninguno de los dos entornos.** No se ha clonado una segunda copia porque sin dependencias no serviría |

**Dónde compilar:**

1. **En el Mac del autor (recomendado).** Necesita JDK 25 y RAM ≥ 8 GB (H; no se conocen las características del Mac). Clonar fuera del repositorio del paper, en la rama `research/eip-7851` y el commit `85a51a11`. El tiempo de la primera compilación no está medido (H).
2. **Alternativa:** habilitar en claude.ai (Settings › Capabilities, o el administrador de la organización) los dominios `services.gradle.org`, `plugins.gradle.org`, `repo1.maven.org`, `repo.maven.apache.org`, `hyperledger.jfrog.io`, `artifacts.consensys.net` y `splunk.jfrog.io`, más una fuente de JDK 25. Así Claude compilaría y pasaría los tests unitarios en la nube (2 núcleos: lento, H). La VM no sirve ni con red, porque tiene 3 GB frente a los 4 GB que pide Gradle.

---

## 2. Dónde implementa Besu EIP-7702 (Besu `85a51a11`)

| Pieza | Archivo y clase | Líneas | Qué hace (D) |
|---|---|---|---|
| Indicador `0xef0100` | `evm/worldstate/CodeDelegationHelper.java` | 40, 43, 56–60, 69–71, 83–103 | `CODE_DELEGATION_PREFIX = ef0100`; `hasCodeDelegation` exige exactamente 23 bytes y ese prefijo; `getTargetAddress` corta los 3 primeros bytes; `getTarget` carga el código del destino sin seguir cadenas |
| Escritura del indicador | `evm/worldstate/CodeDelegationService.java` | 40–49, 57–59 | Escribe `ef0100‖d` (o vacía con `d = 0`). `canSetCodeDelegation`: código vacío o `hasCodeDelegation` |
| Lista de autorizaciones | `core/mainnet/CodeDelegationProcessor.java` | 73–97, 99–166, 168–191, 193–215 | Pasos 1–9 de 7702. Una tupla inválida se salta (`touchOnly`, l. 128–131) sin cambiar código ni nonce |
| Invocación en la transacción | `core/mainnet/MainnetTransactionProcessor.java` | 321–328 | Procesa la lista en un `updater` aparte antes de ejecutar |
| Validación de la transacción (bloque) | `core/mainnet/MainnetTransactionProcessor.java` → `MainnetTransactionValidator.java` | 217–240; 294–366 | `validate` y después `validateForSender` con el estado actual del remitente |
| Regla de origen (3607 + 7702) | `core/mainnet/MainnetTransactionValidator.java` | 355–363, 367–369 | `canSendTransaction`: sin código, o `hasCodeDelegation`. Si no, `TX_SENDER_NOT_AUTHORIZED` |
| Validación del pool | `eth/transactions/TransactionPool.java` | 511, 591–606 | Llama a `validateForSender` con `TransactionValidationParams.transactionPool()` sobre el estado de la cabeza |
| Política del pool para delegadas | `eth/transactions/DelegationLimits.java` | 268–275, 441–444 | Límites de pendientes para cuentas con `hasCodeDelegation` |
| Pool tras un bloque | `eth/transactions/TransactionPool.java` | 420–461 | `manageBlockAdded` y `DelegationLimits.blockAdded`. **No revalida el código del remitente** |
| Selección de bloque | `besu/ethereum/blockcreation/.../selectors/ProcessingResultTransactionSelector.java` | 79–116 | Una transacción inválida por motivo no transitorio (incluido `TX_SENDER_NOT_AUTHORIZED`) se borra del pool |
| Ejecución: llamada de nivel superior | `core/mainnet/TopLevelTransactionSupport.java` | 68–89, 118–140 | `accountCode` sigue la delegación si `hasCodeDelegation` |
| Ejecución: familia CALL | `evm/operation/AbstractCallOperation.java` | 252–259, 419–437 | `getCode` sigue la delegación si `hasCodeDelegation` |
| Gas de resolución | `evm/gascalculator/PragueGasCalculator.java` | 108–127 | Coste cálido o frío del destino si `hasCodeDelegation` |
| EXTCODESIZE / EXTCODEHASH / EXTCODECOPY | `evm/operation/ExtCodeSizeOperation.java` l. 65; `ExtCodeHashOperation.java` l. 69; `ExtCodeCopyOperation.java` l. 79 | — | Leen el código bruto de la cuenta: ven el indicador de 23 bytes y no lo siguen |
| CODESIZE / CODECOPY | `evm/operation/CodeSizeOperation.java` l. 36; `CodeCopyOperation.java` l. 48 | — | Usan `frame.getCode()`, el código cargado en el marco |
| Código actualizado en la transacción | `evm/worldstate/UpdateTrackingAccount.java` | 228–258 | `setCode` guarda `updatedCode`, que tiene prioridad en `getOrCreateCachedCode` |
| Opcodes por fork | `evm/MainnetEVMs.java` | 1007–1013 (Prague), 1068–1077 (Osaka), 1142–1160 (Amsterdam), 1438–1446 (futureEips, PAY `0xfc`), 1513–1518 (experimentalEips) | Registro acumulativo por fork |
| Tabla de nombres de opcodes | `evm/code/OpcodeInfo.java` | 244–251, 325 | Solo para imprimir (`evm/Code.java` l. 381–399). `0xa5`–`0xa9`, `0xac` y `0xf6`, sin asignar |
| EVM v2 (experimental) | `evm/EVM.java` | 189–191, 271–272, 659 | Activado por `--Xevm-v2` (desactivado por defecto: `besu/app/.../cli/options/EvmOptions.java` l. 36, 84). Tiene su propia copia de CALL y EXTCODE* (`evm/v2/operation/…`) |
| Forks en el genesis | `besu/config/src/main/java/org/hyperledger/besu/config/JsonGenesisConfigOptions.java` | 376–382 | `futureEipsTime` y `experimentalEipsTime`, además de `pragueTime`, `osakaTime`, etc. |
| Especificación de protocolo por fork | `core/mainnet/MainnetProtocolSpecs.java` | 1359–1405 | `experimentalEips` = `futureEips` (= Bogotá + PAY) con `MainnetEVMs.experimentalEips` |
| Génesis de desarrollo con Prague | `besu/acceptance-tests/tests/src/acceptanceTest/resources/dev/dev_prague.json` | — | `cancunTime: 0`, `pragueTime: 0`, chainId 20211 |
| Prueba de aceptación de 7702 | `besu/acceptance-tests/.../ethereum/CodeDelegationTransactionAcceptanceTest.java` l. 45, 72–77; `PragueAcceptanceTestHelper.java` l. 57, 124–190 | — | Nodo dirigido por Engine API (`engine_forkchoiceUpdatedV3`, `engine_getPayloadV4`, `engine_newPayloadV4`) |
| `ecRecover` | `evm/precompile/ECRECPrecompiledContract.java` l. 39 | — | Sin relación con el código de la cuenta. No hay rastro de EIP-8151 ni 8164 en el árbol (búsqueda) |

---

## 3. Cambios por regla de EIP-7851 (Besu `85a51a11`)

**Idea central (H, apoyada en D):** `hasCodeDelegation` es el único punto donde Besu decide qué es una delegación. Si acepta también `0xef0101`, la ejecución, el gas y EXTCODE* quedan cubiertos. Pero entonces dos sitios que hoy rechazan `0xef0101` «por accidente» empezarían a aceptarlo: la regla de origen y `canSetCodeDelegation`. Ahí hay que añadir exclusiones explícitas.

Alternativa descartada: dejar `hasCodeDelegation` estricto y crear un predicado nuevo para la ejecución. Obliga a tocar unos diez sitios de llamada (§2) y es fácil olvidar uno.

| Regla (7851) | Archivo y clase | Cambio |
|---|---|---|
| Prefijo `0xef0101` (l. 26) | `evm/worldstate/CodeDelegationHelper.java` | Añadir la constante `ECDSA_DISABLED_DELEGATION_PREFIX = ef0101` y el predicado `hasEcdsaDisabledDelegation(code)` (23 bytes y prefijo `ef0101`). Ampliar `hasCodeDelegation` a 23 bytes con `ef0100` **o** `ef0101`. `getTargetAddress` ya vale para los dos (corta 3 bytes) |
| Ejecución idéntica a `0xef0100` (l. 37) | Sin cambios en `TopLevelTransactionSupport`, `AbstractCallOperation`, `AbstractCallOperationV2`, `PragueGasCalculator`, `MainnetTransactionProcessor` l. 957 ni `PrestateTracer` | Se hereda de `hasCodeDelegation` |
| `SETSELFDELEGATE`: un operando, devuelve 0/1 (l. 41–57, 69–71) | **Nuevo** `evm/operation/SetSelfDelegateOperation.java` | `authority = frame.getRecipientAddress()` (el contexto, también bajo DELEGATECALL). Leer el operando y tomar sus 160 bits bajos (`Words.toAddress`, `evm/internal/Words.java` l. 46). Leer el código **bruto** de `authority` desde el `WorldUpdater` del marco. (1) `d = 0`: devolver 0. (2) 23 bytes y prefijo `ef0100` o `ef0101`: `setCode(ef0101‖d)` y devolver 1. (3) En otro caso, 0. No toca el nonce ni otras cuentas |
| Gas 9500 por intento (l. 33, 59, 91) | Mismo archivo, más un método en `evm/gascalculator/GasCalculator.java` (o constante en la operación) | Coste fijo de 9500 antes de evaluar las reglas, también cuando devuelve 0. Sin coste de acceso: `authority` ya está caliente. Comprobar con un test que no se cobra nada más |
| Parada en contexto estático (l. 61) | Mismo archivo | `if (frame.isStatic()) return ILLEGAL_STATE_CHANGE`, como `SelfDestructOperation` y `SStoreOperation` |
| Revert (l. 63) | Ninguno | La escritura va al `WorldUpdater` del marco, que se descarta con el revert (D: `UpdateTrackingAccount` l. 228–258). Probar con los dos modos de `EvmConfiguration.WorldUpdaterMode`, STACKED y JOURNALED (`evm/internal/EvmConfiguration.java`) |
| Código ya cargado (l. 65, 73) | Ninguno | CODESIZE y CODECOPY usan `frame.getCode()`. EXTCODE* leen `account.getCode()` y `getCodeHash()` (§2). Las llamadas posteriores releen el código vía `getOrCreateCachedCode`, donde `updatedCode` tiene prioridad. Solo se necesitan tests |
| Registro del opcode | `evm/MainnetEVMs.java`, `registerPragueOperations` (l. 1007–1013) | `registry.put(new SetSelfDelegateOperation(gasCalculator))` **solo si** el indicador `--Xeip7851-enabled` está activo (DV-2). Por herencia queda también en Osaka y posteriores |
| Indicador de activación | `evm/internal/EvmConfiguration.java` (record, l. 34–41) y `besu/app/src/main/java/org/hyperledger/besu/cli/options/EvmOptions.java` (patrón de `--Xevm-v2`, l. 36 y 84) | Nuevo campo `enableEip7851` y opción `--Xeip7851-enabled`. Hay 9 sitios con `new EvmConfiguration(` (6 en producción) |
| Nombre del opcode | `evm/code/OpcodeInfo.java` l. 251 | `validOpcode("SETSELFDELEGATE", 0xac, 1, 1, 1)`. Solo cosmético |
| EVM v2 | `evm/EVM.java` l. 659 | Sin cambio si v2 sigue desactivada (por defecto, `default ->` delega en `operationsV2[opcode]`). **Pendiente:** comprobar que `OperationsV2.of` envuelve operaciones sin versión v2. No usar `--Xevm-v2` en la devnet |
| Salto de autorizaciones (l. 79) | `evm/worldstate/CodeDelegationService.java`, `canSetCodeDelegation` (l. 57–59) | `… && !hasEcdsaDisabledDelegation(code)`. El procesador ya salta con `touchOnly` (l. 128–131): no cambia el código ni el nonce, y la autoridad queda caliente, como cualquier tupla inválida |
| Rechazo en el bloque (l. 81) | `core/mainnet/MainnetTransactionValidator.java`, `canSendTransaction` (l. 367–369) | `codeHash vacío || (hasCodeDelegation && !hasEcdsaDisabledDelegation)`. Mensaje propio («ECDSA-disabled delegation (EIP-7851)») con el motivo `TX_SENDER_NOT_AUTHORIZED` (DV-4). Se aplica en el bloque (`MainnetTransactionProcessor` l. 236) y en la selección de bloque |
| Rechazo en el pool (l. 81) | Ninguno además del anterior | `TransactionPool` l. 591–606 usa el mismo `validateForSender` sobre el estado de la cabeza |
| Expulsión de pendientes («should», l. 83) | Opcional: `eth/transactions/TransactionPool.java`, `processBlockAddedEvent` (l. 448–461) | No implementar en el mínimo (DV-3). Comportamiento esperado sin cambios (D): la pendiente sigue en el pool hasta la siguiente selección, falla `validateForSender` y `ProcessingResultTransactionSelector` (l. 79–116) la borra. Solo ocurre en el nodo que produce bloques |
| Pool, política de delegadas | `eth/transactions/DelegationLimits.java` l. 268–275, 441–444 | Sin cambio. Con `hasCodeDelegation` ampliado, una cuenta `0xef0101` cuenta como delegada; es irrelevante porque no puede originar transacciones |
| Error RPC (B-8) | `besu/ethereum/api/.../response/RpcErrorType.java` l. 171; `JsonRpcErrorConverter.java` l. 37 | Sin cambio: `-32007`. **Pendiente:** comprobar si `eth_sendRawTransaction` devuelve también el mensaje detallado |

Por qué se pueden aplicar sin condición las reglas de validación (prefijo, salto y rechazo) y solo hace falta condicionar el opcode (H, apoyada en S y D): en un Besu sin el opcode, el código `0xef0101‖d` no puede aparecer en el estado. 7702 solo escribe `ef0100` (`CodeDelegationService` l. 48), y EIP-3541 prohíbe desplegar código que empiece por `0xef` (no hay copia local de 3541; `ContractCreationProcessorTest` lo prueba en Besu). La única entrada posible sería un `alloc` de genesis o un test de estado escrito a mano.

---

## 4. Requisitos de ESPECIFICACION §4 → lugar de cambio (Besu `85a51a11`)

| Id | Lugar | Estado |
|---|---|---|
| B-1 | Commit fijado. Génesis basado en `dev_prague.json` (Prague desde la génesis) más el indicador. Devnet de un nodo dirigida por Engine API (§9): el orden dentro del bloque lo decide la selección por priority fee, y el autor decide cuándo se construye el bloque | Plan en §9 |
| B-2 | `SetSelfDelegateOperation` (nueva), `MainnetEVMs` l. 1007–1013, `EvmConfiguration`, `EvmOptions` y `OpcodeInfo` l. 251 | §3 |
| B-3 | `CodeDelegationHelper` l. 40–60 (ampliación). EXTCODE* sin cambio (l. 65/69/79). Marcos cargados sin cambio (`frame.getCode()`) | §3 |
| B-4 | `CodeDelegationService.canSetCodeDelegation` l. 57–59 | §3 |
| B-5 | `MainnetTransactionValidator.canSendTransaction` l. 367–369 (bloque y pool). Expulsión: DV-3 | §3 |
| B-6 | El mismo cambio que B-5. Hoy ya se cumple, porque `hasCodeDelegation` es estricto (l. 56–60); hay que mantenerlo al ampliarlo | §3 |
| B-7 | Ninguno. `ECRECPrecompiledContract` no depende del código; 8151 y 8164 no están en el árbol | No encontrado = correcto |
| B-8 | `eth_getCode` (código bruto). Error `-32007`. `debug_traceTransaction` (la pila muestra el 0/1 del opcode). `txpool_besuTransactions` y `txpool_content` (`RpcMethod.java` l. 173–178; API `TXPOOL`, `RpcApis.java` l. 30) | Pendiente: mensaje detallado del error |
| B-9 | Con la devnet dirigida por Engine API, F es el bloque que el script marca como `finalizedBlockHash` en `engine_forkchoiceUpdatedV3`. Se fija F = I + 0 (cada bloque se finaliza al construirlo) salvo en FI-9. Alternativa: QBFT de un nodo (inclusión = finalidad; 7702 con Osaka probado en `BftMiningSoakTest.java` l. 392), con menos control del orden | Plan en §9 |
| B-10 | Tests unitarios por regla (§8) y una prueba de aceptación en la devnet (hito H2) | §8, §10 |

---

## 5. Opcode: `0xac` (desviación DV-1)

El Draft deja `SETSELFDELEGATE_OPCODE` como TBD (7851 l. 32). Propuesta: **`0xac`**. Alternativa de reserva: `0xad`.

Justificación:

1. **Libre en Besu `85a51a11`:** `unallocatedOpcode(0xac)` en `evm/code/OpcodeInfo.java` l. 251, y ningún `Operation` lo registra (búsqueda de `super(0x..` y `OPCODE = 0x..` en `evm/operation/`).
2. **No lo asigna ninguna EIP** del repositorio `ethereum/EIPs` en el commit `3db38a3725105cb67b8804ac3e147967113bc3ca` (17-11-2026; búsqueda de `0xac` como opcode en `EIPS/eip-*.md`, sin resultados). Tampoco `0xa5`, `0xa6`, `0xa9`, `0xad` ni `0xaf`.
3. **Se descartan los candidatos naturales del bloque `0xf0`:**
   - `0xf6` lo usa EIP-7819 (`SETDELEGATE`, l. 51), que además escribe indicadores `0xef0100`. Confundirlos en las trazas sería grave. También lo usan EIP-8175 (`RETURNETH`) y EIP-7877, y antes EIP-3074 (`AUTH`).
   - `0xf7`–`0xf9` y `0xfb` los usó EOF y varias propuestas.
   - `0xfc` es PAY (EIP-5920), registrado en `futureEips` (`MainnetEVMs` l. 1438–1446).
4. **No choca con los Drafts que cita el paper:** EIP-8141 usa `0xaa` y `0xb0`–`0xb5`, y EIP-8024 usa `0xe6`–`0xe8`.

**Riesgo:** el bloque `0xa5`–`0xaf` atrae propuestas (`0xa7`: 8298; `0xa8`: 2937; `0xab`: 999; `0xae`: 8081/8163). Si una EIP posterior asigna `0xac`, solo afecta a la reproducibilidad, no a los resultados. Hay que repetir la búsqueda antes del envío.

---

## 6. Desviaciones respecto del Draft (propuestas)

| Id | Desviación | Motivo |
|---|---|---|
| DV-1 | `SETSELFDELEGATE = 0xac` | TBD en el Draft (§5) |
| DV-2 | Se activa con un indicador de línea de órdenes sobre Prague, no con un fork propio. Las reglas de validación de `0xef0101` se aplican siempre | Prague con Engine API está probado en Besu. `experimentalEips` hereda Amsterdam y Bogotá (`MainnetProtocolSpecs` l. 1359–1405), con Engine API y gas distintos (EIP-2780, 7928): más superficie sin necesidad |
| DV-3 | No se expulsan del pool las pendientes al recibir un bloque (el «should» de l. 83). Se borran al seleccionarlas | Lo que ya hace `ProcessingResultTransactionSelector` (l. 79–116). FI-7 lo registra |
| DV-4 | Rechazo con el motivo existente `TX_SENDER_NOT_AUTHORIZED` y un mensaje propio | Evita tocar `TransactionInvalidReason`, `RpcErrorType` y el conversor |

Las cuatro van a DECISIONES como D-24 y D-25 (propuestas).

---

## 7. Lado OTS-C1 (diseño, sin código)

### 7.1 Cómo se emite `SETSELFDELEGATE`

| Opción | Valoración |
|---|---|
| **A. Helper de bytecode crudo invocado con DELEGATECALL (recomendada)** | Un runtime de una docena de bytes: lee la palabra 0 del calldata, ejecuta `0xac` y devuelve el resultado en 32 bytes. Se coloca en el `alloc` del genesis en una dirección fija o se despliega con un initcode a mano. Bajo DELEGATECALL desde el contexto de `a`, `authority = a` (7851 l. 41) y el código bruto es el de `a` (l. 65). OTS-C1 y el proxy se compilan con solc 0.8.30 sin cambios, porque el opcode solo vive en el helper |
| B. Objeto Yul con `verbatim` | `verbatim` solo existe en objetos Yul independientes, no en el ensamblador en línea de Solidity. Habría que compilar con `solc --strict-assembly`, y sería el mismo helper con más herramientas. Pendiente: si Foundry 1.5.1 compila `.yul` en `src/` |
| C. Parchear el bytecode de solc (un marcador sustituido por `0xac`) | Frágil: altera los metadatos y el hash, y es difícil de auditar. Descartada |
| D. Contrato completo en Yul o Huff | Reescribir OTS. Descartada |

**Seguridad del helper (A):**

- Llamado con CALL, ejecuta en su propio contexto: su código no es un indicador y devuelve 0 sin cambios.
- Un tercero que le haga DELEGATECALL solo se afecta a sí mismo.
- El único peligro es un DELEGATECALL desde el contexto de `a`. Por eso OTS-C1 no debe tener DELEGATECALL en el camino operacional (ESPECIFICACION §2.4, último punto).

Coste: unos 9500 de gas más el DELEGATECALL (acceso frío al helper). Hay que medirlo en X1.

### 7.2 Encaje con V1 y D-22

**Discrepancia que hay que resolver:** ESPECIFICACION §2.2 dice `SETSELFDELEGATE(d)`, pero D-22 y §2.4 piden `ind(a) = 0xef0101‖proxy`. Además, si la autorización delega en el proxy `P`, el slot de implementación de `a` todavía está vacío al ejecutar T1. Propuesta (D-26, propuesta):

- La tupla de T1 delega en la **implementación** `d` (OTS-C1): `ind(a) = 0xef0100‖d`.
- `initializeAndRetire(s_1, [ρ_1, ρ_2])`, ejecutada en el contexto de `a`:
  1. inicializa con una llamada externa a sí misma, de modo que `msg.sender == a` (OTS l. 258);
  2. escribe el slot de implementación (por ejemplo, el de ERC-1967) con `d`;
  3. hace DELEGATECALL al helper con `P`;
  4. revierte si el helper no devuelve 1.
- Resultado: `ind(a) = 0xef0101‖P` con el slot igual a `d`. Una sola ejecución de `SETSELFDELEGATE`, como pide D-22. Los marcos ya cargados siguen ejecutando `d` (7851 l. 73), y las llamadas posteriores a `a` pasan por `P`, que lee el slot.
- `P` es un proxy mínimo en Solidity: delega en el slot y revierte si está vacío. Usa opcodes estándar, así que Foundry lo prueba.
- Hay que comprobar que el slot no colisiona con el storage de OTS. OTS usa slots secuenciales y `mapping` (`ots/src/OneTimeSignerAccount.sol` l. 179–195), así que un slot ERC-1967 no colisiona salvo con probabilidad despreciable (A).

**V2:**

- T1 es la migración del TFM con `d` = OTS-C1 (OTS original no tiene función de retirada).
- T2a y T2b llaman a `retire()`.
- Propuesta: **`retire()` sin argumentos**, con `P` fijo como `immutable` de OTS-C1 y solo efectiva desde `0xef0100`. Si aceptara el destino como argumento, un firmante operacional que la alcanzara por T2b (operación con `target = a`, H3) podría dejar `0xef0101‖Adv`, la pérdida irreversible que D-22 quiere evitar. Con el destino fijo, T2b solo hace lo que Alicia quiere.
- Después de la retirada, `SETSELFDELEGATE` no se usa más. La redelegación es una escritura del slot autorizada con una `ρ` (D-22, D-23).

**Redelegación (D-22, D-23):** una función que verifica una firma EIP-712 de una `ρ` activa sobre `(nuevaImplementación, siguienteρ, nonce/dominio)`, consume la `ρ`, registra la sucesora y escribe el slot. Si la sucesora no es válida, pausa en vez de revertir (patrón de OTS l. 500–519). Puntos abiertos para el autor: el esquema exacto del struct; si cambiar la implementación debe exigir que la nueva tenga el mismo layout; y el cambio de nombre de la clave (D-23).

### 7.3 Herramientas contra la devnet

| Herramienta | Uso | Límite |
|---|---|---|
| `forge build` / `forge create` | Compilar y desplegar OTS-C1, `P`, testigos y ERC20Permit | Ninguno: no contienen `0xac` |
| `forge test` (revm) | Lógica de OTS-C1 con un **helper simulado** que registra la llamada y devuelve 1 o 0 (FI-3). El estado `0xef0101` se emula con `vm.etch` para las comprobaciones posteriores | revm no conoce `0xac`: la retirada real solo se prueba en Besu |
| `forge script` | Solo con `--skip-simulation` (pendiente: comprobar el nombre de la opción en 1.5.1); la simulación local con revm fallaría en `0xac` | Mejor no usarlo para T1 |
| `cast send` (`--auth`), `cast wallet sign-auth`, `cast code`, `cast rpc` | T1 de tipo 4, OP-tx, OP-auth, `eth_getCode`, `debug_traceTransaction`, `txpool_*` | `cast` estima el gas con `eth_estimateGas` en el nodo (Besu sí ejecuta `0xac`). Pendiente: opciones exactas en 1.5.1 |
| viem (ya en `ots/wallet`) | Script de X1: `signAuthorization`, envío de tipo 4, orden de envíos, lectura de oráculos | Sin simulación local |
| Script del motor de bloques | Construir bloques bajo demanda (§9) | Hay que escribirlo, copiando `PragueAcceptanceTestHelper` l. 57–190 |
| Anvil | No sirve para C1 | — |

---

## 8. Tests unitarios mínimos por regla (Besu)

Modelos existentes: `besu/evm/src/test/java/org/hyperledger/besu/evm/worldstate/CodeDelegationHelperTest.java`, `…/evm/operation/ExtCode{Size,Hash,Copy}OperationTest.java`, `…/evm/operation/SStoreOperationTest.java`, `…/evm/operation/AbstractCallOperationTest.java`, `…/evm/gascalculator/PragueGasCalculatorTest.java`, `besu/ethereum/core/src/test/java/org/hyperledger/besu/ethereum/mainnet/CodeDelegationProcessorTest.java`, `…/MainnetTransactionValidatorTest.java` y `besu/ethereum/eth/src/test/java/org/hyperledger/besu/ethereum/eth/transactions/DelegatedSenderTransactionPoolTest.java`.

| Regla | Tests (mínimo) |
|---|---|
| Prefijo (l. 26) | `hasCodeDelegation` es verdadero con `ef0101‖x` y falso con 22 o 24 bytes y con `ef0102‖x`. `hasEcdsaDisabledDelegation` solo es verdadero con `ef0101`. `getTargetAddress` sobre `ef0101` |
| Ejecución (l. 37) | Un CALL a una cuenta `ef0101‖d` ejecuta el código de `d`. El gas de resolución es igual que con `ef0100`. Una transacción de nivel superior a `a` ejecuta `d` |
| Opcode: reglas (l. 69–71) | (a) `ef0100‖d` → `ef0101‖x` y devuelve 1. (b) `ef0101‖d` → `ef0101‖x` y devuelve 1. (c) Código vacío → 0, sin cambio. (d) Contrato normal de 23 bytes → 0. (e) `x = 0` → 0, sin cambio. (f) Bits altos sucios con los 160 bajos a 0 → 0. (g) Bits altos sucios con los bajos ≠ 0 → usa los bajos. (h) El nonce no cambia |
| Opcode: contexto (l. 41, 65) | Bajo DELEGATECALL actúa sobre `recipient`, no sobre la dirección del código |
| Gas (l. 33, 59) | 9500 exactos en los casos que devuelven 1 y en los que devuelven 0. Con gas insuficiente, `INSUFFICIENT_GAS` |
| Estático (l. 61) | Bajo STATICCALL, `ILLEGAL_STATE_CHANGE` |
| Revert (l. 63) | Un marco que revierte después del opcode deja el código anterior, en los modos STACKED y JOURNALED |
| Código cargado (l. 73) | En el mismo marco, después del opcode, CODESIZE devuelve el tamaño del código antiguo; EXTCODESIZE(`a`) = 23; EXTCODEHASH = keccak del indicador nuevo; EXTCODECOPY copia el indicador nuevo. Una llamada reentrante a `a` ejecuta el delegado nuevo |
| Salto de autorizaciones (l. 79) | Autoridad con `ef0101`: la tupla se salta, el código y el nonce no cambian, también con `address = 0`. Control: con `ef0100` se aplica |
| Bloque (l. 81) | `validateForSender` con remitente `ef0101`: `TX_SENDER_NOT_AUTHORIZED`, en los tipos 0, 2 y 4. Control: `ef0100` válido |
| Pool (l. 81) | `addTransactionViaApi` desde un remitente `ef0101`: rechazada. Una pendiente que pasa a `ef0101` desaparece en la siguiente selección de bloque (DV-3) |
| Registro | Sin el indicador, `0xac` en Prague es INVALID; con él, existe en Prague y Osaka |

Unos 25 tests. La mayoría son variaciones de tests que ya existen.

---

## 9. Devnet local y despliegue de OTS-C1

1. **Compilar** en el Mac (§1): `./gradlew installDist` (pendiente: confirmar la tarea y el tiempo). El binario queda en `build/install/besu/bin/besu` (H).
2. **Génesis:** copia de `dev_prague.json` con chainId propio y:
   - en `alloc`: `h` (Alicia), relayer, atacante y el helper (§7.1) con su código;
   - nada en `0xef0101` (§3, último párrafo).
3. **Arranque (opciones comprobadas en el código):** `--genesis-file`; `--rpc-http-api` con ETH, NET, WEB3, DEBUG, TXPOOL y ENGINE (`JsonRpcHttpOptions.java` l. 90); `--engine-rpc-port` y `--engine-jwt-disabled` (`EngineRPCOptions.java` l. 40, 52); y la nueva `--Xeip7851-enabled`. **Pendiente:** precio mínimo de gas, `--data-path`, y si hace falta habilitar el RPC del motor aparte. Se toman del acceptance test `createExecutionEngineGenesisNode`.
4. **Motor de bloques:** un script que repite `PragueAcceptanceTestHelper.buildNewBlock` (l. 57–114):
   - `forkchoiceUpdatedV3` con atributos de payload;
   - `getPayloadV4`;
   - `newPayloadV4`;
   - `forkchoiceUpdatedV3` a la nueva cabeza, con `finalized` = la nueva cabeza (B-9).
   
   Para FI-9 (opcional): dos payloads hermanos del mismo padre y un `forkchoiceUpdated` al alternativo (H: no comprobado que Besu lo acepte sin un CL).
5. **Humo:** una transacción 7702 con `cast` contra un delegado trivial, igual que en el acceptance test, primero con Besu sin cambios (H0).
6. **Desplegar OTS-C1:** `forge create` de OTS-C1 (`d`, con `P` como inmutable) y de `P` (o `P` primero, con `d` en el constructor de nada: el slot lo escribe `a`). También testigos, `SenderVault`, `OriginGated` y `ERC20Permit`, si X4 entra.
7. **Oráculos (§0.3 de ESPECIFICACION):** `eth_getCode(a)`, `eth_getStorageAt(a, slot)`, las *views* de OTS a través de `a`, `eth_getBalance`, recibos, el error de `eth_sendRawTransaction`, `txpool_besuTransactions` y `debug_traceTransaction`.

---

## 10. Hitos y escenarios de X1 que habilita cada uno

| Hito | Contenido | Habilita |
|---|---|---|
| **H0** Entorno | JDK 25 en el Mac; compilar el commit; pasar los tests de 7702 existentes; devnet Prague dirigida por Engine API; humo 7702 | Nada de X1; elimina el riesgo de entorno |
| **H1** Besu C1 | Cambios de §3 y tests de §8 | B-2 a B-6 a nivel unitario |
| **H2** Aceptación en devnet | Besu C1 en la devnet, con el helper y un delegado trivial (sin OTS-C1) | B-10; OP-tx, OP-auth y OP-permit tras una retirada directa; EXTCODE*; **FI-1**, **FI-3**, **FI-4**, **FI-7**, **FI-8** a nivel de protocolo; FI-9 opcional |
| **H3** OTS-C1 | `initializeAndRetire`, `retire()`, `P`, redelegación con `ρ`; tests Foundry con el helper simulado | Lógica de C1-cl-O, C1-ql-O y C1-qr-O en Foundry (OP-redel, OP-adv) |
| **H4a** X1-V1 | T1 de §2.2 en la devnet | **C1-cl-M**, **C1-ql-M** (mismo ensayo con otra entrega de claves), **FI-2**, FI-3 y FI-4 con OTS-C1 (FI-3 necesita una variante de prueba sin la comprobación del valor devuelto), **C1-hc-M** en los dos órdenes, **C1-qr-M** (carrera con la autorización del atacante; FI-8) |
| **H4b** X1-V2 y control | T1 + T2a/T2b; ejecuciones de control | **FI-5**, **FI-6**, FI-7 con OTS; C1-cl-O/R y C1-hc-O/R (una ejecución de control cada una); OP-redel en Besu |
| H5 (fuera de X1) | X4 en C1 | X4-1 a X4-4 en Besu |

---

## 11. Riesgos

| Riesgo | Impacto | Mitigación |
|---|---|---|
| R1. Sin compilación en la VM ni en la nube | Cada cambio de Besu depende de una compilación del autor; ciclo lento | Compilar en el Mac desde H0, o habilitar los dominios para la nube (§1) |
| R2. Ampliar `hasCodeDelegation` toca más de lo previsto (DelegationLimits, PrestateTracer, tests existentes que asuman `ef0101` ≠ delegación) | Fallos en la suite | Pasar los tests de `evm`, `ethereum:core` y `ethereum:eth`. Si algo se rompe, volver al predicado separado (§3) |
| R3. Comprobaciones de estilo de Besu (spotless, errorprone, javadoc obligatorio en `evm`) | Compilación rota por formato | `./gradlew spotlessApply`; javadoc desde el principio |
| R4. Motor de bloques por Engine API | Retraso en H0/H2 | Copiar el JSON de `PragueAcceptanceTestHelper`. Alternativa: QBFT de un nodo (B-9) |
| R5. Foundry: `forge script` y la simulación con revm | Fallos opacos | Usar `cast` y viem para todo lo que toque `0xac` |
| R6. Diseño de OTS-C1 abierto: §2.2 frente a D-22, `retire()` con argumento, esquema de la redelegación | Retraso en H3 | Decidir D-26 antes de H3 |
| R7. El Draft cambia (`af5ea766`, 05-11) | Desfase con la versión en línea | Volver a comprobar el commit antes del envío (`VERSIONES.md`) |
| R8. Competencia con las tareas 2 y 3 | X1 no llega | Hitos G1–G3 (§12) |
| R9. EVM v2 activada por error | `0xac` sin implementar en v2 | No usar `--Xevm-v2`. Pendiente: confirmar el comportamiento de `OperationsV2.of` |

---

## 12. Estimación (días de persona; H, no medida)

| Hito | Seguro | Incierto (+) | Fuente de la incertidumbre |
|---|---|---|---|
| H0 Entorno | 1,0 | 1,0 | Primera compilación, JDK 25, motor de bloques |
| H1 Besu C1 + tests | 2,5 | 1,0 | Comprobaciones de estilo, el indicador en 9 constructores, efectos de R2 |
| H2 Aceptación en devnet | 1,0 | 0,5 | Orden en el pool, mensajes de error |
| H3 OTS-C1 (mínimo para V1: 1,0 + 0,5) | 2,0 | 1,5 | Puntos abiertos de D-22/D-23 |
| H4a X1-V1 | 1,0 | 0,5 | Carreras (`qr`, `hc`) |
| H4b X1-V2 y control | 0,5 | 0,5 | — |
| **Total completo** | **8,0** | **+5,0** → hasta 13 | |
| **Camino mínimo** (H0, H1, H2, H3 mínimo, H4a) | **6,5** | **+3,0** → hasta 9,5 | |

**Comparación con el 2-12 (miércoles, AoE):**

- Del 18-11 al 2-12 hay 15 días naturales. Hay que restar:
  - la tarea 2 (abstract, el 25-11);
  - la tarea 3 (versión reducida: X2–X4 bajo C0, costes y reescritura del manuscrito), que tiene prioridad y no está estimada aquí;
  - la redacción de los resultados de Besu en el paper (≈ 1 día, no incluido arriba).
- **X1 completo: no llega** con margen razonable.
- **Camino mínimo: posible pero justo.** Exige empezar el 19–20-11 y unos 7 días dedicados, con compilación en el Mac desde el primer día o con la nube habilitada.

**Hitos de control (propuesta):**

| Control | Fecha límite | Condición | Si no se cumple |
|---|---|---|---|
| G1 | 21-11 | H0 hecho: Besu compila y la devnet Prague produce bloques con una 7702 | Versión reducida (D-18) |
| G2 | 25-11 | H1 hecho: tests de B-2 a B-6 en verde | Versión reducida; Besu pasa a trabajo posterior |
| G3 | 29-11 | H4a con C1-cl-M y FI-2 a FI-4 | Se envía sin X1, o con H2 solo como validación de la realización (sin afirmar celdas de la matriz) |
| Corte | 1-12 | Redacción | — |

---

## 13. No encontrado / pendiente (no supuesto)

- Que `OperationsV2.of` cubra una operación sin versión v2 (solo afecta si se activa `--Xevm-v2`).
- Si `eth_sendRawTransaction` devuelve el mensaje detallado además de `-32007`.
- Las opciones exactas para arrancar la devnet además de las comprobadas (§9.3), y si Besu acepta reorgs por `forkchoiceUpdated` sin CL (FI-9).
- Nombres exactos de las opciones de Foundry 1.5.1 (`--skip-simulation`, `cast send --auth`, `cast wallet sign-auth`) y si compila `.yul`.
- Tiempo de compilación y memoria necesaria en el Mac del autor.
- EIP-3541 no tiene copia local en `fuentes/`.
