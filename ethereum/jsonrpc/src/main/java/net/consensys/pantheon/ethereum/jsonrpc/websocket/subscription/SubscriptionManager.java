package net.consensys.pantheon.ethereum.jsonrpc.websocket.subscription;

import net.consensys.pantheon.ethereum.jsonrpc.internal.results.JsonRpcResult;
import net.consensys.pantheon.ethereum.jsonrpc.websocket.subscription.request.SubscribeRequest;
import net.consensys.pantheon.ethereum.jsonrpc.websocket.subscription.request.SubscriptionType;
import net.consensys.pantheon.ethereum.jsonrpc.websocket.subscription.request.UnsubscribeRequest;
import net.consensys.pantheon.ethereum.jsonrpc.websocket.subscription.response.SubscriptionResponse;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.eventbus.Message;
import io.vertx.core.json.Json;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The SubscriptionManager is responsible for managing subscriptions and sending messages to the
 * clients that have an active subscription subscription.
 *
 * <p>TODO: The logic to send a notification to a client that has an active subscription TODO:
 * handle connection close (remove subscriptions)
 */
public class SubscriptionManager extends AbstractVerticle {

  private static final Logger LOG = LogManager.getLogger();

  public static final String EVENTBUS_REMOVE_SUBSCRIPTIONS_ADDRESS =
      "SubscriptionManager::removeSubscriptions";

  private final AtomicLong subscriptionCounter = new AtomicLong(0);
  private final Map<Long, Subscription> subscriptions = new HashMap<>();
  private final Map<String, List<Long>> connectionSubscriptionsMap = new HashMap<>();
  private final SubscriptionBuilder subscriptionBuilder = new SubscriptionBuilder();

  @Override
  public void start() {
    vertx.eventBus().consumer(EVENTBUS_REMOVE_SUBSCRIPTIONS_ADDRESS, this::removeSubscriptions);
  }

  public Long subscribe(final SubscribeRequest request) {
    LOG.info("Subscribe request {}", request);

    final long subscriptionId = subscriptionCounter.incrementAndGet();
    final Subscription subscription = subscriptionBuilder.build(subscriptionId, request);
    addSubscription(subscription, request.getConnectionId());

    return subscription.getId();
  }

  private void addSubscription(final Subscription subscription, final String connectionId) {
    subscriptions.put(subscription.getId(), subscription);
    mapSubscriptionToConnection(connectionId, subscription.getId());
  }

  private void mapSubscriptionToConnection(final String connectionId, final Long subscriptionId) {
    if (connectionSubscriptionsMap.containsKey(connectionId)) {
      connectionSubscriptionsMap.get(connectionId).add(subscriptionId);
    } else {
      connectionSubscriptionsMap.put(connectionId, Lists.newArrayList(subscriptionId));
    }
  }

  public boolean unsubscribe(final UnsubscribeRequest request) {
    LOG.debug("Unsubscribe request subscriptionId = {}", request.getSubscriptionId());

    if (!subscriptions.containsKey(request.getSubscriptionId())) {
      throw new SubscriptionNotFoundException(request.getSubscriptionId());
    }

    destroySubscription(request.getSubscriptionId(), request.getConnectionId());

    return true;
  }

  private void destroySubscription(final long subscriptionId, final String connectionId) {
    subscriptions.remove(subscriptionId);

    if (connectionSubscriptionsMap.containsKey(connectionId)) {
      removeSubscriptionToConnectionMapping(connectionId, subscriptionId);
    }
  }

  private void removeSubscriptionToConnectionMapping(
      final String connectionId, final Long subscriptionId) {
    if (connectionSubscriptionsMap.get(connectionId).size() > 1) {
      connectionSubscriptionsMap.get(connectionId).remove(subscriptionId);
    } else {
      connectionSubscriptionsMap.remove(connectionId);
    }
  }

  @VisibleForTesting
  void removeSubscriptions(final Message<String> message) {
    final String connectionId = message.body();
    if (connectionId == null || "".equals(connectionId)) {
      LOG.warn("Received invalid connectionId ({}). No subscriptions removed.");
    }

    LOG.debug("Removing subscription for connectionId = {}", connectionId);

    final List<Long> subscriptionIds =
        Lists.newArrayList(
            connectionSubscriptionsMap.getOrDefault(connectionId, Lists.newArrayList()));
    subscriptionIds.forEach(subscriptionId -> destroySubscription(subscriptionId, connectionId));
  }

  @VisibleForTesting
  Map<Long, Subscription> subscriptions() {
    return Maps.newHashMap(subscriptions);
  }

  @VisibleForTesting
  public Map<String, List<Long>> getConnectionSubscriptionsMap() {
    return Maps.newHashMap(connectionSubscriptionsMap);
  }

  public <T> List<T> subscriptionsOfType(final SubscriptionType type, final Class<T> clazz) {
    return subscriptions
        .entrySet()
        .stream()
        .map(Entry::getValue)
        .filter(subscription -> subscription.isType(type))
        .map(subscriptionBuilder.mapToSubscriptionClass(clazz))
        .collect(Collectors.toList());
  }

  public void sendMessage(final Long subscriptionId, final JsonRpcResult msg) {
    final SubscriptionResponse response = new SubscriptionResponse(subscriptionId, msg);

    connectionSubscriptionsMap
        .entrySet()
        .stream()
        .filter(e -> e.getValue().contains(subscriptionId))
        .map(Entry::getKey)
        .findFirst()
        .ifPresent(connectionId -> vertx.eventBus().send(connectionId, Json.encode(response)));
  }
}
