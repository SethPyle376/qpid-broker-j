/*
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */
package org.apache.qpid.systests.jms_1_1.extensions.routing;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.jms.Connection;
import javax.jms.Destination;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.junit.jupiter.api.Test;

import org.apache.qpid.server.model.Exchange;
import org.apache.qpid.server.model.Protocol;
import org.apache.qpid.systests.JmsTestBase;

public class MessageRoutingTest extends JmsTestBase
{
    private static final String EXCHANGE_NAME = "testExchange";
    private static final String QUEUE_NAME = "testQueue";
    private static final String ROUTING_KEY = "testRoute";

    @Test
    public void testRoutingWithSubjectSetAsJMSMessageType() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();
        
        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            
            Destination sendingDestination = session.createTopic(EXCHANGE_NAME);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");
            message.setJMSType(ROUTING_KEY);

            MessageProducer messageProducer = session.createProducer(sendingDestination);
            messageProducer.send(message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    

    @Test
    public void testAnonymousRelayRoutingWithSubjectSetAsJMSMessageType() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();

        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Destination sendingDestination = session.createTopic(EXCHANGE_NAME);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");
            message.setJMSType(ROUTING_KEY);

            MessageProducer messageProducer = session.createProducer(null);
            messageProducer.send(sendingDestination, message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    @Test
    public void testRoutingWithRoutingKeySetAsJMSProperty() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();

        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

            Destination sendingDestination = session.createTopic(EXCHANGE_NAME);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");
            message.setStringProperty("routing_key", ROUTING_KEY);

            MessageProducer messageProducer = session.createProducer(sendingDestination);
            messageProducer.send(message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    @Test
    public void testRoutingWithExchangeAndRoutingKeyDestination() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();

        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

            Destination sendingDestination = session.createTopic(EXCHANGE_NAME + "/" + ROUTING_KEY);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");

            MessageProducer messageProducer = session.createProducer(sendingDestination);
            messageProducer.send(message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    @Test
    public void testAnonymousRelayRoutingWithExchangeAndRoutingKeyDestination() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();

        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

            Destination sendingDestination = session.createTopic(EXCHANGE_NAME + "/" + ROUTING_KEY);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");

            MessageProducer messageProducer = session.createProducer(null);
            messageProducer.send(sendingDestination, message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    @Test
    public void testRoutingToQueue() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();

        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

            Destination sendingDestination = session.createQueue(QUEUE_NAME);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");

            MessageProducer messageProducer = session.createProducer(sendingDestination);
            messageProducer.send(message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    @Test
    public void testAnonymousRelayRoutingToQueue() throws Exception
    {
        assumeTrue(is(equalTo(Protocol.AMQP_1_0)).matches(getProtocol()), "AMQP 1.0 test");

        prepare();

        Connection connection = getConnection();
        try
        {
            connection.start();
            Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);

            Destination sendingDestination = session.createQueue(QUEUE_NAME);
            Destination receivingDestination = session.createQueue(QUEUE_NAME);

            Message message = session.createTextMessage("test");

            MessageProducer messageProducer = session.createProducer(null);
            messageProducer.send(sendingDestination, message);

            MessageConsumer messageConsumer = session.createConsumer(receivingDestination);
            Message receivedMessage = messageConsumer.receive(getReceiveTimeout());

            assertNotNull(receivedMessage, "Message not received");
            assertEquals("test", ((TextMessage) message).getText());
        }
        finally
        {
            connection.close();
        }
    }

    private void prepare() throws Exception
    {
        createEntityUsingAmqpManagement(EXCHANGE_NAME, "org.apache.qpid.DirectExchange",
                                        Collections.singletonMap(Exchange.UNROUTABLE_MESSAGE_BEHAVIOUR, "REJECT"));
        createEntityUsingAmqpManagement(QUEUE_NAME, "org.apache.qpid.Queue", Collections.emptyMap());

        final Map<String, Object> arguments = new HashMap<>();
        arguments.put("destination", QUEUE_NAME);
        arguments.put("bindingKey", ROUTING_KEY);
        performOperationUsingAmqpManagement(EXCHANGE_NAME, "bind", "org.apache.qpid.Exchange", arguments);
    }
}
