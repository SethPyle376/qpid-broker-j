/*
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
 */

package org.apache.qpid.systests.jms_1_1.extensions.message;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;

import javax.jms.Connection;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.MessageFormatException;
import javax.jms.MessageProducer;
import javax.jms.ObjectMessage;
import javax.jms.Queue;
import javax.jms.Session;

import org.junit.jupiter.api.Test;

import org.apache.qpid.systests.JmsTestBase;

public class ObjectMessageClassAllowlistingTest extends JmsTestBase
{
    private static final int TEST_VALUE = 37;

    @Test
    public void testObjectMessage() throws Exception
    {
        Queue destination = createQueue(getTestName());
        final Connection c = getConnectionBuilder().setDeserializationPolicyAllowList("*").build();
        try
        {
            c.start();
            Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageConsumer _consumer = s.createConsumer(destination);
            MessageProducer _producer = s.createProducer(destination);

            sendTestObjectMessage(s, _producer);
            Message receivedMessage = _consumer.receive(getReceiveTimeout());
            assertNotNull(receivedMessage, "did not receive message within receive timeout");
            assertTrue(receivedMessage instanceof ObjectMessage, "message is of wrong type");
            ObjectMessage receivedObjectMessage = (ObjectMessage) receivedMessage;
            Object payloadObject = receivedObjectMessage.getObject();
            assertTrue(payloadObject instanceof HashMap, "payload is of wrong type");

            @SuppressWarnings("unchecked")
            HashMap<String, Integer> payload = (HashMap<String, Integer>) payloadObject;
            assertEquals((Integer) TEST_VALUE, payload.get("value"), "payload has wrong value");
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testNotAllowListedByConnectionUrlObjectMessage() throws Exception
    {
        Queue destination = createQueue(getTestName());
        final Connection c = getConnectionBuilder().setDeserializationPolicyAllowList("org.apache.qpid").build();
        try
        {
            c.start();
            Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageConsumer consumer = s.createConsumer(destination);
            MessageProducer producer = s.createProducer(destination);

            sendTestObjectMessage(s, producer);
            Message receivedMessage = consumer.receive(getReceiveTimeout());
            assertNotNull(receivedMessage, "did not receive message within receive timeout");
            assertTrue(receivedMessage instanceof ObjectMessage, "message is of wrong type");
            ObjectMessage receivedObjectMessage = (ObjectMessage) receivedMessage;
            try
            {
                receivedObjectMessage.getObject();
                fail("should not deserialize class");
            }
            catch (MessageFormatException e)
            {
                // pass
            }
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testAllowListedClassByConnectionUrlObjectMessage() throws Exception
    {
        Queue destination = createQueue(getTestName());
        final Connection c =
                getConnectionBuilder().setDeserializationPolicyAllowList("java.util.HashMap,java.lang").build();
        try
        {
            c.start();
            Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageConsumer consumer = s.createConsumer(destination);
            MessageProducer producer = s.createProducer(destination);

            sendTestObjectMessage(s, producer);
            Message receivedMessage = consumer.receive(getReceiveTimeout());
            assertNotNull(receivedMessage, "did not receive message within receive timeout");
            assertTrue(receivedMessage instanceof ObjectMessage, "message is of wrong type");
            ObjectMessage receivedObjectMessage = (ObjectMessage) receivedMessage;

            @SuppressWarnings("unchecked")
            HashMap<String, Integer> object = (HashMap<String, Integer>) receivedObjectMessage.getObject();
            assertEquals((Integer) TEST_VALUE, object.get("value"), "Unexpected value");
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testDenyListedClassByConnectionUrlObjectMessage() throws Exception
    {
        Queue destination = createQueue(getTestName());
        final Connection c = getConnectionBuilder().setDeserializationPolicyAllowList("java")
                                                   .setDeserializationPolicyDenyList("java.lang.Integer")
                                                   .build();
        try
        {
            c.start();
            Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
            MessageConsumer consumer = s.createConsumer(destination);
            MessageProducer producer = s.createProducer(destination);

            sendTestObjectMessage(s, producer);
            Message receivedMessage = consumer.receive(getReceiveTimeout());
            assertNotNull(receivedMessage, "did not receive message within receive timeout");
            assertTrue(receivedMessage instanceof ObjectMessage, "message is of wrong type");
            ObjectMessage receivedObjectMessage = (ObjectMessage) receivedMessage;

            try
            {
                receivedObjectMessage.getObject();
                fail("Should not be allowed to deserialize black listed class");
            }
            catch (JMSException e)
            {
                // pass
            }
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testAllowListedAnonymousClassByConnectionUrlObjectMessage() throws Exception
    {
        final Connection c =
                getConnectionBuilder().setDeserializationPolicyAllowList(ObjectMessageClassAllowlistingTest.class.getCanonicalName())
                                      .build();
        try
        {
            doTestAllowListedEnclosedClassTest(c, createAnonymousObject(TEST_VALUE));
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testDenyListedAnonymousClassByConnectionUrlObjectMessage() throws Exception
    {
        final Connection c = getConnectionBuilder()
                .setDeserializationPolicyAllowList(ObjectMessageClassAllowlistingTest.class.getPackage().getName())
                .setDeserializationPolicyDenyList(ObjectMessageClassAllowlistingTest.class.getCanonicalName())
                .build();
        try
        {
            doTestDenyListedEnclosedClassTest(c, createAnonymousObject(TEST_VALUE));
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testAllowListedNestedClassByConnectionUrlObjectMessage() throws Exception
    {
        final Connection c = getConnectionBuilder()
                .setDeserializationPolicyAllowList(ObjectMessageClassAllowlistingTest.NestedClass.class.getCanonicalName())
                .build();
        try
        {
            doTestAllowListedEnclosedClassTest(c, new NestedClass(TEST_VALUE));
        }
        finally
        {
            c.close();
        }
    }

    @Test
    public void testDenyListedNestedClassByConnectionUrlObjectMessage() throws Exception
    {
        final Connection c = getConnectionBuilder()
                .setDeserializationPolicyAllowList(ObjectMessageClassAllowlistingTest.class.getCanonicalName())
                .setDeserializationPolicyDenyList(NestedClass.class.getCanonicalName())
                .build();
        try
        {
            doTestDenyListedEnclosedClassTest(c, new NestedClass(TEST_VALUE));
        }
        finally
        {
            c.close();
        }
    }

    private void doTestAllowListedEnclosedClassTest(Connection c, Serializable content) throws Exception
    {
        Queue destination = createQueue(getTestName());
        c.start();
        Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
        MessageConsumer consumer = s.createConsumer(destination);
        MessageProducer producer = s.createProducer(destination);

        final ObjectMessage sendMessage = s.createObjectMessage();
        sendMessage.setObject(content);
        producer.send(sendMessage);

        Message receivedMessage = consumer.receive(getReceiveTimeout());
        assertNotNull(receivedMessage, "did not receive message within receive timeout");
        assertTrue(receivedMessage instanceof ObjectMessage, "message is of wrong type");
        Object receivedObject = ((ObjectMessage) receivedMessage).getObject();
        assertEquals(content.getClass(), receivedObject.getClass(), "Received object has unexpected class");
        assertEquals(content, receivedObject, "Received object has unexpected content");
    }

    private void doTestDenyListedEnclosedClassTest(final Connection c, final Serializable content) throws Exception
    {
        Queue destination = createQueue(getTestName());
        c.start();
        Session s = c.createSession(false, Session.AUTO_ACKNOWLEDGE);
        MessageConsumer consumer = s.createConsumer(destination);
        MessageProducer producer = s.createProducer(destination);

        final ObjectMessage sendMessage = s.createObjectMessage();
        sendMessage.setObject(content);
        producer.send(sendMessage);

        Message receivedMessage = consumer.receive(getReceiveTimeout());
        assertNotNull(receivedMessage, "did not receive message within receive timeout");
        assertTrue(receivedMessage instanceof ObjectMessage, "message is of wrong type");
        try
        {
            ((ObjectMessage) receivedMessage).getObject();
            fail("Exception not thrown");
        }
        catch (MessageFormatException e)
        {
            // pass
        }
    }

    private void sendTestObjectMessage(final Session s, final MessageProducer producer) throws JMSException
    {
        HashMap<String, Integer> messageContent = new HashMap<>();
        messageContent.put("value", TEST_VALUE);
        Message objectMessage = s.createObjectMessage(messageContent);
        producer.send(objectMessage);
    }

    public static Serializable createAnonymousObject(final int field)
    {
        return new Serializable()
        {
            private final int _field = field;

            @Override
            public int hashCode()
            {
                return _field;
            }

            @Override
            public boolean equals(final Object o)
            {
                if (this == o)
                {
                    return true;
                }
                if (o == null || getClass() != o.getClass())
                {
                    return false;
                }

                final Serializable that = (Serializable) o;

                return getFieldValueByReflection(that).equals(_field);
            }

            private Object getFieldValueByReflection(final Serializable that)
            {
                try
                {
                    final Field f = that.getClass().getDeclaredField("_field");
                    f.setAccessible(true);
                    return f.get(that);
                }
                catch (NoSuchFieldException | IllegalAccessException e)
                {
                    throw new RuntimeException(e);
                }
            }
        };
    }

    public static class NestedClass implements Serializable
    {
        private final int _field;

        public NestedClass(final int field)
        {
            _field = field;
        }

        @Override
        public boolean equals(final Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || getClass() != o.getClass())
            {
                return false;
            }

            final NestedClass that = (NestedClass) o;

            return _field == that._field;
        }

        @Override
        public int hashCode()
        {
            return _field;
        }
    }
}
