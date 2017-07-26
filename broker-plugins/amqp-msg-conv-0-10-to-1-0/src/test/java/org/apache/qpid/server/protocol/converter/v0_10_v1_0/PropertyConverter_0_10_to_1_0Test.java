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

package org.apache.qpid.server.protocol.converter.v0_10_v1_0;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mockito.Matchers.booleanThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.apache.qpid.server.bytebuffer.QpidByteBuffer;
import org.apache.qpid.server.model.NamedAddressSpace;
import org.apache.qpid.server.protocol.converter.MessageConversionException;
import org.apache.qpid.server.protocol.v0_10.MessageMetaData_0_10;
import org.apache.qpid.server.protocol.v0_10.MessageTransferMessage;
import org.apache.qpid.server.protocol.v0_10.transport.DeliveryProperties;
import org.apache.qpid.server.protocol.v0_10.transport.MessageDeliveryMode;
import org.apache.qpid.server.protocol.v0_10.transport.MessageDeliveryPriority;
import org.apache.qpid.server.protocol.v0_10.transport.MessageProperties;
import org.apache.qpid.server.protocol.v0_10.transport.ReplyTo;
import org.apache.qpid.server.protocol.v1_0.Message_1_0;
import org.apache.qpid.server.protocol.v1_0.type.Binary;
import org.apache.qpid.server.protocol.v1_0.type.messaging.Header;
import org.apache.qpid.server.protocol.v1_0.type.messaging.Properties;
import org.apache.qpid.server.store.StoredMessage;
import org.apache.qpid.test.utils.QpidTestCase;

public class PropertyConverter_0_10_to_1_0Test extends QpidTestCase
{
    private NamedAddressSpace _namedAddressSpace;
    private MessageConverter_0_10_to_1_0 _messageConverter;

    @Override
    public void setUp() throws Exception
    {
        super.setUp();
        _namedAddressSpace = mock(NamedAddressSpace.class);
        _messageConverter = new MessageConverter_0_10_to_1_0();
    }

    public void testContentTypeConversion()
    {
        String contentType = "test-content-type";

        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setContentType(contentType);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected content type", contentType, properties.getContentType().toString());
    }


    public void testContentTypeJavaObjectStreamConversion()
    {
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setContentType("application/java-object-stream");
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected content type",
                     "application/x-java-serialized-object",
                     properties.getContentType().toString());
    }

    public void testContentEncodingConversion()
    {
        String contentEncoding = "my-test-encoding";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setContentEncoding(contentEncoding);
        MessageTransferMessage message = createTestMessage(new DeliveryProperties(), messageProperties, new byte[]{(byte)1}, 0);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected content encoding", contentEncoding, properties.getContentEncoding().toString());
    }

    public void testHeaderConversion()
    {
        Map<String, Object> headers = new HashMap<>();
        headers.put("testProperty1", "testProperty1Value");
        headers.put("intProperty", 1);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();
        assertEquals("Unexpected application applicationProperties", headers, new HashMap<>(applicationProperties));
    }

    public void testHeaderConversionWhenQpidSubjectIsPresent()
    {
        String testSubject = "testSubject";
        Map<String, Object> headers = new HashMap<>();
        headers.put("testProperty1", "testProperty1Value");
        headers.put("qpid.subject", testSubject);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected subject", testSubject, properties.getSubject());
        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();
        assertFalse("Unexpected subject in application properties", applicationProperties.containsKey("qpid.subject"));
    }


    public void testPersistentDeliveryModeConversion()
    {
        final DeliveryProperties deliveryProperties = new DeliveryProperties();
        deliveryProperties.setDeliveryMode(MessageDeliveryMode.PERSISTENT);
        MessageTransferMessage message = createTestMessage(deliveryProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Header header = convertedMessage.getHeaderSection().getValue();
        assertTrue("Unexpected durable header", header.getDurable());
    }

    public void testNonPersistentDeliveryModeConversion()
    {
        final DeliveryProperties deliveryProperties = new DeliveryProperties();
        deliveryProperties.setDeliveryMode(MessageDeliveryMode.NON_PERSISTENT);
        MessageTransferMessage message = createTestMessage(deliveryProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Header header = convertedMessage.getHeaderSection().getValue();
        assertFalse("Unexpected durable header", header.getDurable());
    }

    public void testPriorityConversion()
    {
        final byte priority = 5;
        final DeliveryProperties deliveryProperties = new DeliveryProperties();
        deliveryProperties.setPriority(MessageDeliveryPriority.get(priority));
        MessageTransferMessage message = createTestMessage(deliveryProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Header header = convertedMessage.getHeaderSection().getValue();
        assertEquals("Unexpected priority", priority, header.getPriority().byteValue());
    }

    public void testCorrelationIdConversion()
    {
        final String correlationId = "testCorrelationId";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setCorrelationId(correlationId.getBytes());
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected correlationId", correlationId, new String(((Binary)properties.getCorrelationId()).getArray(), UTF_8));
    }

    public void testReplyToConversionWhenExchangeAndRoutingKeySpecified()
    {
        final String exchangeName = "amq.direct";
        final String routingKey = "test_routing_key";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setReplyTo(new ReplyTo(exchangeName, routingKey));
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected reply-to", "amq.direct/test_routing_key", properties.getReplyTo());
    }

    public void testReplyToConversionWhenExchangeSpecified()
    {
        final String exchangeName = "amq.direct";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setReplyTo(new ReplyTo(exchangeName, null));
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected reply-to", exchangeName, properties.getReplyTo());
    }

    public void testReplyToConversionWhenRoutingKeySpecified()
    {
        final String routingKey = "test_routing_key";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setReplyTo(new ReplyTo(null, routingKey));
        MessageTransferMessage message = createTestMessage(messageProperties);


        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected reply-to", routingKey, properties.getReplyTo());
    }

    public void testReplyToConversionWhenExchangeIsEmptyStringAndRoutingKeySpecified()
    {
        final String routingKey = "test_routing_key";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setReplyTo(new ReplyTo("", routingKey));
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected reply-to", "test_routing_key", properties.getReplyTo());
    }

    public void testReplyToConversionWhenExchangeAndRoutingKeyAreNull()
    {
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setReplyTo(new ReplyTo(null, null));
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertNull("Unexpected reply-to", properties.getReplyTo());
    }

        public void testExpirationConversion()
        {
            long timestamp = System.currentTimeMillis();
            int ttl = 100000;
            final long expiration = timestamp + ttl;

            final DeliveryProperties deliveryProperties = new DeliveryProperties();
            deliveryProperties.setExpiration(expiration);
            MessageTransferMessage message = createTestMessage(deliveryProperties, new MessageProperties(), null, timestamp);

            final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

            Properties properties = convertedMessage.getPropertiesSection().getValue();
            assertEquals("Unexpected expiration", expiration, properties.getAbsoluteExpiryTime().getTime());
        }

    public void testTTLConversion()
    {
        long timestamp = System.currentTimeMillis();
        int ttl = 100000;

        final DeliveryProperties deliveryProperties = new DeliveryProperties();
        deliveryProperties.setTtl(ttl);
        MessageTransferMessage message = createTestMessage(deliveryProperties, new MessageProperties(), null, timestamp);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Header header = convertedMessage.getHeaderSection().getValue();
        assertEquals("Unexpected TTL", ttl, header.getTtl().longValue());
    }

    public void testMessageIdConversion()
    {
        UUID messageId = UUID.randomUUID();
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setMessageId(messageId);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected messageId", messageId, properties.getMessageId());
    }

    public void testTimestampConversion()
    {
        final DeliveryProperties deliveryProperties = new DeliveryProperties();
        final long timestamp = System.currentTimeMillis() - 1000;
        deliveryProperties.setTimestamp(timestamp);
        MessageTransferMessage message = createTestMessage(deliveryProperties);
        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected creation timestamp", timestamp, properties.getCreationTime().getTime());
    }

    public void testJmsTypeConversion()
    {
        final String type = "test-type";
        final Map<String, Object> headers = Collections.singletonMap("x-jms-type", type);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected subject", type, properties.getSubject());
        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();
        assertFalse("Unexpected x-jms-type in application properties", applicationProperties.containsKey("x-jms-type"));
    }

    public void testQpidSubjectTakesPrecedenceOverJmsType()
    {
        final String jmsType = "test-jms-type";
        final String qpidSubjectType = "test-qpid-type";
        final Map<String, Object> headers = new HashMap<>();
        headers.put("x-jms-type", jmsType);
        headers.put("qpid.subject", qpidSubjectType);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected subject", qpidSubjectType, properties.getSubject());
        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();
        assertTrue("Unexpected entries in application properties", applicationProperties.isEmpty());
    }

    public void testUserIdConversion()
    {
        final String userId = "test-userId";
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setUserId(userId.getBytes());
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();
        assertEquals("Unexpected user-id", userId, new String(properties.getUserId().getArray(), UTF_8));
    }

    public void testHeaderJMSXGroupIdConversion()
    {
        String testGroupId = "testGroupId";
        Map<String, Object> headers = Collections.singletonMap("JMSXGroupID", testGroupId);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();

        assertEquals("Unexpected group-id", testGroupId, properties.getGroupId());

        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();
        assertFalse("Unexpected JMSXGroupID in application properties",
                    applicationProperties.containsKey("JMSXGroupID"));
    }

    public void testHeaderJMSXGroupSeqConversion()
    {
        int testGroupSequenceNumber = 1;
        Map<String, Object> headers = Collections.singletonMap("JMSXGroupSeq", testGroupSequenceNumber);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();

        assertEquals("Unexpected group-sequence", testGroupSequenceNumber, properties.getGroupSequence().intValue());

        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();
        assertFalse("Unexpected JMSXGroupSeq in application properties",
                    applicationProperties.containsKey("JMSXGroupSeq"));
    }

    public void testHeaderJMSXGroupSeqConversionWhenWrongType()
    {
        short testGroupSequenceNumber = (short) 1;
        Map<String, Object> headers = Collections.singletonMap("JMSXGroupSeq", testGroupSequenceNumber);
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();

        assertEquals("Unexpected group-sequence", null, properties.getGroupSequence());

        Map<String, Object> applicationProperties = convertedMessage.getApplicationPropertiesSection().getValue();

        assertTrue("JMSXGroupSeq was removed from application properties",
                   applicationProperties.containsKey("JMSXGroupSeq"));
    }

    public void testHeaderWithMapValueConversionFails()
    {
        Map<String, Object> headers = Collections.singletonMap("mapHeader", Collections.emptyMap());
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        try
        {
            _messageConverter.convert(message, _namedAddressSpace);
            fail("Exception is expected");
        }
        catch (MessageConversionException e)
        {
            // pass
        }
    }

    public void testHeaderWithListValueConversionFails()
    {
        Map<String, Object> headers = Collections.singletonMap("listHeader", Collections.emptyList());
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        try
        {
            _messageConverter.convert(message, _namedAddressSpace);
            fail("Exception is expected");
        }
        catch (MessageConversionException e)
        {
            // pass
        }
    }

    public void testHeaderWithArrayValueConversionFails()
    {
        Map<String, Object> headers = Collections.singletonMap("listHeader", new int[]{1});
        final MessageProperties messageProperties = new MessageProperties();
        messageProperties.setApplicationHeaders(headers);
        MessageTransferMessage message = createTestMessage(messageProperties);

        try
        {
            _messageConverter.convert(message, _namedAddressSpace);
            fail("Exception is expected");
        }
        catch (MessageConversionException e)
        {
            // pass
        }
    }

    public void testExchangeRoutingKeyConversion()
    {
        final String testExchange = "testExchange";
        final String testRoutingKey = "testRoutingKey";
        final DeliveryProperties deliveryProperties = new DeliveryProperties();
        deliveryProperties.setExchange(testExchange);
        deliveryProperties.setRoutingKey(testRoutingKey);
        MessageTransferMessage message = createTestMessage(deliveryProperties);

        final Message_1_0 convertedMessage = _messageConverter.convert(message, _namedAddressSpace);

        Properties properties = convertedMessage.getPropertiesSection().getValue();

        assertEquals("Unexpected to", testExchange + "/" + testRoutingKey, properties.getTo());
    }

    private MessageTransferMessage createTestMessage(final DeliveryProperties deliveryProperties)
    {
        return createTestMessage(deliveryProperties, new MessageProperties(), null, 0);
    }

    private MessageTransferMessage createTestMessage(final MessageProperties messageProperties)
    {
        return createTestMessage(new DeliveryProperties(), messageProperties, null, 0);
    }

    private MessageTransferMessage createTestMessage(final DeliveryProperties deliveryProperties,
                                                     final MessageProperties messageProperties,
                                                     final byte[] content,
                                                     final long arrivalTime)
    {
        int bodySize = content == null ? 0 : content.length;
        final org.apache.qpid.server.protocol.v0_10.transport.Header header = new org.apache.qpid.server.protocol.v0_10.transport.Header(deliveryProperties, messageProperties);
        final MessageMetaData_0_10 metaData = new MessageMetaData_0_10(header, bodySize, arrivalTime);

        final StoredMessage<MessageMetaData_0_10> storedMessage = mock(StoredMessage.class);
        when(storedMessage.getMetaData()).thenReturn(metaData);

        if (content != null)
        {
            when(storedMessage.getContentSize()).thenReturn(content.length);
            when(storedMessage.getContent(0, content.length)).thenReturn(Collections.singleton(QpidByteBuffer.wrap(
                    content)));
        }
        return new MessageTransferMessage(storedMessage, null);
    }
}