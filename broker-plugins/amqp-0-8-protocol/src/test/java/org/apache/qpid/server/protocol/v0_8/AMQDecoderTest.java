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
package org.apache.qpid.server.protocol.v0_8;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.apache.qpid.server.bytebuffer.QpidByteBuffer;
import org.apache.qpid.server.protocol.ProtocolVersion;
import org.apache.qpid.server.protocol.v0_8.transport.AMQBody;
import org.apache.qpid.server.protocol.v0_8.transport.AMQDataBlock;
import org.apache.qpid.server.protocol.v0_8.transport.AMQFrame;
import org.apache.qpid.server.protocol.v0_8.transport.AMQProtocolVersionException;
import org.apache.qpid.server.protocol.v0_8.transport.BasicContentHeaderProperties;
import org.apache.qpid.server.protocol.v0_8.transport.ContentBody;
import org.apache.qpid.server.protocol.v0_8.transport.ContentHeaderBody;
import org.apache.qpid.server.protocol.v0_8.transport.FrameCreatingMethodProcessor;
import org.apache.qpid.server.protocol.v0_8.transport.HeartbeatBody;
import org.apache.qpid.server.transport.ByteBufferSender;
import org.apache.qpid.test.utils.UnitTestBase;

class AMQDecoderTest extends UnitTestBase
{
    private static final ByteBuffer EMPTY_BYTE_BUFFER = ByteBuffer.allocate(0);
    private ClientDecoder _decoder;
    private FrameCreatingMethodProcessor _methodProcessor;

    @BeforeEach
    void setUp() throws Exception
    {
        _methodProcessor = new FrameCreatingMethodProcessor(ProtocolVersion.v0_91);
        _decoder = new ClientDecoder(_methodProcessor);
    }

    private ByteBuffer getHeartbeatBodyBuffer()
    {
        final TestSender sender = new TestSender();
        HeartbeatBody.FRAME.writePayload(sender);
        return combine(sender.getSentBuffers());
    }

    @Test
    void singleFrameDecode() throws AMQProtocolVersionException, AMQFrameDecodingException
    {
        final ByteBuffer msg = getHeartbeatBodyBuffer();
        _decoder.decodeBuffer(msg);
        final List<AMQDataBlock> frames = _methodProcessor.getProcessedMethods();
        if (frames.get(0) instanceof AMQFrame)
        {
            assertEquals(HeartbeatBody.FRAME.getBodyFrame().getFrameType(),
                    (long) ((AMQFrame) frames.get(0)).getBodyFrame().getFrameType());
        }
        else
        {
            fail("decode was not a frame");
        }
    }

    @Test
    void contentHeaderPropertiesFrame() throws AMQProtocolVersionException, AMQFrameDecodingException
    {
        final BasicContentHeaderProperties props = new BasicContentHeaderProperties();
        final Map<String, Object> headersMap = Map.of("hello", "world",
                "1+1=", 2);
        final FieldTable table = FieldTableFactory.createFieldTable(headersMap);
        props.setHeaders(table);
        final AMQBody body = new ContentHeaderBody(props);
        final AMQFrame frame = new AMQFrame(1, body);
        final TestSender sender = new TestSender();
        frame.writePayload(sender);
        final ByteBuffer msg = combine(sender.getSentBuffers());

        _decoder.decodeBuffer(msg);
        final List<AMQDataBlock> frames = _methodProcessor.getProcessedMethods();
        final AMQDataBlock firstFrame = frames.get(0);
        if (firstFrame instanceof AMQFrame)
        {
            assertEquals(ContentHeaderBody.TYPE, (long) ((AMQFrame) firstFrame).getBodyFrame().getFrameType());
            final BasicContentHeaderProperties decodedProps = ((ContentHeaderBody)((AMQFrame)firstFrame).getBodyFrame()).getProperties();
            final Map<String, Object> headers = decodedProps.getHeadersAsMap();
            assertEquals("world", headers.get("hello"));
        }
        else
        {
            fail("decode was not a frame");
        }
    }


    @Test
    void decodeWithManyBuffers() throws AMQProtocolVersionException, AMQFrameDecodingException
    {
        final SecureRandom random = new SecureRandom();
        final byte[] payload = new byte[2048];
        random.nextBytes(payload);
        final AMQBody body = new ContentBody(ByteBuffer.wrap(payload));
        final AMQFrame frame = new AMQFrame(1, body);
        final TestSender sender = new TestSender();
        frame.writePayload(sender);
        final ByteBuffer allData = combine(sender.getSentBuffers());

        for (int i = 0 ; i < allData.remaining(); i++)
        {
            final byte[] minibuf = new byte[1];
            minibuf[0] = allData.get(i);
            _decoder.decodeBuffer(ByteBuffer.wrap(minibuf));
        }

        final List<AMQDataBlock> frames = _methodProcessor.getProcessedMethods();
        if (frames.get(0) instanceof AMQFrame)
        {
            assertEquals(ContentBody.TYPE, (long) ((AMQFrame) frames.get(0)).getBodyFrame().getFrameType());
            final ContentBody decodedBody = (ContentBody) ((AMQFrame) frames.get(0)).getBodyFrame();
            byte[] bodyBytes;
            try (final QpidByteBuffer payloadBuffer = decodedBody.getPayload())
            {
                bodyBytes = new byte[payloadBuffer.remaining()];
                payloadBuffer.get(bodyBytes);
            }
            assertArrayEquals(payload, bodyBytes, "Body was corrupted");
        }
        else
        {
            fail("decode was not a frame");
        }
    }

    @Test
    void partialFrameDecode() throws AMQProtocolVersionException, AMQFrameDecodingException
    {
        final  ByteBuffer msg = getHeartbeatBodyBuffer();
        final ByteBuffer msgA = msg.slice();
        final int msgbPos = msg.remaining() / 2;
        final int msgaLimit = msg.remaining() - msgbPos;
        msgA.limit(msgaLimit);
        msg.position(msgbPos);
        final ByteBuffer msgB = msg.slice();

        _decoder.decodeBuffer(msgA);
        final List<AMQDataBlock> frames = _methodProcessor.getProcessedMethods();
        assertEquals(0, (long) frames.size());

        _decoder.decodeBuffer(msgB);
        assertEquals(1, (long) frames.size());
        if (frames.get(0) instanceof AMQFrame)
        {
            assertEquals(HeartbeatBody.FRAME.getBodyFrame().getFrameType(),
                    (long) ((AMQFrame) frames.get(0)).getBodyFrame().getFrameType());
        }
        else
        {
            fail("decode was not a frame");
        }
    }

    @Test
    void multipleFrameDecode() throws AMQProtocolVersionException, AMQFrameDecodingException
    {
        final ByteBuffer msgA = getHeartbeatBodyBuffer();
        final ByteBuffer msgB = getHeartbeatBodyBuffer();
        final ByteBuffer msg = ByteBuffer.allocate(msgA.remaining() + msgB.remaining());
        msg.put(msgA);
        msg.put(msgB);
        msg.flip();
        _decoder.decodeBuffer(msg);
        final List<AMQDataBlock> frames = _methodProcessor.getProcessedMethods();
        assertEquals(2, (long) frames.size());
        for (final AMQDataBlock frame : frames)
        {
            if (frame instanceof AMQFrame)
            {
                assertEquals(HeartbeatBody.FRAME.getBodyFrame().getFrameType(),
                        (long) ((AMQFrame) frame).getBodyFrame().getFrameType());
            }
            else
            {
                fail("decode was not a frame");
            }
        }
    }

    @Test
    void multiplePartialFrameDecode() throws AMQProtocolVersionException, AMQFrameDecodingException
    {
        final ByteBuffer msgA = getHeartbeatBodyBuffer();
        final ByteBuffer msgB = getHeartbeatBodyBuffer();
        final ByteBuffer msgC = getHeartbeatBodyBuffer();

        final ByteBuffer sliceA = ByteBuffer.allocate(msgA.remaining() + msgB.remaining() / 2);
        sliceA.put(msgA);
        final int limit = msgB.limit();
        final int pos = msgB.remaining() / 2;
        msgB.limit(pos);
        sliceA.put(msgB);
        sliceA.flip();
        msgB.limit(limit);
        msgB.position(pos);

        final ByteBuffer sliceB = ByteBuffer.allocate(msgB.remaining() + pos);
        sliceB.put(msgB);
        msgC.limit(pos);
        sliceB.put(msgC);
        sliceB.flip();
        msgC.limit(limit);

        _decoder.decodeBuffer(sliceA);
        final List<AMQDataBlock> frames = _methodProcessor.getProcessedMethods();
        assertEquals(1, (long) frames.size());
        frames.clear();
        _decoder.decodeBuffer(sliceB);
        assertEquals(1, (long) frames.size());
        frames.clear();
        _decoder.decodeBuffer(msgC);
        assertEquals(1, (long) frames.size());
        for (final AMQDataBlock frame : frames)
        {
            if (frame instanceof AMQFrame)
            {
                assertEquals(HeartbeatBody.FRAME.getBodyFrame().getFrameType(),
                        (long) ((AMQFrame) frame).getBodyFrame().getFrameType());
            }
            else
            {
                fail("decode was not a frame");
            }
        }
    }

    private static class TestSender implements ByteBufferSender
    {
        private final Collection<QpidByteBuffer> _sentBuffers = new ArrayList<>();

        @Override
        public boolean isDirectBufferPreferred()
        {
            return false;
        }

        @Override
        public void send(final QpidByteBuffer msg)
        {
            _sentBuffers.add(msg.duplicate());
            msg.position(msg.limit());
        }

        @Override
        public void flush()
        {

        }

        @Override
        public void close()
        {

        }

        public Collection<QpidByteBuffer> getSentBuffers()
        {
            return _sentBuffers;
        }

    }

    private static ByteBuffer combine(final Collection<QpidByteBuffer> bufs)
    {
        if (bufs == null || bufs.isEmpty())
        {
            return EMPTY_BYTE_BUFFER;
        }
        else
        {
            int size = 0;
            boolean isDirect = false;
            for (final QpidByteBuffer buf : bufs)
            {
                size += buf.remaining();
                isDirect = isDirect || buf.isDirect();
            }
            final ByteBuffer combined = isDirect ? ByteBuffer.allocateDirect(size) : ByteBuffer.allocate(size);

            for (final QpidByteBuffer buf : bufs)
            {
                buf.copyTo(combined);
            }
            combined.flip();
            return combined;
        }
    }
}
