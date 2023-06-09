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

import java.nio.ByteBuffer;

import org.apache.qpid.server.bytebuffer.QpidByteBuffer;
import org.apache.qpid.server.protocol.ProtocolVersion;
import org.apache.qpid.server.protocol.v0_8.transport.*;

public class ClientDecoder extends AMQDecoder<ClientMethodProcessor<? extends ClientChannelMethodProcessor>>
{
    private QpidByteBuffer _incompleteBuffer;

    /**
     * Creates a new AMQP decoder.
     *
     * @param methodProcessor method processor
     */
    public ClientDecoder(final ClientMethodProcessor<? extends ClientChannelMethodProcessor> methodProcessor)
    {
        super(false, methodProcessor);
    }

    public void decodeBuffer(final ByteBuffer incomingBuffer) throws AMQFrameDecodingException, AMQProtocolVersionException
    {
        if (_incompleteBuffer == null)
        {
            final QpidByteBuffer qpidByteBuffer = QpidByteBuffer.wrap(incomingBuffer);
            final int required = decode(qpidByteBuffer);
            if (required != 0)
            {
                _incompleteBuffer = QpidByteBuffer.allocate(qpidByteBuffer.remaining() + required);
                _incompleteBuffer.put(qpidByteBuffer);
            }
            qpidByteBuffer.dispose();
        }
        else
        {
            if (incomingBuffer.remaining() < _incompleteBuffer.remaining())
            {
                _incompleteBuffer.put(incomingBuffer);
            }
            else
            {
                _incompleteBuffer.flip();
                final QpidByteBuffer aggregatedBuffer =
                        QpidByteBuffer.allocate(_incompleteBuffer.remaining() + incomingBuffer.remaining());
                aggregatedBuffer.put(_incompleteBuffer);
                aggregatedBuffer.put(incomingBuffer);
                aggregatedBuffer.flip();
                final int required = decode(aggregatedBuffer);

                _incompleteBuffer.dispose();
                if (required != 0)
                {
                    _incompleteBuffer = QpidByteBuffer.allocate(aggregatedBuffer.remaining() + required);
                    _incompleteBuffer.put(aggregatedBuffer);
                }
                else
                {
                    _incompleteBuffer = null;
                }
                aggregatedBuffer.dispose();
            }
        }
        // post-condition: assert(!incomingBuffer.hasRemaining());
    }

    @Override
    protected void processMethod(final int channelId, final QpidByteBuffer in) throws AMQFrameDecodingException
    {
        final ClientMethodProcessor<? extends ClientChannelMethodProcessor> methodProcessor = getMethodProcessor();
        final ClientChannelMethodProcessor channelMethodProcessor = methodProcessor.getChannelMethodProcessor(channelId);
        final int classAndMethod = in.getInt();
        final int classId = classAndMethod >> 16;
        final int methodId = classAndMethod & 0xFFFF;
        methodProcessor.setCurrentMethod(classId, methodId);
        try
        {
            switch (classAndMethod)
            {
                //CONNECTION_CLASS:
                case 0x000a000a:
                    ConnectionStartBody.process(in, methodProcessor);
                    break;
                case 0x000a0014:
                    ConnectionSecureBody.process(in, methodProcessor);
                    break;
                case 0x000a001e:
                    ConnectionTuneBody.process(in, methodProcessor);
                    break;
                case 0x000a0029:
                    ConnectionOpenOkBody.process(in, methodProcessor);
                    break;
                case 0x000a002a:
                    ConnectionRedirectBody.process(in, methodProcessor);
                    break;
                case 0x000a0032:
                    if (methodProcessor.getProtocolVersion().equals(ProtocolVersion.v0_8))
                    {
                        ConnectionRedirectBody.process(in, methodProcessor);
                    }
                    else
                    {
                        ConnectionCloseBody.process(in, methodProcessor);
                    }
                    break;
                case 0x000a0033:
                    if (methodProcessor.getProtocolVersion().equals(ProtocolVersion.v0_8))
                    {
                        throw newUnknownMethodException(classId, methodId, methodProcessor.getProtocolVersion());
                    }
                    else
                    {
                        methodProcessor.receiveConnectionCloseOk();
                    }
                    break;
                case 0x000a003c:
                    if (methodProcessor.getProtocolVersion().equals(ProtocolVersion.v0_8))
                    {
                        ConnectionCloseBody.process(in, methodProcessor);
                    }
                    else
                    {
                        throw newUnknownMethodException(classId, methodId, methodProcessor.getProtocolVersion());
                    }
                    break;
                case 0x000a003d:
                    if (methodProcessor.getProtocolVersion().equals(ProtocolVersion.v0_8))
                    {
                        methodProcessor.receiveConnectionCloseOk();
                    }
                    else
                    {
                        throw newUnknownMethodException(classId, methodId, methodProcessor.getProtocolVersion());
                    }
                    break;

                // CHANNEL_CLASS:

                case 0x0014000b:
                    ChannelOpenOkBody.process(in, methodProcessor.getProtocolVersion(), channelMethodProcessor);
                    break;
                case 0x00140014:
                    ChannelFlowBody.process(in, channelMethodProcessor);
                    break;
                case 0x00140015:
                    ChannelFlowOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x0014001e:
                    ChannelAlertBody.process(in, channelMethodProcessor);
                    break;
                case 0x00140028:
                    ChannelCloseBody.process(in, channelMethodProcessor);
                    break;
                case 0x00140029:
                    channelMethodProcessor.receiveChannelCloseOk();
                    break;

                // ACCESS_CLASS:

                case 0x001e000b:
                    AccessRequestOkBody.process(in, channelMethodProcessor);
                    break;

                // EXCHANGE_CLASS:

                case 0x0028000b:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveExchangeDeclareOk();
                    }
                    break;
                case 0x00280015:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveExchangeDeleteOk();
                    }
                    break;
                case 0x00280017:
                    ExchangeBoundOkBody.process(in, channelMethodProcessor);
                    break;

                // QUEUE_CLASS:

                case 0x0032000b:
                    QueueDeclareOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x00320015:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveQueueBindOk();
                    }
                    break;
                case 0x0032001f:
                    QueuePurgeOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x00320029:
                    QueueDeleteOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x00320033:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveQueueUnbindOk();
                    }
                    break;

                // BASIC_CLASS:

                case 0x003c000b:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveBasicQosOk();
                    }
                    break;
                case 0x003c0015:
                    BasicConsumeOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c001f:
                    BasicCancelOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c0032:
                    BasicReturnBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c003c:
                    BasicDeliverBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c0047:
                    BasicGetOkBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c0048:
                    BasicGetEmptyBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c0050:
                    BasicAckBody.process(in, channelMethodProcessor);
                    break;
                case 0x003c0065:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveBasicRecoverSyncOk();
                    }
                    break;
                case 0x003c006f:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveBasicRecoverSyncOk();
                    }
                    break;
                case 0x003c0078:
                    BasicNackBody.process(in, channelMethodProcessor);
                    break;

                // CONFIRM CLASS:

                case 0x0055000b:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveConfirmSelectOk();
                    }
                    break;

                // TX_CLASS:

                case 0x005a000b:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveTxSelectOk();
                    }
                    break;
                case 0x005a0015:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveTxCommitOk();
                    }
                    break;
                case 0x005a001f:
                    if(!channelMethodProcessor.ignoreAllButCloseOk())
                    {
                        channelMethodProcessor.receiveTxRollbackOk();
                    }
                    break;

                default:
                    throw newUnknownMethodException(classId, methodId, methodProcessor.getProtocolVersion());

            }
        }
        finally
        {
            methodProcessor.setCurrentMethod(0, 0);
        }
    }
}
