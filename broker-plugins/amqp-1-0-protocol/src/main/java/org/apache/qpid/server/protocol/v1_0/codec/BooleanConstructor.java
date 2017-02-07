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

package org.apache.qpid.server.protocol.v1_0.codec;

import java.util.List;

import org.apache.qpid.server.protocol.v1_0.type.AmqpErrorException;
import org.apache.qpid.server.protocol.v1_0.type.transport.*;
import org.apache.qpid.server.protocol.v1_0.type.transport.Error;
import org.apache.qpid.server.bytebuffer.QpidByteBuffer;

public class BooleanConstructor
{
    private static final TypeConstructor<Boolean> TRUE_INSTANCE = new TypeConstructor<Boolean>()
    {

        @Override
        public Boolean construct(final List<QpidByteBuffer> in, final ValueHandler handler) throws AmqpErrorException
        {
            return Boolean.TRUE;
        }
    };

    private static final TypeConstructor<Boolean> FALSE_INSTANCE = new TypeConstructor<Boolean>()
        {

            @Override
            public Boolean construct(final List<QpidByteBuffer> in, final ValueHandler handler)
                    throws AmqpErrorException
            {
                return Boolean.FALSE;
            }
        };
    private static final TypeConstructor<Boolean> BYTE_INSTANCE = new TypeConstructor<Boolean>()
    {

        @Override
        public Boolean construct(final List<QpidByteBuffer> in, final ValueHandler handler) throws AmqpErrorException
        {
            if(QpidByteBufferUtils.hasRemaining(in))
            {
                byte b = QpidByteBufferUtils.get(in);
                return b != (byte) 0;
            }
            else
            {
                org.apache.qpid.server.protocol.v1_0.type.transport.Error error = new Error();
                error.setCondition(ConnectionError.FRAMING_ERROR);
                error.setDescription("Cannot construct boolean: insufficient input data");
                throw new AmqpErrorException(error);
            }
        }
    };


    public static TypeConstructor<Boolean> getTrueInstance()
    {
        return TRUE_INSTANCE;
    }

    public static TypeConstructor<Boolean> getFalseInstance()
    {
        return FALSE_INSTANCE;
    }

    public static TypeConstructor<Boolean> getByteInstance()
    {
        return BYTE_INSTANCE;
    }
}
