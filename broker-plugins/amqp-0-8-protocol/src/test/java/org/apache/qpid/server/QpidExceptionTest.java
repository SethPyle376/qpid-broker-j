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
package org.apache.qpid.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import org.apache.qpid.server.protocol.ErrorCodes;
import org.apache.qpid.server.protocol.v0_8.AMQFrameDecodingException;
import org.apache.qpid.server.protocol.v0_8.AMQShortString;
import org.apache.qpid.test.utils.UnitTestBase;

/**
 * This test is to ensure that when an AMQException is rethrown that the specified exception is correctly wrapped up.
 * <p>
 * There are three cases:
 * Re-throwing an AMQException
 * Re-throwing a Subclass of AMQException
 * Re-throwing a Subclass of AMQException that does not have the default AMQException constructor which will force the
 * creation of an AMQException.
 */
class QpidExceptionTest extends UnitTestBase
{
    /**
     * Test that an AMQException will be correctly created and rethrown.
     */
    @Test
    void rethrowGeneric()
    {
        final QpidException test = new QpidException("refused", new RuntimeException());

        final QpidException e = reThrowException(test);

        assertEquals(QpidException.class, e.getClass(), "Exception not of correct class");
    }

    /**
     * Test that a subclass of AMQException that has the default constructor will be correctly created and rethrown.
     */
    @Test
    void rethrowAMQESubclass()
    {
        final AMQFrameDecodingException test = new AMQFrameDecodingException("Error", new Exception());
        final QpidException e = reThrowException(test);

        assertEquals(AMQFrameDecodingException.class, e.getClass(), "Exception not of correct class");
    }

    /**
     * Test that a subclass of AMQException that doesnot have the  default constructor will be correctly rethrown as an
     * AMQException
     */
    @Test
    void rethrowAMQESubclassNoConstructor()
    {
        final AMQExceptionSubclass test = new AMQExceptionSubclass("Invalid Argument Exception");

        final QpidException e = reThrowException(test);

        assertEquals(QpidException.class, e.getClass(), "Exception not of correct class");
    }

    /**
     * Private method to rethrown and validate the basic values of the rethrown
     * @param test Exception to rethrow
     */
    private QpidException reThrowException(final QpidException test)
    {
        final QpidException amqe = test.cloneForCurrentThread();
        if (test instanceof AMQException)
        {
            assertEquals(((AMQException) test).getErrorCode(), (long) ((AMQException) amqe).getErrorCode(),
                    "Error code does not match.");
        }
        assertTrue(amqe.getMessage().startsWith(test.getMessage()), "Exception message does not start as expected.");
        assertEquals(test, amqe.getCause(), "Test Exception is not set as the cause");
        assertEquals(test.getCause(), amqe.getCause().getCause(), "Cause is not correct");

        return amqe;
    }

    @Test
    void getMessageAsString()
    {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 25; i++)
        {
            sb.append("message [").append(i).append("]");
        }
        final AMQException e = new AMQException(ErrorCodes.INTERNAL_ERROR, sb.toString(), null);
        final AMQShortString message = AMQShortString.validValueOf(e.getMessage());
        assertEquals(sb.substring(0, AMQShortString.MAX_LENGTH - 3) + "...", message.toString());
    }

    /**
     * Private class that extends AMQException but does not have a default exception.
     */
    private static class AMQExceptionSubclass extends QpidException
    {
        public AMQExceptionSubclass(final String msg)
        {
            super(msg, null);
        }
    }
}

