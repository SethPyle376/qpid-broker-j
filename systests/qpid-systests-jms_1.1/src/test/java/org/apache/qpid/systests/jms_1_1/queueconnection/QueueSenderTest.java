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

package org.apache.qpid.systests.jms_1_1.queueconnection;

import static org.junit.jupiter.api.Assertions.fail;

import javax.jms.InvalidDestinationException;
import javax.jms.Queue;
import javax.jms.QueueConnection;
import javax.jms.QueueSender;
import javax.jms.QueueSession;
import javax.jms.Session;

import org.junit.jupiter.api.Test;

import org.apache.qpid.systests.JmsTestBase;

public class QueueSenderTest extends JmsTestBase
{
    @Test
    public void sendToUnknownQueue() throws Exception
    {
        QueueConnection connection = ((QueueConnection) getConnectionBuilder().build());

        try
        {
            QueueSession session = connection.createQueueSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue invalidDestination = session.createQueue("unknown");

            try
            {
                QueueSender sender = session.createSender(invalidDestination);
                sender.send(session.createMessage());
                fail("Exception not thrown");
            }
            catch (InvalidDestinationException e)
            {
                //PASS
            }
        }
        finally
        {
            connection.close();
        }
    }

    @Test
    public void anonymousSenderSendToUnknownQueue() throws Exception
    {
        QueueConnection connection = ((QueueConnection) getConnectionBuilder().setSyncPublish(true).build());

        try
        {
            QueueSession session = connection.createQueueSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue invalidDestination = session.createQueue("unknown");

            try
            {
                QueueSender sender = session.createSender(null);
                sender.send(invalidDestination, session.createMessage());
                fail("Exception not thrown");
            }
            catch (InvalidDestinationException e)
            {
                //PASS
            }
        }
        finally
        {
            connection.close();
        }
    }
}
