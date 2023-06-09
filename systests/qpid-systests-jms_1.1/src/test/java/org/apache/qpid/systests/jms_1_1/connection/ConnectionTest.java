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
package org.apache.qpid.systests.jms_1_1.connection;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.UUID;

import javax.jms.Connection;
import javax.jms.IllegalStateException;
import javax.jms.JMSException;
import javax.jms.JMSSecurityException;

import org.junit.jupiter.api.Test;

import org.apache.qpid.server.model.Protocol;
import org.apache.qpid.systests.JmsTestBase;

public class ConnectionTest extends JmsTestBase
{
    @Test
    public void successfulConnection() throws Exception
    {
        Connection con = getConnection();
        assertThat(con, is(notNullValue()));
        con.close();
    }

    @Test
    public void badPassword() throws Exception
    {
        Connection con = null;
        try
        {
            con = getConnectionBuilder().setUsername("user")
                                  .setPassword("badpassword").build();
            fail("Exception not thrown");
        }
        catch (JMSSecurityException e)
        {
            // PASS
        }
        catch (JMSException e)
        {
            assertThat(getProtocol(), is(not(Protocol.AMQP_1_0)));
            assertThat(e.getMessage().toLowerCase(), containsString("authentication failed"));
        }
        finally
        {
            if (con != null)
            {
                con.close();
            }
        }
    }

    @Test
    public void unresolvableHost() throws Exception
    {
        Connection con = null;
        try
        {
            /* RFC-2606 guarantees that .invalid address will never resolve */
            con = getConnectionBuilder().setHost("unknownhost.unknowndomain.invalid")
                                                         .build();
            fail("Exception not thrown");
        }
        catch (JMSException e)
        {
            // PASS
        }
        finally
        {
            if (con != null)
            {
                con.close();
            }
        }

    }

    @Test
    public void unknownVirtualHost() throws Exception
    {
        Connection con = null;
        try
        {
            con = getConnectionBuilder().setVirtualHost("unknown")
                                        .build();
            fail("Exception not thrown");
        }
        catch (JMSException e)
        {
            // PASS
        }
        finally
        {
            if (con != null)
            {
                con.close();
            }
        }
    }

    @Test
    public void connectionFactorySuppliedClientIdImmutable() throws Exception
    {
        final String clientId = UUID.randomUUID().toString();
        Connection con = getConnectionBuilder().setClientId(clientId)
                                               .build();
        assertThat(con.getClientID(), is(equalTo(clientId)));
        try
        {
            con.setClientID(UUID.randomUUID().toString());
            fail("Exception not thrown");
        }
        catch (IllegalStateException e)
        {
            // PASS
        }
        assertThat(con.getClientID(), is(equalTo(clientId)));
    }
}
