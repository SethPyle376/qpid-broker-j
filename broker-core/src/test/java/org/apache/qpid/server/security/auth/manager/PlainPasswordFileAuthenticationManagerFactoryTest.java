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
 *
 */
package org.apache.qpid.server.security.auth.manager;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.apache.qpid.server.model.AuthenticationProvider;
import org.apache.qpid.server.model.Broker;
import org.apache.qpid.server.model.BrokerModel;
import org.apache.qpid.server.model.BrokerTestHelper;
import org.apache.qpid.server.model.ConfiguredObjectFactory;
import org.apache.qpid.server.security.auth.database.PlainPasswordFilePrincipalDatabase;
import org.apache.qpid.test.utils.UnitTestBase;

public class PlainPasswordFileAuthenticationManagerFactoryTest extends UnitTestBase
{
    private final ConfiguredObjectFactory _factory = BrokerModel.getInstance().getObjectFactory();
    private final Map<String, Object> _configuration = new HashMap<>();
    private File _emptyPasswordFile;
    private final Broker<?> _broker = BrokerTestHelper.createBrokerMock();

    @BeforeEach
    public void setUp() throws Exception
    {
        _emptyPasswordFile = File.createTempFile(getTestName(), "passwd");
        _emptyPasswordFile.deleteOnExit();
        _configuration.put(AuthenticationProvider.ID, randomUUID());
        _configuration.put(AuthenticationProvider.NAME, getTestName());
    }

    @AfterEach
    public void tearDown() throws Exception
    {
        if (_emptyPasswordFile != null && _emptyPasswordFile.exists())
        {
            _emptyPasswordFile.delete();
        }
    }

    @Test
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void testPlainInstanceCreated()
    {
        _configuration.put(AuthenticationProvider.TYPE, PlainPasswordDatabaseAuthenticationManager.PROVIDER_TYPE);
        _configuration.put("path", _emptyPasswordFile.getAbsolutePath());

        final AuthenticationProvider<?> manager = _factory.create(AuthenticationProvider.class, _configuration, _broker);
        assertNotNull(manager);
        assertTrue(manager instanceof PrincipalDatabaseAuthenticationManager);
        assertTrue(((PrincipalDatabaseAuthenticationManager)manager).getPrincipalDatabase() instanceof PlainPasswordFilePrincipalDatabase);
    }

    @Test
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void testPasswordFileNotFound()
    {
        //delete the file
        _emptyPasswordFile.delete();

        _configuration.put(AuthenticationProvider.TYPE, PlainPasswordDatabaseAuthenticationManager.PROVIDER_TYPE);
        _configuration.put("path", _emptyPasswordFile.getAbsolutePath());

        final AuthenticationProvider<?> manager = _factory.create(AuthenticationProvider.class, _configuration, _broker);

        assertNotNull(manager);
        assertTrue(manager instanceof PrincipalDatabaseAuthenticationManager);
        assertTrue(((PrincipalDatabaseAuthenticationManager)manager).getPrincipalDatabase() instanceof PlainPasswordFilePrincipalDatabase);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testThrowsExceptionWhenConfigForPlainPDImplementationNoPasswordFileValueSpecified()
    {
        _configuration.put(AuthenticationProvider.TYPE, PlainPasswordDatabaseAuthenticationManager.PROVIDER_TYPE);

        assertThrows(IllegalArgumentException.class,
                () -> _factory.create(AuthenticationProvider.class, _configuration, _broker),
                "No authentication manager should be created");
    }
}
