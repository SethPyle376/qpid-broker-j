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
package org.apache.qpid.server.security.access.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.EnumSet;

class ObjectTypeTest
{
    @Test
    void isSupported()
    {
        for (LegacyOperation operation : LegacyOperation.values())
        {
            assertTrue(ObjectType.ALL.isSupported(operation));
        }

        for (ObjectType objectType : ObjectType.values())
        {
            objectType.getOperations().forEach(operation -> assertTrue(objectType.isSupported(operation)));
            final EnumSet<LegacyOperation> legacyOperations = EnumSet.allOf(LegacyOperation.class);
            legacyOperations.removeAll(objectType.getOperations());
            legacyOperations.forEach(operation -> assertFalse(objectType.isSupported(operation)));
        }
    }

    @Test
    void string()
    {
        assertEquals("All", ObjectType.ALL.toString());
        assertEquals("Broker", ObjectType.BROKER.toString());
        assertEquals("Exchange", ObjectType.EXCHANGE.toString());
        assertEquals("Group", ObjectType.GROUP.toString());
        assertEquals("Management", ObjectType.MANAGEMENT.toString());
        assertEquals("Method", ObjectType.METHOD.toString());
        assertEquals("Queue", ObjectType.QUEUE.toString());
        assertEquals("User", ObjectType.USER.toString());
        assertEquals("Virtualhost", ObjectType.VIRTUALHOST.toString());
        assertEquals("Virtualhostnode", ObjectType.VIRTUALHOSTNODE.toString());
    }
}
