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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.qpid.test.utils.UnitTestBase;

import org.junit.jupiter.api.Test;

class PropertyTest extends UnitTestBase
{
    @Test
    void parse()
    {
        assertEquals(Property.AUTO_DELETE, Property.parse(Property.AUTO_DELETE.getCanonicalName()));
        assertEquals(Property.AUTO_DELETE, Property.parse(Property.AUTO_DELETE.name()));
        assertEquals(Property.AUTO_DELETE, Property.parse("autoDelete"));
        assertEquals(Property.ATTRIBUTES, Property.parse("attribute_names"));
    }

    @Test
    void isBooleanType()
    {
        assertFalse(Property.isBooleanType(Property.ROUTING_KEY));
        assertFalse(Property.isBooleanType(Property.NAME));
        assertFalse(Property.isBooleanType(Property.QUEUE_NAME));
        assertFalse(Property.isBooleanType(Property.OWNER));
        assertFalse(Property.isBooleanType(Property.TYPE));
        assertFalse(Property.isBooleanType(Property.ALTERNATE));

        assertTrue(Property.isBooleanType(Property.DURABLE));
        assertTrue(Property.isBooleanType(Property.EXCLUSIVE));
        assertTrue(Property.isBooleanType(Property.TEMPORARY));
        assertTrue(Property.isBooleanType(Property.AUTO_DELETE));

        assertFalse(Property.isBooleanType(Property.COMPONENT));
        assertFalse(Property.isBooleanType(Property.PACKAGE));
        assertFalse(Property.isBooleanType(Property.CLASS));
        assertFalse(Property.isBooleanType(Property.FROM_NETWORK));
        assertFalse(Property.isBooleanType(Property.FROM_HOSTNAME));
        assertFalse(Property.isBooleanType(Property.VIRTUALHOST_NAME));
        assertFalse(Property.isBooleanType(Property.METHOD_NAME));
        assertFalse(Property.isBooleanType(Property.ATTRIBUTES));
        assertFalse(Property.isBooleanType(Property.CREATED_BY));
    }

    @Test
    void parse_Exception()
    {
        final IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
                () -> Property.parse("X"),
                "An exception is expected");
        assertNotNull(thrown.getMessage());
    }
}
