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

package org.apache.qpid.server.store;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import java.util.Map;

import org.junit.jupiter.api.Test;

public class UpgraderHelperTest
{
    @Test
    public void renameContextVariables()
    {
        final Map<String, String> context = Map.of("foo", "fooValue",
                "bar", "barValue");
        final Map<String, String> newContext =
                UpgraderHelper.renameContextVariables(context, Map.of("foo", "newFoo"));
        assertThat(newContext, is(notNullValue()));
        assertThat(newContext.size(), equalTo(context.size()));
        assertThat(newContext.get("bar"), equalTo(context.get("bar")));
        assertThat(newContext.get("newFoo"), equalTo(context.get("foo")));
    }
}
