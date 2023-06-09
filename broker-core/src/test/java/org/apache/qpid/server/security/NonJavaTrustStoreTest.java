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

package org.apache.qpid.server.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.junit.jupiter.api.Test;

import org.junit.jupiter.api.extension.RegisterExtension;

import org.apache.qpid.server.configuration.IllegalConfigurationException;
import org.apache.qpid.server.model.Broker;
import org.apache.qpid.server.model.BrokerModel;
import org.apache.qpid.server.model.BrokerTestHelper;
import org.apache.qpid.server.model.ConfiguredObjectFactory;
import org.apache.qpid.server.model.TrustStore;
import org.apache.qpid.test.utils.tls.KeyCertificatePair;
import org.apache.qpid.test.utils.tls.TlsResource;
import org.apache.qpid.test.utils.tls.TlsResourceBuilder;
import org.apache.qpid.test.utils.UnitTestBase;

public class NonJavaTrustStoreTest extends UnitTestBase
{
    @RegisterExtension
    public static final TlsResource TLS_RESOURCE = new TlsResource();

    private static final Broker<?> BROKER = BrokerTestHelper.createBrokerMock();
    private static final ConfiguredObjectFactory FACTORY = BrokerModel.getInstance().getObjectFactory();
    private static final String NAME = "myTestTrustStore";
    private static final String NON_JAVA_TRUST_STORE = "NonJavaTrustStore";
    private static final String DN_FOO = "CN=foo";
    private static final String DN_CA = "CN=CA";
    private static final String DN_BAR = "CN=bar";
    private static final String NOT_A_CRL = "/not/a/crl";

    @Test
    public void testCreationOfTrustStoreWithoutCRL() throws Exception
    {
        final KeyCertificatePair keyCertPair = TlsResourceBuilder.createSelfSigned(DN_FOO);
        final Path certificateFile = TLS_RESOURCE.saveCertificateAsPem(keyCertPair.getCertificate());
        final Map<String, Object> attributes = Map.of(NonJavaTrustStore.NAME, NAME,
                NonJavaTrustStore.CERTIFICATES_URL, certificateFile.toFile().getAbsolutePath(),
                NonJavaTrustStore.TYPE, NON_JAVA_TRUST_STORE,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_CHECK_ENABLED, false);
        final TrustStore<?> trustStore = createTestTrustStore(attributes);
        final TrustManager[] trustManagers = trustStore.getTrustManagers();

        assertNotNull(trustManagers);
        assertEquals(1, trustManagers.length, "Unexpected number of trust managers");
        assertNotNull(trustManagers[0], "Trust manager unexpected null");
    }

    @Test
    public void testCreationOfTrustStoreFromValidCertificate() throws Exception
    {
        final CertificateAndCrl<File> data = generateCertificateAndCrl();
        final Map<String, Object> attributes = Map.of(NonJavaTrustStore.NAME, NAME,
                NonJavaTrustStore.CERTIFICATES_URL, data.getCertificate().getAbsolutePath(),
                NonJavaTrustStore.TYPE, NON_JAVA_TRUST_STORE,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_CHECK_ENABLED, true,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_LIST_URL, data.getCrl().getAbsolutePath());
        final TrustStore<?> trustStore = createTestTrustStore(attributes);
        final TrustManager[] trustManagers = trustStore.getTrustManagers();

        assertNotNull(trustManagers);
        assertEquals(1, trustManagers.length, "Unexpected number of trust managers");
        assertNotNull(trustManagers[0], "Trust manager unexpected null");
    }

    @Test
    public void testChangeOfCrlInTrustStoreFromValidCertificate() throws Exception
    {
        final CertificateAndCrl<File> data = generateCertificateAndCrl();
        final Map<String, Object> attributes = Map.of(NonJavaTrustStore.NAME, NAME,
                NonJavaTrustStore.CERTIFICATES_URL, data.getCertificate().getAbsolutePath(),
                NonJavaTrustStore.TYPE, NON_JAVA_TRUST_STORE,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_CHECK_ENABLED, true,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_LIST_URL, data.getCrl().getAbsolutePath());
        final TrustStore<?> trustStore = createTestTrustStore(attributes);
        final IllegalConfigurationException thrown = assertThrows(IllegalConfigurationException.class,
                () -> trustStore.setAttributes(Map.of(FileTrustStore.CERTIFICATE_REVOCATION_LIST_URL, NOT_A_CRL)),
                "Exception not thrown");

        assertTrue(thrown.getMessage().contains(String.format(
                "Unable to load certificate revocation list '%s' for truststore '%s'",
                NOT_A_CRL, NAME)), "Exception text not as unexpected:" + thrown.getMessage());
        assertEquals(data.getCrl().getAbsolutePath(), trustStore.getCertificateRevocationListUrl(),
                "Unexpected CRL path value after failed change");

        final Path emptyCrl = TLS_RESOURCE.createCrl(data.getCa());
        trustStore.setAttributes(Map.of(FileTrustStore.CERTIFICATE_REVOCATION_LIST_URL, emptyCrl.toFile().getAbsolutePath()));

        assertEquals(emptyCrl.toFile().getAbsolutePath(), trustStore.getCertificateRevocationListUrl(),
                "Unexpected CRL path value after change that is expected to be successful");
    }

    @Test
    public void testUseOfExpiredTrustAnchorDenied() throws Exception
    {
        final KeyCertificatePair keyCertPair = createExpiredCertificate();
        final Path certificatePath = TLS_RESOURCE.saveCertificateAsPem(keyCertPair.getCertificate());
        final Map<String, Object> attributes = Map.of(NonJavaTrustStore.NAME, NAME,
                NonJavaTrustStore.TRUST_ANCHOR_VALIDITY_ENFORCED, true,
                NonJavaTrustStore.CERTIFICATES_URL, certificatePath.toFile().getAbsolutePath(),
                NonJavaTrustStore.TYPE, NON_JAVA_TRUST_STORE);
        final TrustStore<?> trustStore = createTestTrustStore(attributes);
        final TrustManager[] trustManagers = trustStore.getTrustManagers();

        assertNotNull(trustManagers);
        assertEquals(1, trustManagers.length, "Unexpected number of trust managers");
        final boolean condition = trustManagers[0] instanceof X509TrustManager;
        assertTrue(condition, "Unexpected trust manager type");

        final X509TrustManager trustManager = (X509TrustManager) trustManagers[0];

        final CertificateException thrown = assertThrows(CertificateException.class,
                () -> trustManager.checkClientTrusted(new X509Certificate[]{keyCertPair.getCertificate()}, "NULL"),
                "Exception not thrown");

        // IBMJSSE2 does not throw CertificateExpiredException, it throws a CertificateException
        assertTrue(thrown instanceof CertificateExpiredException || "Certificate expired".equals(thrown.getMessage()));
    }

    @Test
    public void testCreationOfTrustStoreWithoutCertificate() throws Exception
    {
        final CertificateAndCrl<File> data = generateCertificateAndCrl();
        final Map<String, Object> attributes = Map.of(
                NonJavaTrustStore.NAME, NAME,
                NonJavaTrustStore.CERTIFICATES_URL, data.getCrl().getAbsolutePath(),
                NonJavaTrustStore.TYPE, NON_JAVA_TRUST_STORE);

        KeyStoreTestHelper.checkExceptionThrownDuringKeyStoreCreation(FACTORY, BROKER, TrustStore.class, attributes,
                                                                      "Cannot load certificate(s)");
    }

    @Test
    public void testCreationOfTrustStoreFromValidCertificate_MissingCrlFile() throws Exception
    {
        final KeyCertificatePair keyCertPair = TlsResourceBuilder.createSelfSigned(DN_FOO);
        final Path certificateFile = TLS_RESOURCE.saveCertificateAsPem(keyCertPair.getCertificate());
        final Map<String, Object> attributes = Map.of(NonJavaTrustStore.NAME, NAME,
                NonJavaTrustStore.CERTIFICATES_URL, certificateFile.toFile().getAbsolutePath(),
                NonJavaTrustStore.TYPE, NON_JAVA_TRUST_STORE,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_CHECK_ENABLED, true,
                NonJavaTrustStore.CERTIFICATE_REVOCATION_LIST_URL, NOT_A_CRL);

        KeyStoreTestHelper.checkExceptionThrownDuringKeyStoreCreation(FACTORY, BROKER, TrustStore.class, attributes,
                String.format("Unable to load certificate revocation list '%s' for truststore '%s'", NOT_A_CRL, NAME));
    }

    private KeyCertificatePair createExpiredCertificate() throws Exception
    {
        final Instant from = Instant.now().minus(10, ChronoUnit.DAYS);
        final Instant to = Instant.now().minus(5, ChronoUnit.DAYS);
        return TlsResourceBuilder.createSelfSigned(DN_FOO, from, to);
    }

    @SuppressWarnings("unchecked")
    private NonJavaTrustStore<?> createTestTrustStore(final Map<String, Object> attributes)
    {
        return (NonJavaTrustStore<?>) FACTORY.create(TrustStore.class, attributes, BROKER);
    }

    private CertificateAndCrl<File> generateCertificateAndCrl() throws Exception
    {
        final KeyCertificatePair caPair = TlsResourceBuilder.createKeyPairAndRootCA(DN_CA);
        final KeyCertificatePair keyCertPair1 = TlsResourceBuilder.createKeyPairAndCertificate(DN_FOO, caPair);
        final KeyCertificatePair keyCertPair2 = TlsResourceBuilder.createKeyPairAndCertificate(DN_BAR, caPair);
        final Path clrFile =
                TLS_RESOURCE.createCrl(caPair, keyCertPair1.getCertificate(), keyCertPair2.getCertificate());
        final Path caCertificateFile = TLS_RESOURCE.saveCertificateAsPem(caPair.getCertificate());
        return new CertificateAndCrl<>(caCertificateFile.toFile(), clrFile.toFile(), caPair);
    }

    private static class CertificateAndCrl<T>
    {
        private final T _certificate;
        private final T _crl;
        private final KeyCertificatePair _ca;

        private CertificateAndCrl(final T certificate, final T crl, final KeyCertificatePair ca)
        {
            _certificate = certificate;
            _crl = crl;
            _ca = ca;
        }

        T getCertificate()
        {
            return _certificate;
        }

        T getCrl()
        {
            return _crl;
        }

        KeyCertificatePair getCa()
        {
            return _ca;
        }
    }
}
