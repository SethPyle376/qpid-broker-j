package org.apache.qpid.server.okta;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.qpid.server.configuration.IllegalConfigurationException;
import org.apache.qpid.server.model.NamedAddressSpace;
import org.apache.qpid.server.plugin.PluggableService;
import org.apache.qpid.server.security.auth.UsernamePrincipal;
import org.apache.qpid.server.security.auth.manager.oauth2.IdentityResolverException;
import org.apache.qpid.server.security.auth.manager.oauth2.OAuth2AuthenticationProvider;
import org.apache.qpid.server.security.auth.manager.oauth2.OAuth2IdentityResolverService;
import org.apache.qpid.server.security.auth.manager.oauth2.OAuth2Utils;
import org.apache.qpid.server.util.ConnectionBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.security.Principal;
import java.util.Base64;
import java.util.Map;

import static org.apache.qpid.server.model.preferences.GenericPrincipal.UTF8;

@PluggableService
public class OktaClientCredentialsIdentityResolverService implements OAuth2IdentityResolverService {
    private static final Logger LOGGER = LoggerFactory.getLogger(OktaClientCredentialsIdentityResolverService.class);
    private static final String TYPE = "OktaClientCredentials";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public void validate(OAuth2AuthenticationProvider<?> authProvider) throws IllegalConfigurationException {}

    @Override
    public Principal getUserPrincipal(OAuth2AuthenticationProvider<?> authProvider, String accessToken, NamedAddressSpace addressSpace) throws IOException, IdentityResolverException {
        var introspectionEndpoint = authProvider.getIdentityResolverEndpointURI(addressSpace).toURL();

        var connectionBuilder = new ConnectionBuilder(introspectionEndpoint);

        connectionBuilder.setTlsProtocolAllowList(authProvider.getTlsProtocolAllowList())
                .setTlsProtocolDenyList(authProvider.getTlsProtocolDenyList())
                .setTlsCipherSuiteAllowList(authProvider.getTlsCipherSuiteAllowList())
                .setTlsCipherSuiteDenyList(authProvider.getTlsCipherSuiteDenyList());

        var connection = connectionBuilder.build();

        var creds = authProvider.getClientId() + ":" + authProvider.getClientSecret();
        var credsEncoded = Base64.getEncoder().encode(creds.getBytes(UTF8));
        var authHeaderValue = "Basic " + new String(credsEncoded);

        LOGGER.info(authHeaderValue);

        var body = "token=" + accessToken + "&" + "token_type_hint=access_token";
        var postData = body.toCharArray();
        var postDataLength = postData.length;

        LOGGER.info(String.valueOf(postData));

        connection.setRequestMethod("POST");
        connection.setRequestProperty("Accept-Charset", UTF8);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Authorization", authHeaderValue);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("Content-Length", Integer.toString(postDataLength));

        connection.setDoOutput(true);
        var outputWriter = new OutputStreamWriter(connection.getOutputStream());
        outputWriter.write(postData);
        outputWriter.flush();

        connection.connect();

        try (var input = OAuth2Utils.getResponseStream(connection)) {
            int responseCode = connection.getResponseCode();

            if (responseCode != 200) {
                throw new IdentityResolverException(String.format(
                        "Identity resolver '%s' failed, response code %d",
                        introspectionEndpoint, responseCode));
            }
            var node = OBJECT_MAPPER.readTree(input);
            var sub = node.get("sub");

            if (sub == null) {
                throw new IdentityResolverException(String.format(
                        "Identity resolver '%s' failed, response did not include 'sub'",
                        introspectionEndpoint));
            }

            return new UsernamePrincipal(sub.textValue(), authProvider);
        }
    }

    @Override
    public URI getDefaultAuthorizationEndpointURI(OAuth2AuthenticationProvider<?> oAuth2AuthenticationProvider) {
        return null;
    }

    @Override
    public URI getDefaultTokenEndpointURI(OAuth2AuthenticationProvider<?> oAuth2AuthenticationProvider) {
        return null;
    }

    @Override
    public URI getDefaultIdentityResolverEndpointURI(OAuth2AuthenticationProvider<?> oAuth2AuthenticationProvider) {
        return null;
    }

    @Override
    public String getDefaultScope(OAuth2AuthenticationProvider<?> oAuth2AuthenticationProvider) {
        return null;
    }
}
