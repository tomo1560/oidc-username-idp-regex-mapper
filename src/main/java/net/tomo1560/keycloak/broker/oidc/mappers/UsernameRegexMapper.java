package net.tomo1560.keycloak.broker.oidc.mappers;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.mappers.AbstractClaimMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.social.bitbucket.BitbucketIdentityProviderFactory;
import org.keycloak.social.facebook.FacebookIdentityProviderFactory;
import org.keycloak.social.github.GitHubIdentityProviderFactory;
import org.keycloak.social.gitlab.GitLabIdentityProviderFactory;
import org.keycloak.social.google.GoogleIdentityProviderFactory;
import org.keycloak.social.instagram.InstagramIdentityProviderFactory;
import org.keycloak.social.linkedin.LinkedInIdentityProviderFactory;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderFactory;
import org.keycloak.social.openshift.OpenshiftV3IdentityProviderFactory;
import org.keycloak.social.openshift.OpenshiftV4IdentityProviderFactory;
import org.keycloak.social.paypal.PayPalIdentityProviderFactory;
import org.keycloak.social.stackoverflow.StackoverflowIdentityProviderFactory;
import org.keycloak.social.twitter.TwitterIdentityProviderFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UsernameRegexMapper extends AbstractClaimMapper {

    public static final String[] COMPATIBLE_PROVIDERS =
            new String[] {KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
                    OIDCIdentityProviderFactory.PROVIDER_ID,
                    BitbucketIdentityProviderFactory.PROVIDER_ID,
                    FacebookIdentityProviderFactory.PROVIDER_ID,
                    GitHubIdentityProviderFactory.PROVIDER_ID,
                    GitLabIdentityProviderFactory.PROVIDER_ID,
                    GoogleIdentityProviderFactory.PROVIDER_ID,
                    InstagramIdentityProviderFactory.PROVIDER_ID,
                    LinkedInIdentityProviderFactory.PROVIDER_ID,
                    MicrosoftIdentityProviderFactory.PROVIDER_ID,
                    OpenshiftV3IdentityProviderFactory.PROVIDER_ID,
                    OpenshiftV4IdentityProviderFactory.PROVIDER_ID,
                    PayPalIdentityProviderFactory.PROVIDER_ID,
                    StackoverflowIdentityProviderFactory.PROVIDER_ID,
                    TwitterIdentityProviderFactory.PROVIDER_ID};

    public static final String PROVIDER_ID = "oidc-username-idp-regex-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String REGEX = "regex";

    static {
        ProviderConfigProperty ClaimProperty;
        ClaimProperty = new ProviderConfigProperty();
        ClaimProperty.setName(CLAIM);
        ClaimProperty.setLabel("Claim");
        ClaimProperty.setHelpText("");
        ClaimProperty.setType(ProviderConfigProperty.STRING_TYPE);
        ClaimProperty.setDefaultValue("");
        configProperties.add(ClaimProperty);

        ProviderConfigProperty regexProperty;
        regexProperty = new ProviderConfigProperty();
        regexProperty.setName(REGEX);
        regexProperty.setLabel("Regex");
        regexProperty.setHelpText("");
        regexProperty.setType(ProviderConfigProperty.STRING_TYPE);
        regexProperty.setDefaultValue("");
        configProperties.add(regexProperty);
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Preprocessor";
    }

    @Override
    public String getDisplayType() {
        return "Username Regex Importer";
    }

    @Override
    public void updateBrokeredUser(KeycloakSession keycloakSession, RealmModel realmModel,
            UserModel userModel, IdentityProviderMapperModel identityProviderMapperModel,
            BrokeredIdentityContext brokeredIdentityContext) {

    }

    @Override
    public String getHelpText() {
        return "Set the username using a regular expression";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String regexString = mapperModel.getConfig().get(REGEX);
        String claim = mapperModel.getConfig().get(CLAIM);
        String username = (String) AbstractClaimMapper.getClaimValue(context, claim);
        if (username == null || "".equals(username)) {
            return;
        }
        if (regexString != null && !"".equals(regexString)) {
            Pattern regex = Pattern.compile(regexString);
            Matcher m = regex.matcher(username);
            if (m.find()) {
                String result = m.group(1);
                if (result != null && !"".equals(result)) {
                    context.setModelUsername(result);
                    return;
                }
            }
        }
        context.setModelUsername(username);
    }


    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
