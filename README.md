spring-security-oauth2-client
=============================

[![Join the chat at https://gitter.im/pwheel/spring-security-oauth2-client](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/pwheel/spring-security-oauth2-client?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

An OAuth2 client implementation for Spring Security that allows you to use an OAuth2 Provider (such as DailyCred) directly as an Authentication Provider.

Why?
----

The [Spring Security OAuth](http://static.springsource.org/spring-security/oauth/) and [Spring Security Social](http://www.springsource.org/spring-social) projects both expect a user to authenticate locally and then connect that account with the account of an OAuth Service Provider.

This project allows you to directly authenticate with the OAuth Provider in the first instance, rather than as a secondary step.
I was unable to find a project that was easily extensible enough to do what I wanted, so this project was born.
It has been tested against DailyCred.

Usage
----

You should not need to implement any classes to use this library. If you do then it should be easily extendable.

Example usage:

    <http entry-point-ref="oAuth2EntryPoint">
        <logout logout-success-url="/index.shtml"/>
        <custom-filter ref="oauth2AuthFilter" after="EXCEPTION_TRANSLATION_FILTER"/>
    </http>

    <beans:bean id="oAuth2EntryPoint" class="com.racquettrack.security.oauth.OAuth2AuthenticationEntryPoint">
        <beans:property name="oAuth2ServiceProperties" ref="oauth2ServiceProperties"/>
    </beans:bean>

    <beans:bean id="oauth2AuthFilter" class="com.racquettrack.security.oauth.OAuth2AuthenticationFilter">
        <beans:constructor-arg name="defaultFilterProcessesUrl" value="/oauth/callback"/>
        <beans:property name="authenticationManager" ref="authenticationManager"/>
        <beans:property name="oAuth2ServiceProperties" ref="oauth2ServiceProperties"/>
    </beans:bean>

    <beans:bean id="oauth2AuthenticationProvider" class="com.racquettrack.security.oauth.OAuth2AuthenticationProvider">
        <beans:property name="authenticatedUserDetailsService" ref="oAuth2UserDetailsService"/>
        <beans:property name="oAuth2ServiceProperties" ref="oauth2ServiceProperties"/>
    </beans:bean>

    <authentication-manager alias="authenticationManager">
        <authentication-provider ref="oauth2AuthenticationProvider">
        </authentication-provider>
    </authentication-manager>

    <beans:bean id="oauth2ServiceProperties" class="com.racquettrack.security.oauth.OAuth2ServiceProperties">
        <beans:property name="accessTokenUri" value="https://www.dailycred.com/oauth/access_token"/>
        <beans:property name="userAuthorisationUri" value="https://www.dailycred.com/connect"/>
        <beans:property name="additionalAuthParams">
            <beans:map>
                <beans:entry key="egKey1" value="egValue1"/>
                <beans:entry key="egKey2" value="egValue2"/>
            </beans:map>
        </beans:property>
        <beans:property name="redirectUri" value="http://localhost:8080/oauth/callback"/>
        <beans:property name="clientId" value="${oauth2.client_id}"/>
        <beans:property name="clientSecret" value="${oauth2.client_secret}"/>
        <beans:property name="userInfoUri" value="https://www.dailycred.com/graph/me.json"/>
    </beans:bean>

    <beans:bean id="oAuth2UserDetailsService" class="com.racquettrack.security.oauth.OAuth2UserDetailsService">
        <beans:property name="oAuth2UserDetailsLoader" ref="userFacade"/>
        <beans:property name="oAuth2ServiceProperties" ref="oauth2ServiceProperties"/>
    </bean>

1.  Define your OAuth2ServiceProperties class. This class is a placeholder for the configuration of your OAuth Provider. Important properties are:
userAuthorisationUri - This is the URI that a user will be redirected to on trying to authentication / hitting the Authentication Entry Point
additionalAuthParams - Any additional query parameters that you want sent to the OAuth Provider as part of the authorisation redirect.
redirectUri - This is the URI that the OAuth Provider will redirect the user to (on your site) if they successfully authenticate. Must be the same as the OAuth2AuthenticationFilter is listening on.
accessTokenUri - This is the REST URI that should be called to obtain an access token from the code. This is called by the OAuth2AuthenticationFilter after the redirect from the OAuth Provider.
clientId - Your client id, given to you by the OAuth Provider.
clientSecret - Your client secret, given to you by the OAuth Provider. It is important to keep this secret.
userInfoUri - The REST URI in the OAuth Provider's system, that will be called to obtain additional information, e.g. the user id, about the user once an access token has been obtained.

2.  Define your OAuth2UserDetailsService. This is called by the (OAuth2)AuthenticationProvider. You must define a bean (userFacade above) that implements the OAuth2UserDetailsLoader. Accounts in your system are linked to those in the OAuth Provider by the user id; this class resolves the local accounts and creates them if a new uesr has been created in the OAuth Provider.

3.  Define your OAuth2AuthenticationProvider bean, hook in the previous two beans.

4.  Define your authentication-manager.

5.  Define the Authentication Entry Point and declare it in the entry-point-ref.

6.  Define the OAuth2AuthenticationFilter to pick up the redirect from the OAuth Provider and hook it in as a custom-filter.