package com.baeldung.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

class MySimpleUrlAuthenticationSuccessHandlerTest {

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private MySimpleUrlAuthenticationSuccessHandler urlAuthenticationSuccessHandler;

    @BeforeEach
    void setup() {
        urlAuthenticationSuccessHandler = new MySimpleUrlAuthenticationSuccessHandler();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    public void givenManagerRole_thenRedirectedToManagerView() throws Exception {
        Collection<GrantedAuthority> authorities = Arrays.asList(
                new SimpleGrantedAuthority("READ_PRIVILEGE"),
                new SimpleGrantedAuthority("ROLE_MANAGER")
        );
        Authentication authentication = new TestAuthentication(authorities);

        urlAuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("/management.html");
    }

    @Test
    public void givenWritePrivilege_thenRedirectedToAdminView() throws Exception {
        Collection<GrantedAuthority> authorities = Arrays.asList(
                new SimpleGrantedAuthority("READ_PRIVILEGE"),
                new SimpleGrantedAuthority("WRITE_PRIVILEGE")
        );
        Authentication authentication = new TestAuthentication(authorities);

        urlAuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("/console");
    }

    @Test
    public void givenOnlyReadPrivilege_thenRedirectedToUserView() throws Exception {
        Collection<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("READ_PRIVILEGE"));
        Authentication authentication = new TestAuthentication(authorities);

        urlAuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("/homepage.html?user=testName");
    }

    @Test
    public void givenInvalidAuthorities_thenException() {
        Authentication mock = new TestAuthentication(Collections.emptyList());

        assertThatIllegalStateException().isThrownBy(
                () -> urlAuthenticationSuccessHandler.onAuthenticationSuccess(request, response, mock)
        );
    }

    static class TestAuthentication implements Authentication {

        private final Collection<GrantedAuthority> authorities;

        TestAuthentication(Collection<GrantedAuthority> authorities) {
            this.authorities = authorities;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorities;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getDetails() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public boolean isAuthenticated() {
            return false;
        }

        @Override
        public void setAuthenticated(boolean b) throws IllegalArgumentException {

        }

        @Override
        public String getName() {
            return "testName";
        }
    }

}