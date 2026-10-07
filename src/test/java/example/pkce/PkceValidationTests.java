package example.pkce;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("PKCE authorization request validation")
class PkceValidationTests {

    private static final String REDIRECT_URI = "http://127.0.0.1/callback";
    private static final String VALID_S256_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Autowired
    private MockMvc mvc;

    @Test
    @DisplayName("A valid S256 challenge issues an authorization code")
    void validS256ChallengeIssuesAuthorizationCode() throws Exception {
        mvc.perform(authorizationRequest()
                        .queryParam("code_challenge", VALID_S256_CHALLENGE)
                        .with(user("alice")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?code=")));
    }

    @Test
    @DisplayName("An authenticated request with a short S256 challenge is rejected")
    void shortS256ChallengeMustReturnInvalidRequest() throws Exception {
        mvc.perform(authorizationRequest()
                        .queryParam("code_challenge", "SHORT")
                        .with(user("alice")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?error=invalid_request")));
    }

    @Test
    @DisplayName("An authenticated request with a forbidden challenge character is rejected")
    void s256ChallengeWithInvalidCharacterMustReturnInvalidRequest() throws Exception {
        String challenge = VALID_S256_CHALLENGE.substring(0, VALID_S256_CHALLENGE.length() - 1) + "!";
        mvc.perform(authorizationRequest()
                        .queryParam("code_challenge", challenge)
                        .with(user("alice")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?error=invalid_request")));
    }

    @Test
    @DisplayName("An anonymous browser request with a short challenge is rejected before login")
    void shortS256ChallengeMustBeRejectedBeforeLogin() throws Exception {
        mvc.perform(authorizationRequest()
                        .queryParam("code_challenge", "SHORT")
                        .accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", startsWith(REDIRECT_URI + "?error=invalid_request")));
    }

    private static MockHttpServletRequestBuilder authorizationRequest() {
        return get("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", "pkce-client")
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("code_challenge_method", "S256");
    }
}
