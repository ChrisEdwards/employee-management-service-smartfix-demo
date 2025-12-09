package com.example.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.example.config.SecurityConfig;
import com.example.service.EmployeeService;

@WebMvcTest(EmployeeController.class)
@Import(SecurityConfig.class)
public class EmployeeControllerSecurityTest {

  @Autowired private MockMvc mockMvc;

  @MockBean private EmployeeService employeeService;

  @Test
  public void testRedirectWithNormalUrl() throws Exception {
    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", "https://www.contrastsecurity.com"))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).isEqualTo("https://www.contrastsecurity.com");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
  }

  @Test
  public void testRedirectWithHeaderInjectionAttempt() throws Exception {
    String maliciousUrl = "https://example.com\r\nX-Injected-Header: malicious";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
    assertThat(locationHeader).isEqualTo("https://example.comX-Injected-Header: malicious");

    String injectedHeader = result.getResponse().getHeader("X-Injected-Header");
    assertThat(injectedHeader).isNull();
  }

  @Test
  public void testRedirectWithCarriageReturnOnly() throws Exception {
    String maliciousUrl = "https://example.com\rX-Injected: value";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
  }

  @Test
  public void testRedirectWithNewlineOnly() throws Exception {
    String maliciousUrl = "https://example.com\nX-Injected: value";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
  }

  @Test
  public void testRedirectWithMultipleCRLF() throws Exception {
    String maliciousUrl = "https://example.com\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
    // After CRLF removal, the malicious content is concatenated but cannot inject headers
    assertThat(locationHeader)
        .isEqualTo("https://example.comHTTP/1.1 200 OKContent-Type: text/html");
  }

  @Test
  public void testRedirectWithCustomHeaderInjection() throws Exception {
    String maliciousUrl = "https://example.com\r\nSet-Cookie: sessionid=malicious";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");

    String setCookieHeader = result.getResponse().getHeader("Set-Cookie");
    assertThat(setCookieHeader).isNull();

    String customHeader = result.getResponse().getHeader("X-Custom-Header");
    assertThat(customHeader).doesNotContain("\r");
    assertThat(customHeader).doesNotContain("\n");
  }
}
