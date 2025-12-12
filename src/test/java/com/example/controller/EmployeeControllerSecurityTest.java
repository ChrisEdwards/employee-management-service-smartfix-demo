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
  public void testRedirectWithHeaderInjectionAttempt() throws Exception {
    String maliciousUrl = "https://www.contrastsecurity.com\r\nX-Injected-Header: malicious";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    String customHeader = result.getResponse().getHeader("X-Custom-Header");

    assertThat(locationHeader).isNotNull();
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
    assertThat(locationHeader)
        .isEqualTo("https://www.contrastsecurity.comX-Injected-Header: malicious");

    assertThat(customHeader).isNotNull();
    assertThat(customHeader).doesNotContain("\r");
    assertThat(customHeader).doesNotContain("\n");

    assertThat(result.getResponse().getHeader("X-Injected-Header")).isNull();
  }

  @Test
  public void testRedirectWithValidUrl() throws Exception {
    String validUrl = "https://www.contrastsecurity.com";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", validUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");

    assertThat(locationHeader).isNotNull();
    assertThat(locationHeader).isEqualTo(validUrl);
  }

  @Test
  public void testRedirectWithMultipleNewlineAttempts() throws Exception {
    String maliciousUrl =
        "https://www.contrastsecurity.com\r\n\r\nSet-Cookie: sessionid=malicious\r\n";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", maliciousUrl))
            .andExpect(status().isFound())
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");

    assertThat(locationHeader).isNotNull();
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
    assertThat(locationHeader)
        .isEqualTo("https://www.contrastsecurity.comSet-Cookie: sessionid=malicious");

    assertThat(result.getResponse().getHeader("Set-Cookie")).isNull();
  }
}
