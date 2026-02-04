package com.example.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
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
  public void testRedirectWithValidUrl() throws Exception {
    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", "https://www.contrastsecurity.com"))
            .andExpect(status().isFound())
            .andExpect(header().string("Location", "https://www.contrastsecurity.com"))
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).isEqualTo("https://www.contrastsecurity.com");
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
  }

  @Test
  public void testRedirectBlocksHeaderInjectionWithCRLF() throws Exception {
    String maliciousUrl = "https://example.com\r\nX-Injected-Header: malicious";

    mockMvc
        .perform(get("/api/redirect").param("url", maliciousUrl))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void testRedirectBlocksHeaderInjectionWithNewline() throws Exception {
    String maliciousUrl = "https://example.com\nSet-Cookie: sessionid=malicious";

    mockMvc
        .perform(get("/api/redirect").param("url", maliciousUrl))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void testRedirectRejectsInvalidUrlFormat() throws Exception {
    String invalidUrl = "not a valid url";

    mockMvc
        .perform(get("/api/redirect").param("url", invalidUrl))
        .andExpect(status().isBadRequest());
  }

  @Test
  public void testRedirectWithUrlContainingSpecialCharacters() throws Exception {
    String urlWithParams = "https://example.com/path?param=value&other=test";

    MvcResult result =
        mockMvc
            .perform(get("/api/redirect").param("url", urlWithParams))
            .andExpect(status().isFound())
            .andExpect(header().string("Location", urlWithParams))
            .andReturn();

    String locationHeader = result.getResponse().getHeader("Location");
    assertThat(locationHeader).isEqualTo(urlWithParams);
    assertThat(locationHeader).doesNotContain("\r");
    assertThat(locationHeader).doesNotContain("\n");
  }

  @Test
  public void testRedirectSanitizesCustomHeader() throws Exception {
    String maliciousUrl = "https://example.com\r\nX-Evil: injected";

    mockMvc
        .perform(get("/api/redirect").param("url", maliciousUrl))
        .andExpect(status().isBadRequest());
  }
}
