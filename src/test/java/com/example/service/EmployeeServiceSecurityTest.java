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
  public void testExecuteCommand_ValidCommand_ls() {
    String result = employeeService.executeCommand("ls");
    assertThat(result).doesNotContain("Error: Invalid command");
  }

  @Test
  public void testExecuteCommand_ValidCommand_pwd() {
    String result = employeeService.executeCommand("pwd");
    assertThat(result).doesNotContain("Error: Invalid command");
  }

  @Test
  public void testExecuteCommand_ValidCommand_date() {
    String result = employeeService.executeCommand("date");
    assertThat(result).doesNotContain("Error: Invalid command");
  }

  @Test
  public void testExecuteCommand_RejectsCommandInjection_WithSemicolon() {
    String maliciousCommand = "ls; rm -rf /";
    String result = employeeService.executeCommand(maliciousCommand);
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsCommandInjection_WithPipe() {
    String maliciousCommand = "ls | cat /etc/passwd";
    String result = employeeService.executeCommand(maliciousCommand);
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsCommandInjection_WithAmpersand() {
    String maliciousCommand = "ls && cat /etc/passwd";
    String result = employeeService.executeCommand(maliciousCommand);
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsArbitraryCommand() {
    String arbitraryCommand = "cat /etc/passwd";
    String result = employeeService.executeCommand(arbitraryCommand);
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsCommandWithArguments() {
    String commandWithArgs = "ls -la /etc";
    String result = employeeService.executeCommand(commandWithArgs);
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsNullCommand() {
    String result = employeeService.executeCommand(null);
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsEmptyCommand() {
    String result = employeeService.executeCommand("");
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_RejectsWhitespaceCommand() {
    String result = employeeService.executeCommand("   ");
    assertThat(result)
        .contains("Error: Invalid command. Only 'ls', 'pwd', and 'date' commands are allowed.");
  }

  @Test
  public void testExecuteCommand_AcceptsValidCommandWithWhitespace() {
    String result = employeeService.executeCommand("  ls  ");
    assertThat(result).doesNotContain("Error: Invalid command");
  }
}
