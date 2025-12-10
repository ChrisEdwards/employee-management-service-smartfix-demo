package com.example.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

import javax.sql.DataSource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.model.User;

@SpringBootTest
public class EmployeeServiceSecurityTest {

  @Mock private DataSource dataSource;

  @Mock private Connection connection;

  @Mock private PreparedStatement preparedStatement;

  @Mock private ResultSet resultSet;

  @InjectMocks private EmployeeService employeeService;

  @BeforeEach
  public void setup() throws SQLException {
    MockitoAnnotations.openMocks(this);

    when(dataSource.getConnection()).thenReturn(connection);
    when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
    when(preparedStatement.executeQuery()).thenReturn(resultSet);
    when(resultSet.next()).thenReturn(false);
  }

  @Test
  public void testFindUserByUsername_UsesPreparedStatement() throws SQLException {
    String username = "testuser";

    employeeService.findUserByUsername(username);

    verify(connection).prepareStatement(eq("SELECT * FROM users WHERE username = ?"));
    verify(preparedStatement).setString(1, username);
    verify(preparedStatement).executeQuery();
  }

  @Test
  public void testFindUserByUsername_WithSqlInjectionAttempt() throws SQLException {
    String maliciousUsername = "admin' OR '1'='1";

    when(resultSet.next()).thenReturn(false);

    List<User> users = employeeService.findUserByUsername(maliciousUsername);

    verify(connection).prepareStatement(eq("SELECT * FROM users WHERE username = ?"));
    verify(preparedStatement).setString(1, maliciousUsername);

    assertThat(users).isEmpty();
  }

  @Test
  public void testFindUserByUsername_WithSpecialCharacters() throws SQLException {
    String usernameWithSpecialChars = "user'; DROP TABLE users; --";

    when(resultSet.next()).thenReturn(false);

    List<User> users = employeeService.findUserByUsername(usernameWithSpecialChars);

    verify(connection).prepareStatement(eq("SELECT * FROM users WHERE username = ?"));
    verify(preparedStatement).setString(1, usernameWithSpecialChars);

    assertThat(users).isEmpty();
  }

  @Test
  public void testFindUserByUsername_ReturnsCorrectUser() throws SQLException {
    String username = "validuser";

    when(resultSet.next()).thenReturn(true, false);
    when(resultSet.getLong("id")).thenReturn(1L);
    when(resultSet.getString("username")).thenReturn(username);
    when(resultSet.getString("password")).thenReturn("hashedpassword");
    when(resultSet.getString("email")).thenReturn("user@example.com");

    List<User> users = employeeService.findUserByUsername(username);

    verify(preparedStatement).setString(1, username);

    assertThat(users).hasSize(1);
    assertThat(users.get(0).getUsername()).isEqualTo(username);
    assertThat(users.get(0).getEmail()).isEqualTo("user@example.com");
  }
}
