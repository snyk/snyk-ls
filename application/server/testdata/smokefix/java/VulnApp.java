import java.sql.*;

public class VulnApp {
    public void query(Connection conn, String userInput) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = '" + userInput + "'");
    }
}
