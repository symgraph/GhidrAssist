package ghidrassist;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

import java.sql.*;

public class RLHFDatabase {

    private static final String DB_PATH_PROPERTY = "GhidrAssist.RLHFDatabasePath";
    private static final String DEFAULT_DB_PATH = GAUtils.getDefaultDataPath("ghidrassist_rlhf.db");
    private Connection connection;

    public RLHFDatabase() {
        String dbPath = Preferences.getProperty(DB_PATH_PROPERTY, DEFAULT_DB_PATH);
        initializeDatabase(dbPath);
    }

    private void initializeDatabase(String dbPath) {
        try {
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            createFeedbackTable();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to initialize RLHF database: " + e.getMessage());
        }
    }

    private void createFeedbackTable() throws SQLException {
        String createTableSQL = "CREATE TABLE IF NOT EXISTS feedback ("
                + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "model_name TEXT NOT NULL,"
                + "prompt_context TEXT NOT NULL,"
                + "system_context TEXT NOT NULL,"
                + "response TEXT NOT NULL,"
                + "feedback INTEGER NOT NULL" // 1 for thumbs up, 0 for thumbs down
                + ")";
        Statement stmt = connection.createStatement();
        stmt.execute(createTableSQL);
        stmt.close();
    }

    public void storeFeedback(String modelName, String promptContext, String systemContext, String response, int feedback) {
        String insertSQL = "INSERT INTO feedback (model_name, prompt_context, system_context, response, feedback) "
                + "VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(insertSQL)) {
            pstmt.setString(1, modelName);
            pstmt.setString(2, promptContext);
            pstmt.setString(3, systemContext);
            pstmt.setString(4, response);
            pstmt.setInt(5, feedback);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to store feedback: " + e.getMessage());
        }
    }

    public void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to close RLHF database connection: " + e.getMessage());
        }
    }
}
