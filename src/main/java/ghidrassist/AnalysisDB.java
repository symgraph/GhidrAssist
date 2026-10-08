package ghidrassist;

import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.db.migration.SchemaMigrationRunner;
import ghidrassist.db.migration.V2_GraphRAGCore;
import ghidrassist.db.migration.V3_SecurityColumns;
import ghidrassist.db.migration.V4_UserEditedColumn;
import ghidrassist.db.migration.V5_UniqueAddressIndex;
import ghidrassist.db.migration.V7_LlmRenames;
import ghidrassist.db.migration.V9_FunctionCodeFields;
import ghidrassist.db.migration.V10_GraphNodeCategory;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class AnalysisDB {
    private static final String DB_PATH_PROPERTY = "GhidrAssist.AnalysisDBPath";
    private static final String DEFAULT_DB_PATH = GAUtils.getDefaultDataPath("ghidrassist_analysis.db");
    private Connection connection;
    private String databasePath;

    // Cache of BinaryKnowledgeGraph instances per program hash
    private final Map<String, BinaryKnowledgeGraph> graphCache = new ConcurrentHashMap<>();

    public AnalysisDB() {
        String dbPath = Preferences.getProperty(DB_PATH_PROPERTY, DEFAULT_DB_PATH);
        initializeDatabase(dbPath);
    }

    private void initializeDatabase(String dbPath) {
        try {
            databasePath = dbPath;
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            createAnalysisTables();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to initialize Analysis database: " + e.getMessage());
        }
    }

    private void createAnalysisTables() throws SQLException {
        // Use the versioned migration system
        SchemaMigrationRunner runner = new SchemaMigrationRunner(connection);
        runner.runMigrations();

        // Additional legacy compatibility checks
        migrateChatMessagesTable();

        // Validate Graph-RAG schema integrity
        ensureGraphRagSchema();
    }

    private void ensureGraphRagSchema() throws SQLException {
        List<String> nodeColumns = Arrays.asList(
                "id",
                "type",
                "address",
                "binary_id",
                "name",
                "signature",
                "decompiled_code",
                "disassembly",
                "raw_content",
                "llm_summary",
                "confidence",
                "embedding",
                "security_flags",
                "network_apis",
                "file_io_apis",
                "ip_addresses",
                "urls",
                "file_paths",
                "domains",
                "registry_keys",
                "category",
                "risk_level",
                "activity_profile",
                "analysis_depth",
                "created_at",
                "updated_at",
                "is_stale",
                "user_edited"
        );
        List<String> edgeColumns = Arrays.asList(
                "id",
                "source_id",
                "target_id",
                "type",
                "weight",
                "metadata",
                "created_at"
        );
        List<String> communityColumns = Arrays.asList(
                "id",
                "level",
                "binary_id",
                "parent_community_id",
                "name",
                "summary",
                "member_count",
                "is_stale",
                "created_at",
                "updated_at"
        );
        List<String> memberColumns = Arrays.asList(
                "community_id",
                "node_id",
                "membership_score"
        );
        List<String> ftsColumns = Arrays.asList(
                "id",
                "name",
                "signature",
                "llm_summary",
                "security_flags"
        );

        restoreGraphRagTablesFromBackups(nodeColumns, edgeColumns, communityColumns, memberColumns);

        if (!tableExists("graph_nodes") ||
            !tableExists("graph_edges") ||
            !tableExists("graph_communities") ||
            !tableExists("community_members")) {
            Msg.warn(this, "Graph-RAG tables missing after migration; recreating canonical schema");
            recreateGraphRagSchema();
        }

        dropGraphNodeTriggers();

        boolean nodesRenamed = ensureTableSchema("graph_nodes", nodeColumns);
        if (nodesRenamed) {
            renameTableWithCounter("graph_edges");
            renameTableWithCounter("graph_communities");
            renameTableWithCounter("community_members");
            renameTableWithCounter("node_fts");
            recreateGraphRagSchema();
            ensureFtsSync();
            return;
        }

        boolean edgesRenamed = ensureTableSchema("graph_edges", edgeColumns);
        boolean communitiesRenamed = ensureTableSchema("graph_communities", communityColumns);
        boolean membersRenamed = ensureTableSchema("community_members", memberColumns);
        boolean ftsRenamed = ensureTableSchema("node_fts", ftsColumns);

        if (edgesRenamed || communitiesRenamed || membersRenamed || ftsRenamed || !tableExists("node_fts")) {
            Msg.warn(this, "Graph-RAG auxiliary schema out of date; recreating canonical schema");
            recreateGraphRagSchema();
        }

        ensureFtsSync();
    }

    private void dropGraphNodeTriggers() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ai");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ad");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_au");
        }
    }

    private void ensureFtsSync() {
        try (Statement stmt = connection.createStatement()) {
            ResultSet nodeRs = stmt.executeQuery(
                "SELECT COUNT(*) FROM graph_nodes WHERE llm_summary IS NOT NULL AND TRIM(llm_summary) != ''");
            int nodeCount = nodeRs.next() ? nodeRs.getInt(1) : 0;
            nodeRs.close();
            if (nodeCount == 0) return;

            int ftsCount = 0;
            try {
                ResultSet ftsRs = stmt.executeQuery("SELECT COUNT(*) FROM node_fts");
                ftsCount = ftsRs.next() ? ftsRs.getInt(1) : 0;
                ftsRs.close();
            } catch (SQLException e) {
                ftsCount = 0;
            }

            if (ftsCount < nodeCount * 0.8) {
                Msg.info(this, String.format("FTS out of sync (FTS: %d, nodes with summaries: %d). Rebuilding...",
                    ftsCount, nodeCount));
                try {
                    stmt.execute("INSERT INTO node_fts(node_fts) VALUES('rebuild')");
                    Msg.info(this, "FTS rebuild completed.");
                } catch (SQLException rebuildEx) {
                    Msg.warn(this, "FTS rebuild failed (likely corrupt), attempting full repair: " + rebuildEx.getMessage());
                    repairFtsTable();
                }
            }
        } catch (SQLException e) {
            Msg.warn(this, "FTS sync check failed: " + e.getMessage());
        }
    }

    /**
     * Rebuild the FTS index from current graph_nodes data.
     * Call after batch operations (semantic analysis, reindex) to sync FTS.
     */
    public void rebuildFts() {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("INSERT INTO node_fts(node_fts) VALUES('rebuild')");
            Msg.info(this, "FTS index rebuilt successfully.");
        } catch (SQLException e) {
            Msg.warn(this, "FTS rebuild failed, attempting full repair: " + e.getMessage());
            repairFtsTable();
        }
    }

    private boolean ensureTableSchema(String tableName, List<String> expectedColumns) throws SQLException {
        if (!tableExists(tableName)) {
            return false;
        }
        List<String> existing = getTableColumns(tableName);
        if (!columnsMatch(existing, expectedColumns)) {
            renameTableWithCounter(tableName);
            return true;
        }
        return false;
    }

    private boolean columnsMatch(List<String> existing, List<String> expected) {
        Set<String> existingSet = new HashSet<>(existing);
        Set<String> expectedSet = new HashSet<>(expected);
        return existingSet.equals(expectedSet);
    }

    private boolean tableExists(String tableName) throws SQLException {
        try (PreparedStatement stmt = connection.prepareStatement(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?")) {
            stmt.setString(1, tableName);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    private List<String> getTableColumns(String tableName) throws SQLException {
        List<String> columns = new ArrayList<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + tableName + ")")) {
            while (rs.next()) {
                columns.add(rs.getString("name"));
            }
        }
        return columns;
    }

    private String nextBackupName(String tableName) throws SQLException {
        int suffix = 1;
        while (tableExists(tableName + "_backup_" + suffix)) {
            suffix++;
        }
        return tableName + "_backup_" + suffix;
    }

    private void renameTableWithCounter(String tableName) throws SQLException {
        if (!tableExists(tableName)) {
            return;
        }
        try (Statement stmt = connection.createStatement()) {
            if ("node_fts".equals(tableName)) {
                stmt.execute("DROP TABLE IF EXISTS " + tableName);
                return;
            }
            String backupName = nextBackupName(tableName);
            stmt.execute("ALTER TABLE " + tableName + " RENAME TO " + backupName);
        }
    }

    private void restoreGraphRagTablesFromBackups(List<String> nodeColumns, List<String> edgeColumns,
                                                  List<String> communityColumns, List<String> memberColumns)
            throws SQLException {
        restoreTableFromBackupIfMissing("graph_nodes", nodeColumns);
        restoreTableFromBackupIfMissing("graph_edges", edgeColumns);
        restoreTableFromBackupIfMissing("graph_communities", communityColumns);
        restoreTableFromBackupIfMissing("community_members", memberColumns);
    }

    private void restoreTableFromBackupIfMissing(String tableName, List<String> expectedColumns) throws SQLException {
        if (tableExists(tableName)) {
            return;
        }

        List<String> candidates = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(
                "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE ? OR name = ? OR name LIKE ?) ORDER BY name DESC")) {
            stmt.setString(1, tableName + "_backup_%");
            stmt.setString(2, tableName + "_bak");
            stmt.setString(3, tableName + "_bak_%");
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    candidates.add(rs.getString("name"));
                }
            }
        }

        for (String candidate : candidates) {
            if (!columnsMatch(getTableColumns(candidate), expectedColumns)) {
                continue;
            }
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("ALTER TABLE " + candidate + " RENAME TO " + tableName);
            }
            Msg.warn(this, "Restored missing " + tableName + " from backup table " + candidate);
            return;
        }
    }

    private void recreateGraphRagSchema() throws SQLException {
        new V2_GraphRAGCore().migrate(connection);
        new V3_SecurityColumns().migrate(connection);
        new V4_UserEditedColumn().migrate(connection);
        new V5_UniqueAddressIndex().migrate(connection);
        new V7_LlmRenames().migrate(connection);
        new V9_FunctionCodeFields().migrate(connection);
        new V10_GraphNodeCategory().migrate(connection);
    }

    /**
     * Repair or recreate the FTS table when it's corrupt.
     * This properly handles severe corruption by:
     * 1. Dropping any leftover triggers (FTS is managed via explicit rebuild, not triggers)
     * 2. Removing FTS entries from sqlite_master if needed
     * 3. Running VACUUM to rebuild the database
     * 4. Recreating FTS table
     * 5. Rebuilding the index from existing data
     *
     * @return true if repair was successful
     */
    public boolean repairFtsTable() {
        Msg.info(this, "Attempting full FTS table repair...");
        try (Statement stmt = connection.createStatement()) {
            // Step 1: Drop any leftover triggers
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ai");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ad");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_au");

            // Step 2: Try normal drop
            boolean normalDropWorked = false;
            try {
                stmt.execute("DROP TABLE IF EXISTS node_fts");
                normalDropWorked = true;
                Msg.info(this, "FTS table dropped normally");
            } catch (SQLException e) {
                Msg.warn(this, "Normal DROP failed: " + e.getMessage());
            }

            // Step 3: If normal drop failed, use writable_schema + VACUUM
            if (!normalDropWorked) {
                Msg.info(this, "Using writable_schema to remove corrupt FTS entries...");
                stmt.execute("PRAGMA writable_schema = ON");
                stmt.execute("DELETE FROM sqlite_master WHERE type = 'table' AND name = 'node_fts'");
                stmt.execute("DELETE FROM sqlite_master WHERE type = 'table' AND name LIKE 'node_fts_%'");
                stmt.execute("DELETE FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'graph_nodes_%'");
                stmt.execute("PRAGMA writable_schema = OFF");

                Msg.info(this, "Running VACUUM to rebuild database...");
                stmt.execute("VACUUM");
                Msg.info(this, "VACUUM completed");
            }

            // Step 4: Recreate the FTS table
            Msg.info(this, "Creating fresh FTS table...");
            stmt.execute("CREATE VIRTUAL TABLE IF NOT EXISTS node_fts USING fts5("
                    + "id, "
                    + "name, "
                    + "signature, "
                    + "llm_summary, "
                    + "security_flags, "
                    + "content='graph_nodes', "
                    + "content_rowid='rowid'"
                    + ")");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_ai AFTER INSERT ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES (NEW.rowid, NEW.id, NEW.name, NEW.signature, NEW.llm_summary, NEW.security_flags); "
                    + "END");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_ad AFTER DELETE ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.signature, OLD.llm_summary, OLD.security_flags); "
                    + "END");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_au AFTER UPDATE ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.signature, OLD.llm_summary, OLD.security_flags); "
                    + "INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES (NEW.rowid, NEW.id, NEW.name, NEW.signature, NEW.llm_summary, NEW.security_flags); "
                    + "END");

            // Step 5: Rebuild FTS index from existing graph_nodes data
            Msg.info(this, "Rebuilding FTS index from existing data...");
            stmt.execute("INSERT INTO node_fts(node_fts) VALUES('rebuild')");

            Msg.info(this, "FTS table repaired successfully!");
            return true;

        } catch (SQLException e) {
            Msg.error(this, "FTS repair failed: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Check if FTS is healthy by running a simple test query.
     * @return true if FTS is working
     */
    public boolean isFtsHealthy() {
        try (Statement stmt = connection.createStatement()) {
            // Try a simple FTS query
            ResultSet rs = stmt.executeQuery("SELECT 1 FROM node_fts LIMIT 1");
            rs.close();
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * Check if an SQLException indicates FTS table corruption.
     */
    public static boolean isFtsCorruptionError(SQLException e) {
        String message = e.getMessage();
        return message != null && (
                message.contains("SQLITE_CORRUPT_VTAB") ||
                message.contains("vtable constructor failed") ||
                message.contains("node_fts")
        );
    }

    /**
     * Migrate GHChatMessages table - add any missing columns.
     * Uses PRAGMA table_info to check what columns actually exist.
     */
    private void migrateChatMessagesTable() {
        // First check if table exists
        boolean tableExists = false;
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(
                 "SELECT name FROM sqlite_master WHERE type='table' AND name='GHChatMessages'")) {
            tableExists = rs.next();
        } catch (SQLException e) {
            Msg.error(this, "Failed to check if GHChatMessages table exists: " + e.getMessage());
            return;
        }

        if (!tableExists) {
            // Table doesn't exist - let CREATE TABLE IF NOT EXISTS handle it
            return;
        }

        // Table exists - get existing columns
        java.util.Set<String> existingColumns = new java.util.HashSet<>();
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(GHChatMessages)")) {
            while (rs.next()) {
                existingColumns.add(rs.getString("name").toLowerCase());
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get GHChatMessages columns: " + e.getMessage());
            return;
        }

        // Define columns to add with their definitions
        // Note: SQLite ALTER TABLE cannot use non-constant defaults like CURRENT_TIMESTAMP
        // So we add these columns without defaults and handle timestamps in INSERT/UPDATE
        String[][] columnsToAdd = {
            {"program_hash", "TEXT"},
            {"chat_id", "INTEGER"},
            {"session_id", "INTEGER"},  // For backward compatibility with old databases
            {"message_order", "INTEGER"},
            {"sequence_number", "INTEGER"},  // For backward compatibility with old databases
            {"provider_type", "TEXT"},
            {"native_message_data", "TEXT"},
            {"role", "TEXT"},
            {"content_text", "TEXT"},
            {"message_type", "TEXT DEFAULT 'standard'"},
            {"created_at", "TIMESTAMP"},
            {"updated_at", "TIMESTAMP"}
        };

        // Add only missing columns
        for (String[] colDef : columnsToAdd) {
            String colName = colDef[0];
            String colType = colDef[1];
            if (!existingColumns.contains(colName.toLowerCase())) {
                String alterSql = "ALTER TABLE GHChatMessages ADD COLUMN " + colName + " " + colType;
                try (Statement stmt = connection.createStatement()) {
                    stmt.execute(alterSql);
                    Msg.info(this, "Added missing column to GHChatMessages: " + colName);
                } catch (SQLException e) {
                    Msg.error(this, "Failed to add column " + colName + " to GHChatMessages: " + e.getMessage());
                }
            }
        }

        // Migrate data from old 'timestamp' column to 'created_at' if timestamp exists
        if (existingColumns.contains("timestamp")) {
            try (Statement stmt = connection.createStatement()) {
                // Copy timestamp values to created_at for rows where created_at is NULL
                String migrateSql = "UPDATE GHChatMessages SET created_at = timestamp WHERE created_at IS NULL";
                int updated = stmt.executeUpdate(migrateSql);
                if (updated > 0) {
                    Msg.info(this, "Migrated " + updated + " rows from timestamp to created_at in GHChatMessages");
                }
            } catch (SQLException e) {
                Msg.error(this, "Failed to migrate timestamp data: " + e.getMessage());
            }
        }
    }

    public void upsertAnalysis(String programHash, Address functionAddress, String query, String response) {
        String upsertSQL = "INSERT INTO GHAnalysis (program_hash, function_address, query, response) "
                + "VALUES (?, ?, ?, ?) "
                + "ON CONFLICT(program_hash, function_address) "
                + "DO UPDATE SET query = ?, response = ?, timestamp = CURRENT_TIMESTAMP";
        
        try (PreparedStatement pstmt = connection.prepareStatement(upsertSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, functionAddress.toString());
            pstmt.setString(3, query);
            pstmt.setString(4, response);
            pstmt.setString(5, query);
            pstmt.setString(6, response);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to store analysis: " + e.getMessage());
        }
    }

    /**
     * Deletes the analysis entry for the specified program and function
     * 
     * @param programHash The hash of the program
     * @param functionAddress The address of the function
     * @return true if an entry was deleted, false otherwise
     */
    public boolean deleteAnalysis(String programHash, Address functionAddress) {
        String deleteSQL = "DELETE FROM GHAnalysis WHERE program_hash = ? AND function_address = ?";
        
        if (programHash == null || functionAddress == null) {
            Msg.error(this, "Cannot delete analysis: programHash or functionAddress is null");
            return false;
        }
        
        Msg.info(this, "Attempting to delete analysis for " + programHash + " at " + functionAddress.toString());
        
        try (PreparedStatement pstmt = connection.prepareStatement(deleteSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, functionAddress.toString());
            
            int rowsAffected = pstmt.executeUpdate();
            Msg.info(this, "Delete operation affected " + rowsAffected + " rows");
            return rowsAffected > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to delete analysis: " + e.getMessage());
            return false;
        }
    }

    public Analysis getAnalysis(String programHash, Address functionAddress) {
        String selectSQL = "SELECT query, response, timestamp FROM GHAnalysis "
                + "WHERE program_hash = ? AND function_address = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, functionAddress.toString());
            
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new Analysis(
                    rs.getString("query"),
                    rs.getString("response"),
                    rs.getTimestamp("timestamp")
                );
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve analysis: " + e.getMessage());
        }
        return null;
    }

    public void upsertContext(String programHash, String context) {
        if (context == null) {
            // If context is null, delete the entry to revert to default
            deleteContext(programHash);
            return;
        }
        
        String upsertSQL = "INSERT INTO GHContext (program_hash, system_context) "
                + "VALUES (?, ?) "
                + "ON CONFLICT(program_hash) "
                + "DO UPDATE SET system_context = ?, timestamp = CURRENT_TIMESTAMP";
        
        try (PreparedStatement pstmt = connection.prepareStatement(upsertSQL)) {
            pstmt.setString(1, programHash);
            pstmt.setString(2, context);
            pstmt.setString(3, context);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to store context: " + e.getMessage());
        }
    }
    
    public void deleteContext(String programHash) {
        String deleteSQL = "DELETE FROM GHContext WHERE program_hash = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(deleteSQL)) {
            pstmt.setString(1, programHash);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to delete context: " + e.getMessage());
        }
    }

    public String getContext(String programHash) {
        String selectSQL = "SELECT system_context FROM GHContext WHERE program_hash = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getString("system_context");
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve context: " + e.getMessage());
        }
        return null;
    }

    public void upsertReasoningEffort(String programHash, String reasoningEffort) {
        if (reasoningEffort == null || reasoningEffort.equalsIgnoreCase("none")) {
            reasoningEffort = "none";
        }

        // Check if context entry exists
        String selectSQL = "SELECT program_hash FROM GHContext WHERE program_hash = ?";
        boolean exists = false;
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            ResultSet rs = pstmt.executeQuery();
            exists = rs.next();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to check context: " + e.getMessage());
            return;
        }

        if (!exists) {
            // Create entry with default context
            String insertSQL = "INSERT INTO GHContext (program_hash, system_context, reasoning_effort) VALUES (?, '', ?)";
            try (PreparedStatement pstmt = connection.prepareStatement(insertSQL)) {
                pstmt.setString(1, programHash);
                pstmt.setString(2, reasoningEffort);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to insert reasoning effort: " + e.getMessage());
            }
        } else {
            // Update existing entry
            String updateSQL = "UPDATE GHContext SET reasoning_effort = ?, timestamp = CURRENT_TIMESTAMP WHERE program_hash = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(updateSQL)) {
                pstmt.setString(1, reasoningEffort);
                pstmt.setString(2, programHash);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to update reasoning effort: " + e.getMessage());
            }
        }
    }

    public String getReasoningEffort(String programHash) {
        String selectSQL = "SELECT reasoning_effort FROM GHContext WHERE program_hash = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                String effort = rs.getString("reasoning_effort");
                return effort != null ? effort : "none";
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve reasoning effort: " + e.getMessage());
        }
        return "none"; // Default to none if not found
    }

    public void upsertMaxToolCalls(String programHash, int maxToolCalls) {
        // Validate range (must be at least 1)
        if (maxToolCalls < 1) {
            maxToolCalls = 10; // Default value
        }

        // Check if context entry exists
        String selectSQL = "SELECT program_hash FROM GHContext WHERE program_hash = ?";
        boolean exists = false;
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            ResultSet rs = pstmt.executeQuery();
            exists = rs.next();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to check context: " + e.getMessage());
            return;
        }

        if (!exists) {
            // Create entry with default context
            String insertSQL = "INSERT INTO GHContext (program_hash, system_context, max_tool_calls) VALUES (?, '', ?)";
            try (PreparedStatement pstmt = connection.prepareStatement(insertSQL)) {
                pstmt.setString(1, programHash);
                pstmt.setInt(2, maxToolCalls);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to insert max tool calls: " + e.getMessage());
            }
        } else {
            // Update existing entry
            String updateSQL = "UPDATE GHContext SET max_tool_calls = ?, timestamp = CURRENT_TIMESTAMP WHERE program_hash = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(updateSQL)) {
                pstmt.setInt(1, maxToolCalls);
                pstmt.setString(2, programHash);
                pstmt.executeUpdate();
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to update max tool calls: " + e.getMessage());
            }
        }
    }

    public int getMaxToolCalls(String programHash) {
        String selectSQL = "SELECT max_tool_calls FROM GHContext WHERE program_hash = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);

            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                int maxToolCalls = rs.getInt("max_tool_calls");
                // Return default if not set (0) or invalid
                return maxToolCalls > 0 ? maxToolCalls : 10;
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve max tool calls: " + e.getMessage());
        }
        return 10; // Default to 10 if not found
    }

    // Chat History Methods
    
    public void updateChatDescription(int sessionId, String description) {
        String updateSQL = "UPDATE GHChatHistory SET description = ? WHERE id = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(updateSQL)) {
            pstmt.setString(1, description);
            pstmt.setInt(2, sessionId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to update chat description: " + e.getMessage());
        }
    }
    
    public boolean deleteChatSession(int sessionId) {
        String deleteSQL = "DELETE FROM GHChatHistory WHERE id = ?";
        
        try (PreparedStatement pstmt = connection.prepareStatement(deleteSQL)) {
            pstmt.setInt(1, sessionId);
            int rowsAffected = pstmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to delete chat session: " + e.getMessage());
            return false;
        }
    }
    
    public java.util.List<ChatSession> getChatSessions(String programHash) {
        java.util.List<ChatSession> sessions = new java.util.ArrayList<>();
        String selectSQL = "SELECT id, description, last_update FROM GHChatHistory WHERE program_hash = ? ORDER BY last_update DESC";
        
        try (PreparedStatement pstmt = connection.prepareStatement(selectSQL)) {
            pstmt.setString(1, programHash);
            
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                sessions.add(new ChatSession(
                    rs.getInt("id"),
                    rs.getString("description"),
                    rs.getTimestamp("last_update")
                ));
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to retrieve chat sessions: " + e.getMessage());
        }
        return sessions;
    }
    
    // Per-Message Storage Methods

    /**
     * Save a single chat message to the per-message storage.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @param order Message order in conversation
     * @param providerType Provider type (anthropic/openai/ollama/edited)
     * @param nativeData JSON with essential tool info
     * @param role Message role
     * @param content Message content
     * @param messageType Message type (standard/tool_call/tool_response/edited)
     * @return Generated message ID, or -1 on failure
     */
    public int saveMessage(String programHash, int chatId, int order,
                           String providerType, String nativeData,
                           String role, String content, String messageType) {
        // Check if row exists
        String checkSql = "SELECT id FROM GHChatMessages WHERE program_hash = ? AND chat_id = ? AND message_order = ?";
        int existingId = -1;

        try (PreparedStatement checkStmt = connection.prepareStatement(checkSql)) {
            checkStmt.setString(1, programHash);
            checkStmt.setInt(2, chatId);
            checkStmt.setInt(3, order);
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                existingId = rs.getInt("id");
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to check existing message: " + e.getMessage());
            return -1;
        }

        if (existingId > 0) {
            // NEVER UPDATE message_order=0 (the user query) - it must be preserved!
            if (order == 0 && "user".equals(role)) {
                Msg.warn(this, "Attempted to overwrite user query at order=0 - skipping update to preserve original");
                return existingId;
            }

            // Update existing row
            String updateSql = "UPDATE GHChatMessages SET provider_type = ?, native_message_data = ?, "
                    + "role = ?, content_text = ?, message_type = ?, updated_at = CURRENT_TIMESTAMP "
                    + "WHERE id = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
                pstmt.setString(1, providerType);
                pstmt.setString(2, nativeData != null ? nativeData : "{}");
                pstmt.setString(3, role);
                pstmt.setString(4, content);
                pstmt.setString(5, messageType != null ? messageType : "standard");
                pstmt.setInt(6, existingId);
                pstmt.executeUpdate();
                return existingId;
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to update message: " + e.getMessage());
                return -1;
            }
        } else {
            // Insert new row
            // Note: session_id and sequence_number included for backward compatibility with old database schemas
            String insertSql = "INSERT INTO GHChatMessages "
                    + "(program_hash, chat_id, session_id, message_order, sequence_number, provider_type, native_message_data, "
                    + "role, content_text, message_type, created_at, updated_at) "
                    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)";
            try (PreparedStatement pstmt = connection.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, programHash);
                pstmt.setInt(2, chatId);
                pstmt.setInt(3, chatId);  // session_id = chat_id for compatibility
                pstmt.setInt(4, order);
                pstmt.setInt(5, order);   // sequence_number = message_order for compatibility
                pstmt.setString(6, providerType);
                pstmt.setString(7, nativeData != null ? nativeData : "{}");
                pstmt.setString(8, role);
                pstmt.setString(9, content);
                pstmt.setString(10, messageType != null ? messageType : "standard");
                pstmt.executeUpdate();

                ResultSet rs = pstmt.getGeneratedKeys();
                if (rs.next()) {
                    return rs.getInt(1);
                }
            } catch (SQLException e) {
                Msg.showError(this, null, "Database Error", "Failed to insert message: " + e.getMessage());
            }
        }
        return -1;
    }

    /**
     * Get all messages for a chat session.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return List of PersistedChatMessage objects, ordered by message_order
     */
    public List<PersistedChatMessage> getMessages(String programHash, int chatId) {
        List<PersistedChatMessage> messages = new ArrayList<>();
        String sql = "SELECT id, role, content_text, message_order, "
                + "created_at, "
                + "provider_type, native_message_data, message_type "
                + "FROM GHChatMessages WHERE program_hash = ? AND chat_id = ? "
                + "ORDER BY message_order ASC";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                PersistedChatMessage msg = new PersistedChatMessage(
                        rs.getInt("id"),
                        rs.getString("role"),
                        rs.getString("content_text"),
                        rs.getTimestamp("created_at"),
                        rs.getInt("message_order")
                );
                msg.setProviderType(rs.getString("provider_type"));
                msg.setNativeMessageData(rs.getString("native_message_data"));
                msg.setMessageType(rs.getString("message_type"));
                messages.add(msg);
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error",
                    "Failed to retrieve messages: " + e.getMessage());
        }
        return messages;
    }

    /**
     * Delete all messages for a chat session.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return Number of messages deleted
     */
    public int deleteMessages(String programHash, int chatId) {
        String sql = "DELETE FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);
            return pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error",
                    "Failed to delete messages: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Check if a chat session has per-message storage (has been migrated).
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return true if the session has per-message storage
     */
    public boolean hasPerMessageStorage(String programHash, int chatId) {
        String sql = "SELECT COUNT(*) FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            // Table may not exist yet in older databases
            Msg.warn(this, "Error checking per-message storage: " + e.getMessage());
        }
        return false;
    }

    /**
     * Get the count of messages in a chat session.
     *
     * @param programHash Program hash
     * @param chatId Chat session ID
     * @return Number of messages
     */
    public int getMessageCount(String programHash, int chatId) {
        String sql = "SELECT COUNT(*) FROM GHChatMessages WHERE program_hash = ? AND chat_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, chatId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error getting message count: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Get the database connection for use with new chat persistence components.
     * @return The database connection
     */
    public Connection getConnection() {
        return connection;
    }

    public String getDatabasePath() {
        return databasePath;
    }

    // ========================================
    // Graph-RAG Knowledge Graph Methods
    // ========================================

    /**
     * Get or create a BinaryKnowledgeGraph for a program.
     * The graph is cached per program hash for efficiency.
     *
     * @param programHash The program hash identifying the binary
     * @return BinaryKnowledgeGraph instance for the program
     */
    public BinaryKnowledgeGraph getKnowledgeGraph(String programHash) {
        return graphCache.computeIfAbsent(programHash,
                hash -> new BinaryKnowledgeGraph(connection, hash, this));
    }

    /**
     * Check if a knowledge graph exists for a program (has any nodes).
     *
     * @param programHash The program hash
     * @return true if the graph has been populated
     */
    public boolean hasKnowledgeGraph(String programHash) {
        String sql = "SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, programHash);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error checking knowledge graph: " + e.getMessage());
        }
        return false;
    }

    /**
     * Get statistics about a program's knowledge graph.
     *
     * @param programHash The program hash
     * @return Map with "nodes" and "edges" counts
     */
    public Map<String, Integer> getKnowledgeGraphStats(String programHash) {
        Map<String, Integer> stats = new java.util.HashMap<>();
        stats.put("nodes", 0);
        stats.put("edges", 0);
        stats.put("stale_nodes", 0);

        String nodesSql = "SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ?";
        // Count nodes that need summarization: stale OR missing summary
        String staleSql = "SELECT COUNT(*) FROM graph_nodes WHERE binary_id = ? " +
                "AND (is_stale = 1 OR llm_summary IS NULL OR llm_summary = '')";
        String edgesSql = "SELECT COUNT(*) FROM graph_edges e "
                + "INNER JOIN graph_nodes n ON e.source_id = n.id WHERE n.binary_id = ?";

        try (PreparedStatement nodesStmt = connection.prepareStatement(nodesSql);
             PreparedStatement staleStmt = connection.prepareStatement(staleSql);
             PreparedStatement edgesStmt = connection.prepareStatement(edgesSql)) {

            nodesStmt.setString(1, programHash);
            staleStmt.setString(1, programHash);
            edgesStmt.setString(1, programHash);

            ResultSet rs1 = nodesStmt.executeQuery();
            if (rs1.next()) {
                stats.put("nodes", rs1.getInt(1));
            }

            ResultSet rs2 = staleStmt.executeQuery();
            if (rs2.next()) {
                stats.put("stale_nodes", rs2.getInt(1));
            }

            ResultSet rs3 = edgesStmt.executeQuery();
            if (rs3.next()) {
                stats.put("edges", rs3.getInt(1));
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error getting knowledge graph stats: " + e.getMessage());
        }
        return stats;
    }

    /**
     * Get the last updated timestamp (epoch ms) for a program's knowledge graph.
     *
     * @param programHash The program hash
     * @return Epoch milliseconds for most recent update, or null if unknown
     */
    public Long getKnowledgeGraphLastIndexed(String programHash) {
        String sql = "SELECT MAX(updated_at) FROM graph_nodes WHERE binary_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, programHash);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                long value = rs.getLong(1);
                if (!rs.wasNull() && value > 0) {
                    return value;
                }
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error getting knowledge graph last indexed time: " + e.getMessage());
        }
        return null;
    }

    /**
     * Clear the cached BinaryKnowledgeGraph for a program.
     * Call this when switching programs or when the graph needs to be reloaded.
     *
     * @param programHash The program hash
     */
    public void invalidateKnowledgeGraphCache(String programHash) {
        graphCache.remove(programHash);
    }

    /**
     * Clear all cached BinaryKnowledgeGraph instances.
     */
    public void invalidateAllKnowledgeGraphCaches() {
        graphCache.clear();
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            Msg.showError(this, null, "Database Error", "Failed to close Analysis database connection: " + e.getMessage());
        }
    }

    public static class Analysis {
        private final String query;
        private final String response;
        private final Timestamp timestamp;

        public Analysis(String query, String response, Timestamp timestamp) {
            this.query = query;
            this.response = response;
            this.timestamp = timestamp;
        }

        public String getQuery() { return query; }
        public String getResponse() { return response; }
        public Timestamp getTimestamp() { return timestamp; }
    }
    
    public static class ChatSession {
        private final int id;
        private final String description;
        private final Timestamp lastUpdate;
        private final String chatType;

        public ChatSession(int id, String description, Timestamp lastUpdate) {
            this(id, description, lastUpdate, "chat");
        }

        public ChatSession(int id, String description, Timestamp lastUpdate, String chatType) {
            this.id = id;
            this.description = description;
            this.lastUpdate = lastUpdate;
            this.chatType = chatType != null ? chatType : "chat";
        }

        public int getId() { return id; }
        public String getDescription() { return description; }
        public Timestamp getLastUpdate() { return lastUpdate; }
        public String getChatType() { return chatType; }
    }

    /**
     * Data class for line explanations.
     */
    public static class LineExplanation {
        private final int id;
        private final String binaryId;
        private final long functionAddress;
        private final long lineAddress;
        private final String viewType;  // 'DECOMPILER' or 'DISASSEMBLY'
        private final String lineContent;
        private final String contextBefore;
        private final String contextAfter;
        private final String explanation;
        private final long createdAt;
        private final long updatedAt;

        public LineExplanation(int id, String binaryId, long functionAddress, long lineAddress,
                               String viewType, String lineContent, String contextBefore,
                               String contextAfter, String explanation, long createdAt, long updatedAt) {
            this.id = id;
            this.binaryId = binaryId;
            this.functionAddress = functionAddress;
            this.lineAddress = lineAddress;
            this.viewType = viewType;
            this.lineContent = lineContent;
            this.contextBefore = contextBefore;
            this.contextAfter = contextAfter;
            this.explanation = explanation;
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
        }

        public int getId() { return id; }
        public String getBinaryId() { return binaryId; }
        public long getFunctionAddress() { return functionAddress; }
        public long getLineAddress() { return lineAddress; }
        public String getViewType() { return viewType; }
        public String getLineContent() { return lineContent; }
        public String getContextBefore() { return contextBefore; }
        public String getContextAfter() { return contextAfter; }
        public String getExplanation() { return explanation; }
        public long getCreatedAt() { return createdAt; }
        public long getUpdatedAt() { return updatedAt; }
    }

    // ========================================
    // Line Explanation Methods
    // ========================================

    /**
     * Get a cached line explanation.
     *
     * @param binaryId The binary hash
     * @param lineAddress The address of the line
     * @param viewType 'DECOMPILER' or 'DISASSEMBLY'
     * @return LineExplanation if found, null otherwise
     */
    public LineExplanation getLineExplanation(String binaryId, long lineAddress, String viewType) {
        String sql = "SELECT id, binary_id, function_address, line_address, view_type, " +
                     "line_content, context_before, context_after, explanation, created_at, updated_at " +
                     "FROM line_explanations WHERE binary_id = ? AND line_address = ? AND view_type = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setLong(2, lineAddress);
            stmt.setString(3, viewType);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new LineExplanation(
                    rs.getInt("id"),
                    rs.getString("binary_id"),
                    rs.getLong("function_address"),
                    rs.getLong("line_address"),
                    rs.getString("view_type"),
                    rs.getString("line_content"),
                    rs.getString("context_before"),
                    rs.getString("context_after"),
                    rs.getString("explanation"),
                    rs.getLong("created_at"),
                    rs.getLong("updated_at")
                );
            }
        } catch (SQLException e) {
            Msg.warn(this, "Error getting line explanation: " + e.getMessage());
        }
        return null;
    }

    /**
     * Insert or update a line explanation.
     *
     * @param binaryId The binary hash
     * @param functionAddress The function containing this line
     * @param lineAddress The address of the line
     * @param viewType 'DECOMPILER' or 'DISASSEMBLY'
     * @param lineContent The actual code/instruction content
     * @param contextBefore Context lines before
     * @param contextAfter Context lines after
     * @param explanation The LLM-generated explanation
     */
    public void upsertLineExplanation(String binaryId, long functionAddress, long lineAddress,
                                       String viewType, String lineContent, String contextBefore,
                                       String contextAfter, String explanation) {
        String sql = "INSERT INTO line_explanations " +
                     "(binary_id, function_address, line_address, view_type, line_content, " +
                     "context_before, context_after, explanation, created_at, updated_at) " +
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
                     "ON CONFLICT(binary_id, line_address, view_type) DO UPDATE SET " +
                     "function_address = excluded.function_address, " +
                     "line_content = excluded.line_content, " +
                     "context_before = excluded.context_before, " +
                     "context_after = excluded.context_after, " +
                     "explanation = excluded.explanation, " +
                     "updated_at = excluded.updated_at";

        long now = System.currentTimeMillis();
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setLong(2, functionAddress);
            stmt.setLong(3, lineAddress);
            stmt.setString(4, viewType);
            stmt.setString(5, lineContent);
            stmt.setString(6, contextBefore);
            stmt.setString(7, contextAfter);
            stmt.setString(8, explanation);
            stmt.setLong(9, now);
            stmt.setLong(10, now);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to upsert line explanation: " + e.getMessage(), e);
        }
    }

    /**
     * Clear all line explanations for a function.
     * Useful when function is re-analyzed or renamed.
     *
     * @param binaryId The binary hash
     * @param functionAddress The function address
     * @return Number of deleted rows
     */
    public int clearLineExplanationsForFunction(String binaryId, long functionAddress) {
        String sql = "DELETE FROM line_explanations WHERE binary_id = ? AND function_address = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setLong(2, functionAddress);
            return stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to clear line explanations: " + e.getMessage(), e);
        }
        return 0;
    }

    /**
     * Clear a specific line explanation.
     *
     * @param binaryId The binary hash
     * @param lineAddress The line address
     * @param viewType 'DECOMPILER' or 'DISASSEMBLY'
     * @return true if deleted
     */
    public boolean clearLineExplanation(String binaryId, long lineAddress, String viewType) {
        String sql = "DELETE FROM line_explanations WHERE binary_id = ? AND line_address = ? AND view_type = ?";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, binaryId);
            stmt.setLong(2, lineAddress);
            stmt.setString(3, viewType);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to clear line explanation: " + e.getMessage(), e);
        }
        return false;
    }

    // ReAct Message Storage Methods

    /**
     * Save a ReAct message to GHReActMessages table.
     *
     * @param programHash Program hash
     * @param sessionId Chat session ID
     * @param messageOrder Message order in conversation
     * @param phase Current phase (planning/investigation/reflection/synthesis)
     * @param iterationNumber Iteration number (null for planning/synthesis)
     * @param message ChatMessage to save
     * @return Generated message ID, or -1 on failure
     */
    public int saveReActMessage(String programHash, int sessionId, int messageOrder,
                                String phase, Integer iterationNumber,
                                ghidrassist.apiprovider.ChatMessage message) {
        String sql = "INSERT OR REPLACE INTO GHReActMessages " +
                "(program_hash, session_id, message_order, phase, iteration_number, role, content_text, native_message_data) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            pstmt.setInt(3, messageOrder);
            pstmt.setString(4, phase);
            if (iterationNumber != null) {
                pstmt.setInt(5, iterationNumber);
            } else {
                pstmt.setNull(5, java.sql.Types.INTEGER);
            }
            pstmt.setString(6, message.getRole());
            pstmt.setString(7, message.getContent());

            // Store native message data as JSON (tool_calls, tool_call_id, etc.)
            String nativeData = serializeMessageMetadata(message);
            pstmt.setString(8, nativeData);

            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to save ReAct message: " + e.getMessage(), e);
        }
        return -1;
    }

    public boolean updateReActMessageContent(String programHash, int sessionId, int messageOrder,
                                             String newContent) {
        String sql = "UPDATE GHReActMessages SET content_text = ? " +
                "WHERE program_hash = ? AND session_id = ? AND message_order = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, newContent);
            pstmt.setString(2, programHash);
            pstmt.setInt(3, sessionId);
            pstmt.setInt(4, messageOrder);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            Msg.error(this, "Failed to update ReAct message content: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Save a ReAct iteration chunk to GHReActIterationChunks table.
     *
     * @param programHash Program hash
     * @param sessionId Chat session ID
     * @param iterationNumber Iteration number
     * @param summary Iteration summary from LLM
     * @param messageStartIndex Start index in message list
     * @param messageEndIndex End index in message list
     * @return Generated chunk ID, or -1 on failure
     */
    public int saveReActIterationChunk(String programHash, int sessionId, int iterationNumber,
                                       String summary, int messageStartIndex, int messageEndIndex) {
        String sql = "INSERT OR REPLACE INTO GHReActIterationChunks " +
                "(program_hash, session_id, iteration_number, iteration_summary, message_start_index, message_end_index) " +
                "VALUES (?, ?, ?, ?, ?, ?)";

        try (PreparedStatement pstmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            pstmt.setInt(3, iterationNumber);
            pstmt.setString(4, summary);
            pstmt.setInt(5, messageStartIndex);
            pstmt.setInt(6, messageEndIndex);

            pstmt.executeUpdate();

            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to save ReAct iteration chunk: " + e.getMessage(), e);
        }
        return -1;
    }

    /**
     * Serialize ChatMessage metadata to JSON for storage.
     */
    private String serializeMessageMetadata(ghidrassist.apiprovider.ChatMessage message) {
        com.google.gson.JsonObject json = new com.google.gson.JsonObject();

        if (message.getToolCalls() != null) {
            json.add("tool_calls", message.getToolCalls());
        }
        if (message.getToolCallId() != null) {
            json.addProperty("tool_call_id", message.getToolCallId());
        }
        if (message.getThinkingContent() != null) {
            json.addProperty("thinking_content", message.getThinkingContent());
        }
        if (message.getThinkingSignature() != null) {
            json.addProperty("thinking_signature", message.getThinkingSignature());
        }

        return json.toString();
    }

    /**
     * Get ReAct messages for a session.
     *
     * @param programHash Program hash
     * @param sessionId Session ID
     * @return List of messages ordered by message_order
     */
    public List<ghidrassist.apiprovider.ChatMessage> getReActMessages(String programHash, int sessionId) {
        List<ghidrassist.apiprovider.ChatMessage> messages = new ArrayList<>();
        String sql = "SELECT role, content_text, native_message_data FROM GHReActMessages " +
                "WHERE program_hash = ? AND session_id = ? ORDER BY message_order ASC";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);

            ResultSet rs = pstmt.executeQuery();
            com.google.gson.Gson gson = new com.google.gson.Gson();

            while (rs.next()) {
                String role = rs.getString("role");
                String content = rs.getString("content_text");
                String nativeData = rs.getString("native_message_data");

                ghidrassist.apiprovider.ChatMessage message = new ghidrassist.apiprovider.ChatMessage(role, content);

                // Restore metadata from JSON
                if (nativeData != null && !nativeData.isEmpty()) {
                    try {
                        com.google.gson.JsonObject json = gson.fromJson(nativeData, com.google.gson.JsonObject.class);

                        if (json.has("tool_calls")) {
                            message.setToolCalls(json.get("tool_calls").getAsJsonArray());
                        }
                        if (json.has("tool_call_id")) {
                            message.setToolCallId(json.get("tool_call_id").getAsString());
                        }
                        if (json.has("thinking_content")) {
                            message.setThinkingContent(json.get("thinking_content").getAsString());
                        }
                        if (json.has("thinking_signature")) {
                            message.setThinkingSignature(json.get("thinking_signature").getAsString());
                        }
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to parse message metadata: " + e.getMessage());
                    }
                }

                messages.add(message);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to retrieve ReAct messages: " + e.getMessage(), e);
        }

        return messages;
    }

    /**
     * Get ReAct iteration chunks for a session.
     *
     * @param programHash Program hash
     * @param sessionId Session ID
     * @return List of iteration summaries ordered by iteration number
     */
    public List<String> getReActIterationSummaries(String programHash, int sessionId) {
        List<String> summaries = new ArrayList<>();
        String sql = "SELECT iteration_summary FROM GHReActIterationChunks " +
                "WHERE program_hash = ? AND session_id = ? ORDER BY iteration_number ASC";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);

            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String summary = rs.getString("iteration_summary");
                if (summary != null) {
                    summaries.add(summary);
                }
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to retrieve ReAct iteration summaries: " + e.getMessage(), e);
        }

        return summaries;
    }

    /**
     * Check if a session has ReAct messages.
     *
     * @param sessionId Session ID
     * @return true if session has ReAct messages
     */
    public boolean isReActSession(int sessionId) {
        String sql = "SELECT COUNT(*) FROM GHReActMessages WHERE session_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, sessionId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to check if ReAct session: " + e.getMessage(), e);
        }

        return false;
    }

    /**
     * Record that a symbol was renamed by an LLM suggestion.
     */
    public void recordLlmRename(String binaryId, long address, String symbolType, String newName) {
        String sql = "INSERT OR REPLACE INTO llm_renames (binary_id, address, symbol_type, new_name, created_at) "
                + "VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, binaryId);
            pstmt.setLong(2, address);
            pstmt.setString(3, symbolType);
            pstmt.setString(4, newName);
            pstmt.setLong(5, System.currentTimeMillis());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            Msg.error(this, "Failed to record LLM rename: " + e.getMessage(), e);
        }
    }

    /**
     * Check if a symbol at the given address was renamed by an LLM.
     */
    public boolean isLlmRenamed(String binaryId, long address, String symbolType) {
        String sql = "SELECT COUNT(*) FROM llm_renames WHERE binary_id = ? AND address = ? AND symbol_type = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, binaryId);
            pstmt.setLong(2, address);
            pstmt.setString(3, symbolType);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to check LLM rename: " + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Get the maximum iteration number for a ReAct session.
     * Used to continue iteration numbering across multiple ReAct runs in same session.
     *
     * @param programHash Program hash
     * @param sessionId Session ID
     * @return Maximum iteration number, or 0 if no iterations exist
     */
    public int getMaxReActIteration(String programHash, int sessionId) {
        String sql = "SELECT COALESCE(MAX(iteration_number), 0) FROM GHReActIterationChunks " +
                "WHERE program_hash = ? AND session_id = ?";

        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, programHash);
            pstmt.setInt(2, sessionId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to get max ReAct iteration: " + e.getMessage(), e);
        }

        return 0;
    }
}
