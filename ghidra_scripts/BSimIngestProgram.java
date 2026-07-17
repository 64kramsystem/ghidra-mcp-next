// Ingest ALL functions from the current program into a caller-configured BSim database.
// This generates BSim feature vectors (LSH signatures) for every function and
// inserts them into the database's exetable/desctable. One-time per binary.
//
// Script args: [0] = required BSim URL supported by the installed Ghidra client
//
// Usage from MCP: run_script("BSimIngestProgram", args=["file:/absolute/path/to/local-bsim"])
// Usage from Ghidra Script Manager: will prompt for URL if no args provided
//
// IMPORTANT: The program must be saved before ingestion. BSim needs a stable
// MD5 hash and project path to track the executable.
//@category BSim
//@keybinding
//@menupath
//@toolbar

import java.net.URL;
import java.util.Iterator;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryExeCount;
import ghidra.features.bsim.query.protocol.ResponseExe;
import ghidra.features.bsim.query.protocol.ResponseInsert;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class BSimIngestProgram extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"status\": \"error\", \"error\": \"No program is open\"}");
            return;
        }

        String[] args = getScriptArgs();
        String bsimUrl;
        try {
            bsimUrl = requireBsimUrl(args, 0, "BSim Ingest Program");
        } catch (IllegalArgumentException e) {
            println("{\"status\": \"error\", \"error\": \"" + escapeJson(e.getMessage()) + "\"}");
            return;
        }

        String programName = currentProgram.getName();
        String md5 = currentProgram.getExecutableMD5();

        println("{");
        println("  \"operation\": \"bsim_ingest_program\",");
        println("  \"program\": \"" + escapeJson(programName) + "\",");
        println("  \"md5\": \"" + escapeJson(md5 != null ? md5 : "") + "\",");
        println("  \"url\": \"" + escapeJson(bsimUrl) + "\",");

        if (md5 == null || md5.length() < 10) {
            println("  \"status\": \"error\",");
            println("  \"error\": \"Program has no valid MD5 hash. Ensure it has been analyzed.\"");
            println("}");
            return;
        }

        FunctionDatabase database = null;
        GenSignatures gensig = null;
        try {
            URL url = BSimClientFactory.deriveBSimURL(bsimUrl);
            database = BSimClientFactory.buildClient(url, false);

            if (!database.initialize()) {
                String errMsg = database.getLastError() != null
                    ? database.getLastError().message : "Unknown error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"Connection failed: " + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            DatabaseInformation dbInfo = database.getInfo();
            LSHVectorFactory vectorFactory = database.getLSHVectorFactory();

            // Initialize signature generator
            gensig = new GenSignatures(dbInfo.trackcallgraph);
            gensig.setVectorFactory(vectorFactory);
            gensig.addExecutableCategories(dbInfo.execats);
            gensig.addFunctionTags(dbInfo.functionTags);
            gensig.addDateColumnName(dbInfo.dateColumnName);

            // Resolve the program's repository path for BSim tracking
            DomainFile dFile = currentProgram.getDomainFile();
            URL fileURL = dFile.getLocalProjectURL(null);

            String repo = null;
            String path = null;
            if (fileURL != null) {
                path = GhidraURL.getProjectPathname(fileURL);
                // BSim adds the program name to the path, so strip it
                int lastSlash = path.lastIndexOf('/');
                path = lastSlash == 0 ? "/" : path.substring(0, lastSlash);
                URL normalizedProjectURL = GhidraURL.getProjectURL(fileURL);
                repo = normalizedProjectURL.toExternalForm();
            } else {
                // Fallback: use project name as repo
                repo = "ghidra://localhost/" + state.getProject().getName();
                path = GenSignatures.getPathFromDomainFile(currentProgram);
            }

            println("  \"repo\": \"" + escapeJson(repo) + "\",");
            println("  \"path\": \"" + escapeJson(path) + "\",");

            // Open program in GenSignatures and scan all functions
            gensig.openProgram(currentProgram, null, null, null, repo, path);

            FunctionManager fman = currentProgram.getFunctionManager();
            int funcCount = fman.getFunctionCount();
            Iterator<Function> iter = fman.getFunctions(true);

            println("  \"total_functions\": " + funcCount + ",");

            gensig.scanFunctions(iter, funcCount, monitor);

            DescriptionManager manager = gensig.getDescriptionManager();
            int signedFunctions = manager.numFunctions();

            println("  \"signed_functions\": " + signedFunctions + ",");

            if (signedFunctions == 0) {
                println("  \"status\": \"skipped\",");
                println("  \"error\": \"No functions with bodies found to ingest\"");
                println("}");
                return;
            }

            // De-duplicate callgraph entries to avoid SQL constraint violations
            manager.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());

            // Insert into BSim database
            InsertRequest insertReq = new InsertRequest();
            insertReq.manage = manager;
            ResponseInsert insertResponse = insertReq.execute(database);

            if (insertResponse == null) {
                FunctionDatabase.BSimError lastError = database.getLastError();
                if (lastError != null &&
                    (lastError.category == ErrorCategory.Format ||
                     lastError.category == ErrorCategory.Nonfatal)) {
                    println("  \"status\": \"skipped\",");
                    println("  \"error\": \"" + escapeJson(lastError.message) + "\"");
                    println("}");
                    return;
                }
                String errMsg = lastError != null ? lastError.message : "Unknown insert error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"" + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            // Get updated executable count
            QueryExeCount exeCount = new QueryExeCount();
            ResponseExe countResponse = exeCount.execute(database);
            int totalExes = countResponse != null ? countResponse.recordCount : -1;

            println("  \"inserted_executables\": " + insertResponse.numexe + ",");
            println("  \"inserted_functions\": " + insertResponse.numfunc + ",");
            println("  \"database_name\": \"" + escapeJson(dbInfo.databasename) + "\",");
            println("  \"total_executables_in_db\": " + totalExes + ",");
            println("  \"status\": \"success\"");
            println("}");

        } catch (Exception e) {
            println("  \"status\": \"error\",");
            println("  \"error\": \"" + escapeJson(e.getClass().getSimpleName() + ": " + e.getMessage()) + "\"");
            println("}");
        } finally {
            if (gensig != null) {
                gensig.dispose();
            }
            if (database != null) {
                try {
                    database.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private String requireBsimUrl(String[] args, int index, String dialogTitle)
            throws Exception {
        if (args != null && args.length > index && args[index] != null
                && !args[index].isBlank()) {
            return args[index].trim();
        }
        if (!isRunningHeadless()) {
            String value = askString(dialogTitle, "Enter BSim database URL:");
            if (value != null && !value.isBlank()) return value.trim();
        }
        throw new IllegalArgumentException("BSim URL is required");
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
