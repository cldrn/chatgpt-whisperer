package chatgptwhisperer;

import com.theokanning.openai.completion.chat.*;
import com.theokanning.openai.service.OpenAiService;
import docking.Tool;
import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

import javax.swing.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "AI-Assisted Reverse Engineering with ChatGPT",
    description = "Enhances Ghidra with ChatGPT-powered features for analyzing, summarizing, documenting, and identifying vulnerabilities in binary functions. Includes support for decompilation analysis, xref tracing, function signature suggestions, and batch processing.",
    servicesRequired = {ConsoleService.class, CodeViewerService.class}
)
public class ChatGPTWhispererPlugin extends ProgramPlugin {

    private static final int OPENAI_TIMEOUT = 120;

    private static final String IDENTIFY_PROMPT =
        "Analyze the following function and explain its behavior in technical detail. Describe any recognizable algorithms, protocol interactions, or hardware interfaces. If assumptions are made, clearly state them and justify based on available code.\n\n%s";

    private static final String VULNERABILITY_PROMPT =
        "Perform a technical review of this function and describe any potential vulnerabilities, unsafe operations, or misuses of memory. Use secure coding principles to guide your analysis.\n\n%s";

    private static final String SIGNATURE_PROMPT =
        "Analyze this function and propose a likely function signature, including return type, parameter names/types, and a better function name if possible. Use standard C notation in your response.\n\n%s";

    private ConsoleService cs;
    private CodeViewerService cvs;
    private ChatGPTWhispererComponent uiComponent;

    private String apiToken;
    private String openAiModel = "gpt-4o";
    private double temperature = 0.7;
    private boolean appendToComment = false;

    private String assistantPersona =
        "You are an expert reverse engineering assistant trained in analyzing low-level code, including firmware, embedded systems, and decompiled binaries. Your role is to explain complex logic, uncover vulnerabilities, and suggest improvements based on secure coding practices. You understand ARM, C, memory layout, and common patterns found in real-world software. When analyzing code, clearly explain behavior, and identify risks.";

    public ChatGPTWhispererPlugin(PluginTool tool) {
        super(tool);
        String pluginName = getName();
        uiComponent = new ChatGPTWhispererComponent(this, pluginName);
        uiComponent.setHelpLocation(new HelpLocation(this.getClass().getPackage().getName(), "HelpAnchor"));
    }

    @Override
    public void init() {
        super.init();
        cs = tool.getService(ConsoleService.class);
        cvs = tool.getService(CodeViewerService.class);
        apiToken = System.getenv("OPENAI_TOKEN");
        if (apiToken != null) ok("Loaded OpenAI Token: " + censorToken(apiToken));
        ok("Default model: " + openAiModel);
    }

    public void identifyFunction() {
        runSingleFunctionAnalysis(IDENTIFY_PROMPT, "Identify Function");
    }

    public void findVulnerabilities() {
        runSingleFunctionAnalysis(VULNERABILITY_PROMPT, "Vulnerability Analysis");
    }

    public void askCustomQuestion() {
        var context = decompileCurrentFunc();
        if (context == null) return;

        String question = uiComponent.askForQuestion();
        if (question == null || question.isBlank()) return;

        log("Asking custom question...\n\n");
        tool.setStatusInfo("ChatGPTWhisperer: Sending custom question to ChatGPT...");
        String response = askChatGPT(question + "\n\n" + context.decompiledFunc);
        tool.setStatusInfo("ChatGPTWhisperer: Done.");

        if (response != null) {
            log("Q: " + question + "\n\n\n\nA: " + response);
        }
    }

    public void explainFunctionWithXrefs() {
        var context = decompileCurrentFunc();
        if (context == null) return;

        List<String> xrefSummaries = getXrefSummaries(context);

        String xrefPrompt = String.format(
            "The following function is cross-referenced in these contexts:\n%s\n\nExplain how those calling functions might use or affect this function:\n\n%s",
            String.join("\n", xrefSummaries),
            context.decompiledFunc
        );

        log("Analyzing XREFs..." + String.join("\n", xrefSummaries));
        tool.setStatusInfo("ChatGPTWhisperer: Querying ChatGPT with xref context...");
        String response = askChatGPT(xrefPrompt);
        tool.setStatusInfo("ChatGPTWhisperer: Done.");

        if (response != null) {
            log(response);
            maybeAppendComment(context.prog, context.func, response, "[ChatGPTWhisperer] Xrefs Analysis:");
        }
    }

    public void suggestFunctionSignature() {
        runSingleFunctionAnalysis(SIGNATURE_PROMPT, "Signature Suggestion");
    }

    public void identifyAllFunctions() {
        runBatchFunctionAnalysis(IDENTIFY_PROMPT, "[ChatGPTWhisperer] Summary:", "identify");
    }

    public void findVulnerabilitiesInAllFunctions() {
        runBatchFunctionAnalysis(VULNERABILITY_PROMPT, "[ChatGPTWhisperer] Vulnerability Analysis:", "vulnerability analysis");
    }

    // === Core Utilities ===

    private void runSingleFunctionAnalysis(String promptTemplate, String label) {
        var context = decompileCurrentFunc();
        if (context == null) return;

        log("Running analysis: " + label + "...\n\n");
        tool.setStatusInfo("ChatGPTWhisperer: Querying ChatGPT for " + label + "...");
        String response = askChatGPT(String.format(promptTemplate, context.decompiledFunc));
        tool.setStatusInfo("ChatGPTWhisperer: Done.");

        if (response != null) {
            log(response);
            maybeAppendComment(context.prog, context.func, response, "[ChatGPTWhisperer] " + label + ":");
        }
    }

    private void runBatchFunctionAnalysis(String promptTemplate, String commentHeader, String operationLabel) {
        Program prog = currentProgram;
        if (prog == null) {
            error("No program loaded.");
            return;
        }

        List<Function> functions = new ArrayList<>();
        prog.getFunctionManager().getFunctions(true).forEachRemaining(functions::add);

        String filter = askForFunctionFilter();
        if (filter != null && !filter.isBlank()) {
            functions.removeIf(f -> !f.getName().toLowerCase().contains(filter.toLowerCase()));
        }

        if (functions.isEmpty()) {
            error("No functions matched the filter.");
            return;
        }

        if (JOptionPane.showConfirmDialog(null,
            "This will send " + functions.size() + " GPT requests. Continue?",
            "Confirm Batch " + operationLabel, JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
            ok("Batch operation cancelled.");
            return;
        }

        tool.setStatusInfo("ChatGPTWhisperer: Starting batch " + operationLabel + "...");
        for (int i = 0; i < functions.size(); i++) {
            Function func = functions.get(i);
            tool.setStatusInfo("ChatGPT: " + operationLabel + " " + (i + 1) + "/" + functions.size() + ": " + func.getName());

            try {
                FlatProgramAPI api = new FlatProgramAPI(prog);
                FlatDecompilerAPI decompiler = new FlatDecompilerAPI(api);
                String decompiled = decompiler.decompile(func);
                String response = askChatGPT(String.format(promptTemplate, decompiled));
                if (response != null) {
                    log("[" + func.getName() + "]\n" + response);
                    maybeAppendComment(prog, func, response, commentHeader);
                }
            } catch (Exception e) {
                error("Failed to process function " + func.getName() + ": " + e.getMessage());
            }
        }

        tool.setStatusInfo("ChatGPTWhisperer: Batch " + operationLabel + " complete.");
        ok("Batch " + operationLabel + " complete.");
    }

    private record FunctionContext(Program prog, Function func, String decompiledFunc) {}

    private FunctionContext decompileCurrentFunc() {
        ProgramLocation progLoc = cvs.getCurrentLocation();
        if (progLoc == null) return null;

        Program prog = progLoc.getProgram();
        FlatProgramAPI api = new FlatProgramAPI(prog);
        FlatDecompilerAPI decompiler = new FlatDecompilerAPI(api);
        Function func = api.getFunctionContaining(progLoc.getAddress());
        if (func == null) {
            error("No function selected.");
            return null;
        }

        try {
            String decompiled = decompiler.decompile(func);
            return new FunctionContext(prog, func, decompiled);
        } catch (Exception e) {
            error("Decompilation failed: " + e.getMessage());
            return null;
        }
    }

    private List<String> getXrefSummaries(FunctionContext context) {
        ReferenceIterator refs = context.prog.getReferenceManager().getReferencesTo(context.func.getEntryPoint());
        List<String> callers = new ArrayList<>();
        for (Reference ref : refs) {
            Function caller = context.prog.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null && !callers.contains(caller.getName())) {
                callers.add("- Called from: " + caller.getName());
            }
        }
        return callers;
    }

    private void maybeAppendComment(Program prog, Function func, String comment, String header) {
        if (appendToComment || confirm("Append ChatGPT response to function comment?")) {
            int tx = prog.startTransaction("Add ChatGPT Comment");
            String prev = func.getComment();
            func.setComment((prev == null ? "" : prev + "\n\n") + header + "\n" + comment + "\n\n");
            prog.endTransaction(tx, true);
        }
    }

    private String askChatGPT(String prompt) {
        if (!checkOpenAIToken()) return null;

        OpenAiService service = new OpenAiService(apiToken, Duration.ofSeconds(OPENAI_TIMEOUT));
        ChatCompletionRequest request = ChatCompletionRequest.builder()
            .model(openAiModel)
            .temperature(temperature)
            .messages(Arrays.asList(
                new ChatMessage(ChatMessageRole.SYSTEM.value(), assistantPersona),
                new ChatMessage(ChatMessageRole.USER.value(), prompt)
            ))
            .build();

        try {
            return service.createChatCompletion(request).getChoices().stream()
                .map(c -> c.getMessage().getContent())
                .reduce("", String::concat);
        } catch (Exception e) {
            error("OpenAI Error: " + e.getMessage());
            return null;
        }
    }

    private boolean checkOpenAIToken() {
        return apiToken != null || setToken(uiComponent.askForOpenAIToken());
    }

    private boolean confirm(String message) {
        return JOptionPane.showConfirmDialog(null, message, "ChatGPTWhisperer", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION;
    }

    public String askForFunctionFilter() {
        return JOptionPane.showInputDialog(
            null,
            "Optional: enter a function name filter substring (case-insensitive).\nLeave empty to analyze all functions.",
            "Function Filter",
            JOptionPane.QUESTION_MESSAGE
        );
    }

    // === Settings ===

    public Boolean setToken(String token) {
        if (token == null || token.isBlank()) return false;
        apiToken = token;
        return true;
    }

    public String getPersona() { return assistantPersona; }
    public void setPersona(String persona) { this.assistantPersona = persona; }
    public String getModel() { return openAiModel; }
    public void setModel(String model) { this.openAiModel = model; }
    public double getTemperature() { return temperature; }
    public void setTemperature(double temp) { this.temperature = temp; }
    public String getToken() { return apiToken; }
    public boolean isAppendToComment() { return appendToComment; }
    public void setAppendToComment(boolean append) { this.appendToComment = append; }

    public void exportSettings(Path path) {
        try {
            Properties props = new Properties();
            props.setProperty("model", openAiModel);
            props.setProperty("temperature", String.valueOf(temperature));
            props.setProperty("persona", assistantPersona);
            props.setProperty("appendToComment", String.valueOf(appendToComment));
            if (apiToken != null) props.setProperty("token", apiToken);
            props.store(Files.newOutputStream(path), "ChatGPTWhisperer Settings");
            ok("Settings exported to: " + path);
        } catch (IOException e) {
            error("Export failed: " + e.getMessage());
        }
    }

    public void importSettings(Path path) {
        try {
            Properties props = new Properties();
            props.load(Files.newInputStream(path));

            String model = props.getProperty("model");
            if (model != null) openAiModel = model;

            String tempStr = props.getProperty("temperature");
            if (tempStr != null) temperature = Double.parseDouble(tempStr);

            String persona = props.getProperty("persona");
            if (persona != null) assistantPersona = persona;

            String token = props.getProperty("token");
            if (token != null && !token.isBlank()) apiToken = token;

            String appendStr = props.getProperty("appendToComment");
            if (appendStr != null) appendToComment = Boolean.parseBoolean(appendStr);

            ok("Settings loaded.");
        } catch (IOException e) {
            error("Import failed: " + e.getMessage());
        }
    }

    private String censorToken(String token) {
        return token.length() <= 6 ? "****" : token.substring(0, 2) + "*".repeat(token.length() - 5) + token.charAt(token.length() - 1);
    }

    public void log(String message) {
        if (cs != null) cs.println("[ChatGPTWhisperer] [>] " + message);
    }

    public void error(String message) {
        if (cs != null) cs.println("[ChatGPTWhisperer] [-] " + message);
    }

    public void ok(String message) {
        if (cs != null) cs.println("[ChatGPTWhisperer] [+] " + message);
    }
}
