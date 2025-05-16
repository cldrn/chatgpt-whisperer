package chatgptwhisperer;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.framework.plugintool.Plugin;

import javax.swing.*;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;

public class ChatGPTWhispererComponent extends ComponentProvider {

    private final ChatGPTWhispererPlugin plugin;
    private static final String ROOT_MENU = "ChatGPTWhisperer";

    public ChatGPTWhispererComponent(Plugin plugin, String owner) {
        super(plugin.getTool(), owner, owner);
        this.plugin = (ChatGPTWhispererPlugin) plugin;
        createActions();
    }

    private void createActions() {
        // Core functionality
        createMenuAction("Describe Function", "Describe what this function does.", KeyEvent.VK_I, plugin::identifyFunction);
        createMenuAction("Detect Vulnerabilities", "Analyze for vulnerabilities.", KeyEvent.VK_V, plugin::findVulnerabilities);
        createMenuAction("Ask a Question", "Send a custom question about the function.", KeyEvent.VK_Q, plugin::askCustomQuestion);
        createMenuAction("Explain with Xrefs", "Use xrefs to help explain function use cases.", KeyEvent.VK_X, plugin::explainFunctionWithXrefs);
        createMenuAction("Suggest Function Signature", "Suggest return type, parameter types, and name.", KeyEvent.VK_S, plugin::suggestFunctionSignature);
        createMenuAction("Update Function Signature", "Analyze and apply a new function signature", KeyEvent.VK_U, plugin::updateFunctionSignature);

        // Batch functionality
        createMenuAction("Batch/Identify All Functions", "Run identify on all functions in the binary.", KeyEvent.VK_B, plugin::identifyAllFunctions);
        createMenuAction("Batch/Analyze All Functions for Vulnerabilities", "Run vulnerability analysis on all functions.", KeyEvent.VK_N, plugin::findVulnerabilitiesInAllFunctions);
        createMenuAction("Batch/Update Function Signatures", "Update function signatures across filtered functions", KeyEvent.VK_U, plugin::updateFunctionSignaturesInAllFunctions);

        createSettingsMenu();
    }

    private void createSettingsMenu() {
        addSimpleDialogAction("Set Assistant Persona", "Settings", () -> {
            String current = plugin.getPersona();
            String updated = askForPersonaPreset(current);
            if (updated != null && !updated.isBlank()) {
                plugin.setPersona(updated);
                plugin.ok("Persona updated.");
            } else {
                plugin.error("Persona must not be empty.");
            }
        });

        addSimpleDialogAction("Set OpenAI Token", "Settings", () -> {
            String token = askForOpenAIToken();
            if (token != null && !token.isBlank()) {
                plugin.setToken(token);
                plugin.ok("Token updated.");
            }
        });

        addSimpleDialogAction("Set Temperature", "Settings", () -> {
            Double newTemp = askForTemperature(plugin.getTemperature());
            if (newTemp != null) {
                plugin.setTemperature(newTemp);
                plugin.ok("Temperature set to: " + newTemp);
            }
        });

        for (String model : new String[]{
            "gpt-4.1",
            "gpt-4.1-mini",
            "gpt-4.1-nano",
            "gpt-4o",
            "gpt-4",
            "gpt-3.5-turbo",
            "o1",
            "o3-mini"}) {
            DockingAction modelAction = new DockingAction("Use Model: " + model, getName()) {
                @Override
                public void actionPerformed(ActionContext context) {
                    plugin.setModel(model);
                    plugin.ok("Model set to: " + model);
                }
            };
            modelAction.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU, "Settings", "Model", model
            }));
            dockingTool.addAction(modelAction);
        }

        addSimpleDialogAction("Export Settings", "Settings", () -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new File(System.getProperty("user.home"), "chatgptwhisperer.config"));
            int result = chooser.showSaveDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                plugin.exportSettings(chooser.getSelectedFile().toPath());
            }
        });

        addSimpleDialogAction("Import Settings", "Settings", () -> {
            JFileChooser chooser = new JFileChooser();
            int result = chooser.showOpenDialog(null);
            if (result == JFileChooser.APPROVE_OPTION) {
                plugin.importSettings(chooser.getSelectedFile().toPath());
            }
        });

        addSimpleDialogAction("Toggle Append Responses", "Settings", () -> {
            boolean current = plugin.isAppendToComment();
            int result = JOptionPane.showConfirmDialog(null,
                "Currently: " + (current ? "ON" : "OFF") + "\n\nToggle to " + (!current ? "ON" : "OFF") + "?",
                "Append Responses to Comments", JOptionPane.YES_NO_OPTION);
            if (result == JOptionPane.YES_OPTION) {
                plugin.setAppendToComment(!current);
                plugin.ok("Append to comment: " + !current);
            }
        });
    }

    private void createMenuAction(String name, String description, int key, Runnable task) {
        DockingAction action = new DockingAction(name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                new Thread(task).start();
            }
        };
        action.setDescription(description);
        action.setKeyBindingData(new KeyBindingData(key, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        action.setMenuBarData(new MenuData(splitMenuPath(name)));
        dockingTool.addAction(action);
    }

    private void addSimpleDialogAction(String name, String submenu, Runnable actionTask) {
        DockingAction action = new DockingAction(name, getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                actionTask.run();
            }
        };
        action.setMenuBarData(new MenuData(new String[]{
            ToolConstants.MENU_TOOLS, ROOT_MENU, submenu, name
        }));
        dockingTool.addAction(action);
    }

    private String[] splitMenuPath(String name) {
        String[] parts = name.split("/");
        String[] full = new String[2 + parts.length];
        full[0] = ToolConstants.MENU_TOOLS;
        full[1] = ROOT_MENU;
        System.arraycopy(parts, 0, full, 2, parts.length);
        return full;
    }

    public String askForOpenAIToken() {
        return JOptionPane.showInputDialog("Enter your OpenAI Token:");
    }

    public Double askForTemperature(double current) {
        SpinnerNumberModel model = new SpinnerNumberModel(current, 0.0, 1.0, 0.1);
        JSpinner spinner = new JSpinner(model);
        int result = JOptionPane.showConfirmDialog(null, spinner, "Set Temperature (0.0 - 2.0)", JOptionPane.OK_CANCEL_OPTION);
        return result == JOptionPane.OK_OPTION ? (Double) spinner.getValue() : null;
    }

    public String askForPersonaPreset(String current) {
        String[] presets = {
            "You are a reverse engineering assistant with expertise in firmware.",
            "You are a security researcher skilled in vulnerability analysis.",
            "You are a malware analyst helping dissect obfuscated code.",
            "Custom..."
        };

        JComboBox<String> combo = new JComboBox<>(presets);
        JTextArea custom = new JTextArea(current, 4, 40);
        JScrollPane scroll = new JScrollPane(custom);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.add(new JLabel("Choose a predefined persona or write your own:"));
        panel.add(combo);
        panel.add(Box.createVerticalStrut(5));
        panel.add(scroll);

        combo.addActionListener(e -> {
            if (!combo.getSelectedItem().equals("Custom...")) {
                custom.setText(combo.getSelectedItem().toString());
            }
        });

        int result = JOptionPane.showConfirmDialog(null, panel, "Set Persona", JOptionPane.OK_CANCEL_OPTION);
        return result == JOptionPane.OK_OPTION ? custom.getText().trim() : null;
    }

    public String askForQuestion() {
        return JOptionPane.showInputDialog("Ask a question about the current function:");
    }

    @Override
    public JComponent getComponent() {
        return new JPanel(); // unused but required
    }
}
