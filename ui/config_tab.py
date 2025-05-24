# -*- coding: utf-8 -*-
"""
UI components for BB User Agent extension
"""

from java.awt import BorderLayout, FlowLayout, Font, Dimension, GridBagLayout, GridBagConstraints, Insets, Color
from java.awt.event import ActionListener
from javax.swing import (JPanel, JLabel, JTextField, JComboBox, BoxLayout, BorderFactory,
                         JScrollPane, JCheckBox, SwingConstants, JMenuItem, JTextArea, JButton,
                         JToggleButton, DefaultComboBoxModel, JSeparator, Box, ButtonGroup, UIManager)

# Import utils
from utils.listeners import (UAFilterKeyAdapter, SuffixDocumentListener, AutoSaveDocumentListener,
                             ComboDocumentListener, DeviceFilterActionListener, BrowserFilterActionListener,
                             VersionFilterActionListener)
from utils.ui_utils import create_section_title, create_separator
from utils.placeholder_utils import add_placeholder
from utils.browser_utils import BrowserDetector
from utils.user_agent_manager import UserAgentManager


class ConfigTab:
    """BB User Agent extension UI tab"""

    def __init__(self, extension):
        """
        Initialize the UI components
        
        Args:
            extension: The main extension object
        """
        self.extension = extension
        self.tab = None
        self.ua_manager = UserAgentManager(extension)

        # UI components
        self.user_agent_suffix_field = None
        self.use_browser_ua_checkbox = None
        self.user_agent_combo = None
        self.scope_only_checkbox = None
        self.filter_field = None
        self.enable_toggle = None
        self.device_buttons = {}
        self.version_combo = None
        self.persist_temp_project_checkbox = None

    def create_ui(self):
        """Create the extension UI components"""
        try:
            # Main tab panel with BorderLayout and Burp Suite background
            self.tab = JPanel(BorderLayout())
            
            # Use Burp Suite colors
            burp_background = UIManager.getColor("Panel.background")
            if burp_background:
                self.tab.setBackground(burp_background)

            # Main panel with top margin
            wrapper_panel = JPanel(BorderLayout())
            if burp_background:
                wrapper_panel.setBackground(burp_background)
            wrapper_panel.setBorder(BorderFactory.createEmptyBorder(25, 0, 0, 0))

            # Main panel
            main_panel = JPanel()
            if burp_background:
                main_panel.setBackground(burp_background)
            main_panel.setLayout(BoxLayout(main_panel, BoxLayout.Y_AXIS))

            # Set flexible width and height
            main_panel_size = Dimension(1200, 680)
            main_panel.setMaximumSize(main_panel_size)
            main_panel.setPreferredSize(main_panel_size)
            main_panel.setMinimumSize(Dimension(1000, 600))

            # Create a content panel with a more pronounced background
            content_panel = JPanel()
            content_panel.setLayout(BoxLayout(content_panel, BoxLayout.Y_AXIS))

            if burp_background:
                red = burp_background.getRed()
                green = burp_background.getGreen()
                blue = burp_background.getBlue()
                
                brightness = (red + green + blue) / 3
                if brightness < 128:  # Dark theme
                    content_background = Color(max(0, red - 10), max(0, green - 10), max(0, blue - 10))
                else:  # Light theme
                    content_background = Color(min(255, red + 10), min(255, green + 10), min(255, blue + 10))
            else:
                content_background = Color(45, 45, 48)  # Default dark
            
            content_panel.setBackground(content_background)
            content_panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

            # Create a header section
            self._create_header_section(content_panel)

            # Create a User Agent configuration section
            self._create_user_agent_section(content_panel)

            # Create filter sections
            self._create_filter_sections(content_panel)

            # Create a form section
            self._create_form_section(content_panel)

            # Create BugBounty suffix section
            self._create_suffix_section(content_panel)

            # Add a content panel to the main panel
            content_panel_wrapper = JPanel(FlowLayout(FlowLayout.CENTER))
            if burp_background:
                content_panel_wrapper.setBackground(burp_background)
            content_panel_wrapper.add(content_panel)
            main_panel.add(content_panel_wrapper)

            # Add the main panel to wrapper with top margin
            wrapper_panel.add(main_panel, BorderLayout.CENTER)

            # Add a wrapper panel to the tab
            self.tab.add(wrapper_panel, BorderLayout.CENTER)

            # Configure components according to loaded settings
            self._configure_initial_state()

            # Mark UI as fully initialized
            self.extension.ui_initialized = True

            # Initialize filters after UI is created
            self._initialize_filters()

        except Exception as e:
            import traceback
            print("Error creating UI: " + str(e))
            traceback.print_exc()
            self._create_error_ui(str(e))

        return self.tab

    def _create_header_section(self, content_panel):
        """Create the header section with title and enable button"""
        # Header panel with balanced layout
        header_panel = JPanel(BorderLayout())
        header_panel.setBackground(content_panel.getBackground())

        # Left empty panel for balance
        left_panel = JPanel()
        left_panel.setBackground(content_panel.getBackground())
        left_panel.setPreferredSize(Dimension(250, 30))
        header_panel.add(left_panel, BorderLayout.WEST)

        # Centered title
        title_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        title_panel.setBackground(content_panel.getBackground())
        title_label = JLabel("BB User Agent")
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            title_label.setForeground(burp_foreground)
        
        title_label.setFont(Font(title_label.getFont().getName(), Font.BOLD, 18))
        title_panel.add(title_label)
        header_panel.add(title_panel, BorderLayout.CENTER)

        # Right side - Persistence checkbox
        persistence_panel = self._create_persistence_panel(content_panel.getBackground())
        header_panel.add(persistence_panel, BorderLayout.EAST)

        content_panel.add(header_panel)
        content_panel.add(Box.createVerticalStrut(15))

        # Enable button
        self._create_enable_button(content_panel)

        # Scope checkbox
        self._create_scope_checkbox(content_panel)

        # Add separator
        content_panel.add(Box.createVerticalStrut(10))
        content_panel.add(create_separator(content_panel))
        content_panel.add(Box.createVerticalStrut(10))

    def _create_persistence_panel(self, background_color):
        """Create the persistence checkbox panel"""
        persistence_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        persistence_panel.setBackground(background_color)
        persistence_panel.setPreferredSize(Dimension(250, 30))

        self.persist_temp_project_checkbox = JCheckBox("Save settings for temporary project", False)
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            self.persist_temp_project_checkbox.setForeground(burp_foreground)
        
        self.persist_temp_project_checkbox.setBackground(background_color)
        self.persist_temp_project_checkbox.setFont(
            Font(self.persist_temp_project_checkbox.getFont().getName(), Font.PLAIN, 11))

        # Add action listener
        class PersistTempActionListener(ActionListener):
            def __init__(self, extension):
                self.extension = extension

            def actionPerformed(self, event):
                self.extension.on_persist_temp_changed(event)

        self.persist_temp_project_checkbox.addActionListener(PersistTempActionListener(self.extension))
        persistence_panel.add(self.persist_temp_project_checkbox)

        return persistence_panel

    def _create_enable_button(self, content_panel):
        """Create the enable/disable button"""
        enable_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        enable_panel.setBackground(content_panel.getBackground())

        self.enable_toggle = JButton("Enabled")
        
        # Simple button colors - green for enabled, red for disabled
        self.enable_toggle.setBackground(Color(34, 139, 34))  # Green
        self.enable_toggle.setForeground(Color.WHITE)
        self.enable_toggle.setFont(Font(self.enable_toggle.getFont().getName(), Font.BOLD, 12))
        self.enable_toggle.setOpaque(True)
        self.enable_toggle.setBorderPainted(False)
        self.enable_toggle.setFocusPainted(False)
        self.enable_toggle.setContentAreaFilled(True)

        # Add action listener for enabled button
        class EnableButtonListener(ActionListener):
            def __init__(self, extension, button):
                self.extension = extension
                self.button = button

            def actionPerformed(self, event):
                self.extension.extension_enabled = not self.extension.extension_enabled

                if self.extension.extension_enabled:
                    self.button.setText("Enabled")
                    self.button.setBackground(Color(34, 139, 34))  # Green
                else:
                    self.button.setText("Disabled")
                    self.button.setBackground(Color(220, 53, 69))  # Red

                self.button.setForeground(Color.WHITE)
                self.button.repaint()
                self.extension.schedule_auto_save()

        self.enable_toggle.addActionListener(EnableButtonListener(self.extension, self.enable_toggle))
        enable_panel.add(self.enable_toggle)
        content_panel.add(enable_panel)

    def _create_scope_checkbox(self, content_panel):
        """Create the scope checkbox"""
        scope_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        scope_panel.setBackground(content_panel.getBackground())

        self.scope_only_checkbox = JCheckBox("Apply only to in-scope requests", True)
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            self.scope_only_checkbox.setForeground(burp_foreground)
        
        self.scope_only_checkbox.setBackground(content_panel.getBackground())
        self.scope_only_checkbox.addActionListener(self.extension.on_scope_changed)
        scope_panel.add(self.scope_only_checkbox)
        content_panel.add(scope_panel)

    def _create_user_agent_section(self, content_panel):
        """Create the User Agent configuration section"""
        content_panel.add(create_section_title(content_panel, "User Agent Configuration"))
        content_panel.add(Box.createVerticalStrut(10))

        # Use browser user agent checkbox
        browser_ua_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        browser_ua_panel.setBackground(content_panel.getBackground())

        self.use_browser_ua_checkbox = JCheckBox("Use default browser User-Agent", True)
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            self.use_browser_ua_checkbox.setForeground(burp_foreground)
        
        self.use_browser_ua_checkbox.setBackground(content_panel.getBackground())
        self.use_browser_ua_checkbox.addActionListener(self.extension.on_ua_source_changed)
        browser_ua_panel.add(self.use_browser_ua_checkbox)
        content_panel.add(browser_ua_panel)
        content_panel.add(Box.createVerticalStrut(20))

    def _create_filter_sections(self, content_panel):
        """Create all filter sections (device, browser, version)"""
        # Load user agents first
        user_agents = self.ua_manager.load_user_agents()
        if hasattr(self.extension, 'all_user_agents'):
            self.extension.all_user_agents = user_agents

        # Device filter
        self._create_device_filter(content_panel)

        # Browser filter 
        self._create_browser_filter(content_panel, user_agents)

        # Version filter
        self._create_version_filter(content_panel)

    def _create_device_filter(self, content_panel):
        """Create device filter buttons"""
        device_filter_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        device_filter_panel.setBackground(content_panel.getBackground())

        device_filter_label = JLabel("Filter by device type:")
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            device_filter_label.setForeground(burp_foreground)
        
        device_filter_panel.add(device_filter_label)

        button_group = ButtonGroup()
        device_types = ["All", "Windows", "Mac", "Linux", "Chrome OS", "iPhone", "iPad", "Android"]

        for device_type in device_types:
            button = JToggleButton(device_type)
            
            # Simple button colors using Burp Suite theme detection
            burp_background = UIManager.getColor("Panel.background")
            if burp_background:
                red = burp_background.getRed()
                green = burp_background.getGreen()
                blue = burp_background.getBlue()
                brightness = (red + green + blue) / 3
                
                if brightness < 128:  # Dark theme
                    button.setBackground(Color(70, 70, 70))
                    button.setForeground(Color.WHITE)
                else:  # Light theme
                    button.setBackground(Color(220, 220, 220))
                    button.setForeground(Color.BLACK)
            else:
                button.setBackground(Color(70, 70, 70))
                button.setForeground(Color.WHITE)
            
            button.addActionListener(DeviceFilterActionListener(self.extension, device_type))

            self.device_buttons[device_type] = button
            button_group.add(button)
            device_filter_panel.add(button)

        # Select default or saved filter
        selected_filter = getattr(self.extension, 'current_device_filter', "All")
        for device_type in device_types:
            if device_type == selected_filter:
                if device_type in self.device_buttons:
                    self.device_buttons[device_type].setSelected(True)
                    self.device_buttons[device_type].setBackground(Color(100, 100, 100))  # Selected color
            else:
                if device_type in self.device_buttons:
                    self.device_buttons[device_type].setSelected(False)

        content_panel.add(device_filter_panel)

    def _create_browser_filter(self, content_panel, user_agents):
        """Create browser filter buttons using BrowserDetector"""
        browser_filter_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        browser_filter_panel.setBackground(content_panel.getBackground())

        browser_filter_label = JLabel("Filter by browser:")
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            browser_filter_label.setForeground(burp_foreground)
        
        browser_filter_panel.add(browser_filter_label)

        browser_button_group = ButtonGroup()

        # Use BrowserDetector to get available browsers
        available_browsers = BrowserDetector.get_available_browsers(user_agents)

        for browser_type in available_browsers:
            button = JToggleButton(browser_type)
            
            # Simple button colors using Burp Suite theme detection
            burp_background = UIManager.getColor("Panel.background")
            if burp_background:
                red = burp_background.getRed()
                green = burp_background.getGreen()
                blue = burp_background.getBlue()
                brightness = (red + green + blue) / 3
                
                if brightness < 128:  # Dark theme
                    button.setBackground(Color(70, 70, 70))
                    button.setForeground(Color.WHITE)
                else:  # Light theme
                    button.setBackground(Color(220, 220, 220))
                    button.setForeground(Color.BLACK)
            else:
                button.setBackground(Color(70, 70, 70))
                button.setForeground(Color.WHITE)
            
            button.addActionListener(BrowserFilterActionListener(self.extension, browser_type))

            self.device_buttons[browser_type + "_browser"] = button
            browser_button_group.add(button)
            browser_filter_panel.add(button)

        # Select default or saved filter
        selected_browser = getattr(self.extension, 'current_browser_filter', "All")
        for browser_type in available_browsers:
            browser_key = browser_type + "_browser"
            if browser_type == selected_browser:
                if browser_key in self.device_buttons:
                    self.device_buttons[browser_key].setSelected(True)
                    self.device_buttons[browser_key].setBackground(Color(100, 100, 100))  # Selected color
            else:
                if browser_key in self.device_buttons:
                    self.device_buttons[browser_key].setSelected(False)

        content_panel.add(browser_filter_panel)

    def _create_version_filter(self, content_panel):
        """Create version filter dropdown"""
        version_filter_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        version_filter_panel.setBackground(content_panel.getBackground())

        version_filter_label = JLabel("Filter by major version:")
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            version_filter_label.setForeground(burp_foreground)
        
        version_filter_panel.add(version_filter_label)

        self.version_combo = JComboBox(["All"])
        
        # Use Burp Suite text field colors for combo box
        burp_text_bg = UIManager.getColor("TextField.background")
        burp_text_fg = UIManager.getColor("TextField.foreground")
        if burp_text_bg:
            self.version_combo.setBackground(burp_text_bg)
        if burp_text_fg:
            self.version_combo.setForeground(burp_text_fg)
        
        self.version_combo.addActionListener(VersionFilterActionListener(self.extension))
        version_filter_panel.add(self.version_combo)

        content_panel.add(version_filter_panel)
        content_panel.add(Box.createVerticalStrut(10))

    def _create_form_section(self, content_panel):
        """Create the main form section with filter field and user agent combo"""
        form_panel = JPanel(GridBagLayout())
        form_panel.setBackground(content_panel.getBackground())
        form_panel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20))

        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(8, 10, 8, 10)
        constraints.weightx = 1.0

        # Filter field
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        constraints.anchor = GridBagConstraints.CENTER

        filter_center_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        filter_center_panel.setBackground(form_panel.getBackground())

        self.filter_field = JTextField(40)
        add_placeholder(self.filter_field, "Enter keywords to filter User-Agents (e.g., chrome 137)",
                        "", self.extension, 'filter')
        self.filter_field.addKeyListener(UAFilterKeyAdapter(self.extension))
        filter_center_panel.add(self.filter_field)
        form_panel.add(filter_center_panel, constraints)

        # User agent combo
        constraints.gridy = 1

        # Load user agents for combo
        user_agents = getattr(self.extension, 'all_user_agents', [])
        combo_items = ["Select a user agent or directly type a user agent you want to use"] + user_agents

        self.user_agent_combo = JComboBox(combo_items)
        self.user_agent_combo.setEditable(True)
        self.user_agent_combo.setEnabled(not getattr(self.extension, 'use_browser_user_agent', True))
        self.user_agent_combo.addActionListener(self.extension.on_combo_changed)

        # Add document listener for combo text field
        self._setup_combo_listener()

        # Restore selected user agent if available
        self._restore_selected_user_agent(user_agents)

        combo_dimension = self.user_agent_combo.getPreferredSize()
        combo_dimension.width = 700
        self.user_agent_combo.setPreferredSize(combo_dimension)

        form_panel.add(self.user_agent_combo, constraints)

        # Add a form panel to content
        form_panel_wrapper = JPanel(BorderLayout())
        form_panel_wrapper.setBackground(content_panel.getBackground())
        form_panel_wrapper.add(form_panel, BorderLayout.CENTER)
        content_panel.add(form_panel_wrapper)
        content_panel.add(Box.createVerticalStrut(15))

    def _setup_combo_listener(self):
        """Setup document listener for combo box text field"""
        try:
            editor = self.user_agent_combo.getEditor()
            if editor and hasattr(editor, 'getEditorComponent'):
                text_field = editor.getEditorComponent()
                if text_field and hasattr(text_field, 'getDocument'):
                    combo_doc_listener = ComboDocumentListener(self.extension)
                    text_field.getDocument().addDocumentListener(combo_doc_listener)
        except Exception as e:
            print("Warning: Could not add DocumentListener to combo box: " + str(e))

    def _restore_selected_user_agent(self, user_agents):
        """Restore previously selected user agent"""
        if (hasattr(self.extension, 'selected_user_agent') and
                self.extension.selected_user_agent and
                not self.extension.use_browser_user_agent):

            # Try to find in a list first
            for i in range(self.user_agent_combo.getItemCount()):
                if self.user_agent_combo.getItemAt(i) == self.extension.selected_user_agent:
                    self.user_agent_combo.setSelectedIndex(i)
                    return

            # If not found in list, set directly
            if self.extension.selected_user_agent not in user_agents:
                self.user_agent_combo.setSelectedItem(self.extension.selected_user_agent)

    def _create_suffix_section(self, content_panel):
        """Create the BugBounty suffix section"""
        content_panel.add(create_separator(content_panel))
        content_panel.add(Box.createVerticalStrut(2))
        content_panel.add(create_section_title(content_panel, "BugBounty Suffix"))
        content_panel.add(Box.createVerticalStrut(2))

        # Suffix form panel
        suffix_form_panel = JPanel(GridBagLayout())
        suffix_form_panel.setBackground(content_panel.getBackground())
        suffix_form_panel.setBorder(BorderFactory.createEmptyBorder(2, 20, 2, 20))

        suffix_constraints = GridBagConstraints()
        suffix_constraints.fill = GridBagConstraints.HORIZONTAL
        suffix_constraints.insets = Insets(2, 10, 2, 10)
        suffix_constraints.weightx = 1.0
        suffix_constraints.gridx = 0
        suffix_constraints.gridy = 0
        suffix_constraints.gridwidth = 1
        suffix_constraints.anchor = GridBagConstraints.CENTER

        # Create a centered panel for suffix field
        suffix_center_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        suffix_center_panel.setBackground(suffix_form_panel.getBackground())

        # Get current suffix value
        suffix_value = getattr(self.extension, 'user_agent_suffix', "")

        self.user_agent_suffix_field = JTextField(30)

        # Set placeholder or value
        if not suffix_value:
            add_placeholder(self.user_agent_suffix_field, "Enter your bugbounty suffix here",
                            "", self.extension, 'suffix')
        else:
            self.user_agent_suffix_field.setText(suffix_value)
            
            # Use Burp Suite foreground color
            burp_foreground = UIManager.getColor("Panel.foreground")
            if burp_foreground:
                self.user_agent_suffix_field.setForeground(burp_foreground)

        # Add document listeners
        suffix_listener = SuffixDocumentListener(self.extension)
        auto_save_listener = AutoSaveDocumentListener(self.extension)
        self.user_agent_suffix_field.getDocument().addDocumentListener(suffix_listener)
        self.user_agent_suffix_field.getDocument().addDocumentListener(auto_save_listener)

        suffix_center_panel.add(self.user_agent_suffix_field)
        suffix_form_panel.add(suffix_center_panel, suffix_constraints)

        # Add suffix a form panel to content
        suffix_form_wrapper = JPanel(BorderLayout())
        suffix_form_wrapper.setBackground(content_panel.getBackground())
        suffix_form_wrapper.add(suffix_form_panel, BorderLayout.CENTER)
        content_panel.add(suffix_form_wrapper)
        content_panel.add(Box.createVerticalStrut(20))

    def _configure_initial_state(self):
        """Configure UI components according to loaded settings"""
        # Configure checkboxes
        if hasattr(self.extension, 'apply_to_scope_only'):
            self.scope_only_checkbox.setSelected(self.extension.apply_to_scope_only)
        else:
            self.scope_only_checkbox.setSelected(True)

        if hasattr(self.extension, 'use_browser_user_agent'):
            self.use_browser_ua_checkbox.setSelected(self.extension.use_browser_user_agent)
        else:
            self.use_browser_ua_checkbox.setSelected(True)

        if hasattr(self.extension, 'persist_temp_project'):
            self.persist_temp_project_checkbox.setSelected(self.extension.persist_temp_project)
        else:
            self.persist_temp_project_checkbox.setSelected(False)

        # Update component states
        self.user_agent_combo.setEnabled(not self.use_browser_ua_checkbox.isSelected())
        self.filter_field.setEnabled(not self.use_browser_ua_checkbox.isSelected())

    def _initialize_filters(self):
        """Initialize filters and versions after UI creation"""
        if hasattr(self.extension, 'update_available_versions'):
            self.extension.update_available_versions()

        # Apply saved filters
        if hasattr(self.extension, 'current_device_filter') and self.extension.current_device_filter != "All":
            self.extension.filter_by_device_type(self.extension.current_device_filter)
        elif hasattr(self.extension, 'current_browser_filter') and self.extension.current_browser_filter != "All":
            self.extension.filter_by_browser_type(self.extension.current_browser_filter)
        elif hasattr(self.extension, 'current_version_filter') and self.extension.current_version_filter != "All":
            self.extension.filter_by_version(self.extension.current_version_filter)

    def _create_error_ui(self, error_message):
        """Create minimal error UI"""
        self.tab = JPanel(BorderLayout())
        
        # Use Burp Suite background color
        burp_background = UIManager.getColor("Panel.background")
        if burp_background:
            self.tab.setBackground(burp_background)
        
        error_label = JLabel("Error creating UI: " + error_message)
        error_label.setForeground(Color(220, 53, 69))  # Red color for errors
        self.tab.add(error_label, BorderLayout.CENTER)

    def update_enable_button(self, enabled):
        """Update the enable/disable button appearance"""
        if self.enable_toggle:
            if enabled:
                self.enable_toggle.setText("Enabled")
                self.enable_toggle.setBackground(Color(34, 139, 34))  # Green
                self.enable_toggle.setForeground(Color.WHITE)
            else:
                self.enable_toggle.setText("Disabled")
                self.enable_toggle.setBackground(Color(220, 53, 69))  # Red
                self.enable_toggle.setForeground(Color.WHITE)

            # Force visual update
            self.enable_toggle.setOpaque(True)
            self.enable_toggle.setBorderPainted(False)
            self.enable_toggle.setFocusPainted(False)
            self.enable_toggle.repaint()
