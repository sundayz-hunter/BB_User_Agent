# -*- coding: utf-8 -*-
"""
BB User Agent - A Burp Suite extension for managing User-Agent headers in bug bounty
This extension allows users to:
1. Add custom suffixes to User-Agent headers per project
2. Choose between browser User-Agent or predefined User-Agents
3. Save settings per project automatically
4. Apply changes only to in-scope requests
"""

from burp import IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory, IProxyListener, \
    ISessionHandlingAction, IHttpListener
from java.awt import BorderLayout
from java.awt.event import ActionListener
from javax.swing import JMenuItem, DefaultComboBoxModel, SwingUtilities
import threading
import json

# Import utility modules
from utils.project_utils import get_project_name, load_project_settings, save_project_settings
from utils.user_agent_utils import (
    get_browser_user_agent, modify_request_user_agent, filter_user_agents
)
from java.awt import Color
from javax.swing import UIManager

# Import UI components
from ui.config_tab import ConfigTab


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory, IProxyListener,
                   ISessionHandlingAction, IHttpListener):
    # Extension configuration
    NAME = "BB User Agent"
    SETTING_NAME = "bb_user_agent_settings"

    def __init__(self):
        print("Initializing extension...")
        # Initialize variables
        self._callbacks = None
        self._helpers = None

        # User-Agent configuration
        self.user_agent_suffix = ""
        self.use_browser_user_agent = True
        self.selected_user_agent = None
        self.all_user_agents = []
        self.current_project_name = None
        self.projects_settings = {}  # Dictionary to store settings per project
        self.apply_to_scope_only = True
        self.extension_enabled = True
        self.current_device_filter = "All"  # Default to showing all device types
        self.current_browser_filter = "All"  # Default to showing all browsers
        self.current_version_filter = "All"  # Default to showing all versions
        self.available_versions = ["All"]  # Available versions for filtering
        self.persist_temp_project = False  # Whether to save settings in temporary project

        # UI components
        self.ui = None
        self.ui_initialized = False  # Flag to track if UI is fully initialized

    def registerExtenderCallbacks(self, callbacks):
        """Register extension callbacks and initialize UI"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.NAME)

        # Register listeners
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerSessionHandlingAction(self)

        # Load persist temp preference FIRST (from Burp user preferences)
        self.load_persist_temp_preference()

        # Determine current project name based on persist setting
        if self.persist_temp_project:
            self.current_project_name = "Temporary Project"
        else:
            self.current_project_name = get_project_name(callbacks)

        # Load settings for the current project
        project_settings, self.projects_settings = load_project_settings(
            callbacks, self.current_project_name, self.SETTING_NAME
        )

        # Apply loaded settings
        self.user_agent_suffix = project_settings.get("suffix", "")
        self.use_browser_user_agent = project_settings.get("use_browser_ua", True)
        self.selected_user_agent = project_settings.get("selected_ua", None)
        self.apply_to_scope_only = project_settings.get("scope_only", True)
        self.current_device_filter = project_settings.get("device_filter", "All")
        self.current_browser_filter = project_settings.get("browser_filter", "All")
        self.current_version_filter = project_settings.get("version_filter", "All")

        # Create UI
        self.ui = ConfigTab(self)

        # Register the tab
        callbacks.addSuiteTab(self)

        print("Extension loaded successfully")
        print("Current project: {}".format(self.current_project_name))

    def on_suffix_changed(self):
        """Called when the suffix field is changed"""
        if hasattr(self, 'ui') and self.ui and hasattr(self.ui,
                                                       'user_agent_suffix_field') and self.ui.user_agent_suffix_field:
            current_text = self.ui.user_agent_suffix_field.getText()
            field_color = self.ui.user_agent_suffix_field.getForeground()

            placeholder_color = Color.GRAY

            # Only consider it placeholder if color matches AND text is the exact placeholder
            if (field_color == placeholder_color) and \
                    current_text == "Enter your bugbounty suffix here":
                self.user_agent_suffix = ""
            else:
                # Accept any non-placeholder text, including single characters
                self.user_agent_suffix = current_text

    def filter_by_device_type(self, device_type):
        """
        Filter the user agents list based on device type 
        Called when user clicks on a device filter button
        
        Args:
            device_type: The device type to filter for (e.g., Windows, Mac, Android)
        """
        # Store the current device filter
        self.current_device_filter = device_type

        # Update button appearances
        if hasattr(self, 'ui') and self.ui and hasattr(self.ui, 'device_buttons'):
            # Simple button colors using Burp Suite theme detection
            burp_background = UIManager.getColor("Panel.background")
            if burp_background:
                red = burp_background.getRed()
                green = burp_background.getGreen()
                blue = burp_background.getBlue()
                brightness = (red + green + blue) / 3
                
                if brightness < 128:  # Dark theme
                    normal_color = Color(70, 70, 70)
                    selected_color = Color(100, 100, 100)
                else:  # Light theme
                    normal_color = Color(220, 220, 220)
                    selected_color = Color(100, 100, 100)
            else:
                normal_color = Color(70, 70, 70)
                selected_color = Color(100, 100, 100)
            
            # Reset all device buttons to normal background
            device_types = ["All", "Windows", "Mac", "Linux", "Chrome OS", "iPhone", "iPad", "Android"]
            for dt in device_types:
                if dt in self.ui.device_buttons:
                    button = self.ui.device_buttons[dt]
                    if dt == device_type:
                        button.setBackground(selected_color)
                    else:
                        button.setBackground(normal_color)
                    button.repaint()

        # Apply the filter
        self.filter_user_agents_combo()

        # Update available versions based on the new device filter
        self.update_available_versions()

        # Save this preference
        self.schedule_auto_save()

    def filter_by_device_type_internal(self, user_agents, device_type):
        """
        Internal method to filter user agents based on device type
        
        Args:
            user_agents: List of user agent strings to filter
            device_type: The device type to filter for
            
        Returns:
            list: Filtered list of user agents matching the device type
        """
        # Return all if filter is set to "All"
        if device_type == "All":
            return user_agents

        filtered = []

        # Filter user agents based on device type with specific logic
        for ua in user_agents:
            if device_type == "Windows":
                if (
                        "Windows NT" in ua or "Win64" in ua) and "iPhone" not in ua and "iPad" not in ua and "Android" not in ua and "CrOS" not in ua:
                    filtered.append(ua)
            elif device_type == "Mac":
                if (
                        "Macintosh" in ua or "Mac OS X" in ua) and "iPhone" not in ua and "iPad" not in ua and "Android" not in ua and "CrOS" not in ua:
                    filtered.append(ua)
            elif device_type == "Linux":
                if ("Linux" in ua or "X11" in ua) and "Android" not in ua and "iPhone" not in ua and "iPad" not in ua and "CrOS" not in ua:
                    filtered.append(ua)
            elif device_type == "Chrome OS":
                if "CrOS" in ua:
                    filtered.append(ua)
            elif device_type == "iPhone":
                if "iPhone" in ua:
                    filtered.append(ua)
            elif device_type == "iPad":
                if "iPad" in ua:
                    filtered.append(ua)
            elif device_type == "Android":
                if "Android" in ua and "iPhone" not in ua and "iPad" not in ua:
                    filtered.append(ua)

        return filtered

    def filter_by_browser_type(self, browser_type):
        """
        Filter the user agents list based on browser type
        Called when user clicks on a browser filter button
        
        Args:
            browser_type: The browser type to filter for (e.g., Chrome, Firefox, Safari)
        """
        # Store the current browser filter
        self.current_browser_filter = browser_type

        # Update button appearances
        if hasattr(self, 'ui') and self.ui and hasattr(self.ui, 'device_buttons'):
            # Simple button colors using Burp Suite theme detection
            burp_background = UIManager.getColor("Panel.background")
            if burp_background:
                red = burp_background.getRed()
                green = burp_background.getGreen()
                blue = burp_background.getBlue()
                brightness = (red + green + blue) / 3
                
                if brightness < 128:  # Dark theme
                    normal_color = Color(70, 70, 70)
                    selected_color = Color(100, 100, 100)
                else:  # Light theme
                    normal_color = Color(220, 220, 220)
                    selected_color = Color(100, 100, 100)
            else:
                normal_color = Color(70, 70, 70)
                selected_color = Color(100, 100, 100)
            
            # Reset all browser buttons to normal background
            from utils.browser_utils import BrowserDetector
            if hasattr(self, 'all_user_agents'):
                available_browsers = BrowserDetector.get_available_browsers(self.all_user_agents)
                for bt in available_browsers:
                    browser_key = bt + "_browser"
                    if browser_key in self.ui.device_buttons:
                        button = self.ui.device_buttons[browser_key]
                        if bt == browser_type:
                            button.setBackground(selected_color)
                        else:
                            button.setBackground(normal_color)
                        button.repaint()

        # Apply the filter
        self.filter_user_agents_combo()

        # Update available versions based on the new browser filter
        self.update_available_versions()

        # Save this preference
        self.schedule_auto_save()

    def filter_by_browser_type_internal(self, user_agents, browser_type):
        """
        Internal method to filter user agents based on browser type
        Uses the new BrowserDetector utility
        
        Args:
            user_agents: List of user agent strings to filter
            browser_type: The browser type to filter for
            
        Returns:
            list: Filtered list of user agents matching the browser type
        """
        from utils.browser_utils import BrowserDetector
        return BrowserDetector.filter_by_browser(user_agents, browser_type)

    def update_available_versions(self):
        """
        Update the available browser versions based on the current filters
        """
        if not hasattr(self, 'ui') or not self.ui or not hasattr(self.ui, 'version_combo') or not self.ui.version_combo:
            return

        # Start with a filtered list based on current device and browser filters
        filtered_uas = self.all_user_agents

        # Apply device filter if it's set
        if self.current_device_filter != "All":
            filtered_uas = self.filter_by_device_type_internal(filtered_uas, self.current_device_filter)

        # Apply browser filter if it's set
        if self.current_browser_filter != "All":
            filtered_uas = self.filter_by_browser_type_internal(filtered_uas, self.current_browser_filter)

        # Extract major versions from the filtered user agents
        versions = set(["All"])

        for ua in filtered_uas:
            version_match = None

            if self.current_browser_filter == "Chrome" or self.current_browser_filter == "All" and "Chrome" in ua:
                # Extract Chrome version
                import re
                match = re.search(r'Chrome/(\d+)', ua)
                if match:
                    version_match = match.group(1)
            elif self.current_browser_filter == "Firefox" or self.current_browser_filter == "All" and "Firefox" in ua:
                # Extract Firefox version
                import re
                match = re.search(r'Firefox/(\d+)', ua)
                if match:
                    version_match = match.group(1)
            elif self.current_browser_filter == "Safari" or self.current_browser_filter == "All" and "Safari" in ua and "Chrome" not in ua:
                # Extract Safari version
                import re
                match = re.search(r'Version/(\d+)', ua)
                if match:
                    version_match = match.group(1)

            if version_match:
                versions.add(version_match)

        # Convert to list and sort numerically
        version_list = list(versions)

        # Keep "All" at the beginning
        if "All" in version_list:
            version_list.remove("All")

        # Sort numerically
        version_list.sort(key=lambda x: int(x) if x.isdigit() else 0)

        # Add "All" back at the beginning
        version_list.insert(0, "All")

        # Store the available versions
        self.available_versions = version_list

        # Update the version combo box
        self.ui.version_combo.setModel(DefaultComboBoxModel(version_list))

        # Select the current version if it's available, otherwise select "All"
        if self.current_version_filter in version_list:
            self.ui.version_combo.setSelectedItem(self.current_version_filter)
        else:
            self.ui.version_combo.setSelectedItem("All")
            self.current_version_filter = "All"

    def filter_by_version(self, version):
        """
        Filter the user agents list based on browser version
        Called when user selects a version from the version combo box
        
        Args:
            version: The browser version to filter for
        """
        # Store the current version filter
        self.current_version_filter = version

        # Apply the filter
        self.filter_user_agents_combo()

        # Save this preference
        self.schedule_auto_save()

    def filter_by_version_internal(self, user_agents, version):
        """
        Internal method to filter user agents based on browser version
        
        Args:
            user_agents: List of user agent strings to filter
            version: The browser version to filter for
            
        Returns:
            list: Filtered list of user agents matching the browser version
        """
        # Return all if filter is set to "All"
        if version == "All":
            return user_agents

        filtered = []

        # Build the appropriate regex pattern based on the current browser filter
        import re
        patterns = []

        if self.current_browser_filter == "Chrome" or self.current_browser_filter == "All":
            patterns.append(r'Chrome/' + re.escape(version) + r'\.')
        if self.current_browser_filter == "Firefox" or self.current_browser_filter == "All":
            patterns.append(r'Firefox/' + re.escape(version) + r'\.')
        if self.current_browser_filter == "Safari" or self.current_browser_filter == "All":
            patterns.append(r'Version/' + re.escape(version) + r'\.')
        if self.current_browser_filter == "Opera" or self.current_browser_filter == "All":
            patterns.append(r'OPR/' + re.escape(version) + r'\.')

        # Filter user agents based on version patterns
        for ua in user_agents:
            for pattern in patterns:
                if re.search(pattern, ua):
                    filtered.append(ua)
                    break  # Stop checking other patterns for this UA

        return filtered

    def filter_user_agents_combo(self):
        """Filter the User-Agent combo box based on the filter text"""
        if (not hasattr(self, 'ui') or
                not self.ui or
                not hasattr(self.ui, 'filter_field') or
                not self.ui.filter_field or
                not hasattr(self.ui, 'user_agent_combo') or
                not self.ui.user_agent_combo):
            return

        # Get filter text, but check if it's placeholder
        current_text = self.ui.filter_field.getText()
        field_color = self.ui.filter_field.getForeground()

        placeholder_color = Color.GRAY

        if (field_color == placeholder_color) or \
                current_text == "Enter keywords to filter User-Agents (e.g., chrome 137)" or \
                not current_text.strip():
            # If it's placeholder text, show all user agents
            filter_text = ""
        else:
            # Use the actual user input
            filter_text = current_text

        self.filter_user_agents_combo_with_text(filter_text)

    def filter_user_agents_combo_with_text(self, filter_text):
        """Filter the User-Agent combo box with specific text"""
        if (not hasattr(self, 'ui') or
                not self.ui or
                not hasattr(self.ui, 'user_agent_combo') or
                not self.ui.user_agent_combo):
            return

        filtered_agents = filter_user_agents(self.all_user_agents, filter_text)

        # Apply device type filter if it's set
        if hasattr(self, 'current_device_filter') and self.current_device_filter != "All":
            filtered_agents = self.filter_by_device_type_internal(filtered_agents, self.current_device_filter)

        # Apply browser type filter if it's set
        if hasattr(self, 'current_browser_filter') and self.current_browser_filter != "All":
            filtered_agents = self.filter_by_browser_type_internal(filtered_agents, self.current_browser_filter)

        # Apply version filter if it's set
        if hasattr(self, 'current_version_filter') and self.current_version_filter != "All":
            filtered_agents = self.filter_by_version_internal(filtered_agents, self.current_version_filter)

        # Make sure there's at least one item in the list
        if not filtered_agents:
            filtered_agents = ["No User-Agent matches filter"]

        # Update the combo box model
        self.ui.user_agent_combo.setModel(DefaultComboBoxModel(filtered_agents))

        # Try to select an appropriate item
        if self.selected_user_agent:
            for i in range(self.ui.user_agent_combo.getItemCount()):
                if self.ui.user_agent_combo.getItemAt(i) == self.selected_user_agent:
                    self.ui.user_agent_combo.setSelectedIndex(i)
                    break
        elif self.ui.user_agent_combo.getItemCount() > 0:
            self.ui.user_agent_combo.setSelectedIndex(0)

    def schedule_auto_save(self):
        """Schedule an auto-save with a small delay"""
        if not self.ui_initialized:
            return

        current_project_is_temp = self.current_project_name == "Temporary Project"
        if current_project_is_temp and not self.persist_temp_project:
            return

        def delayed_save():
            try:
                self.sync_current_ui_values()

                current_project_is_temp = self.current_project_name == "Temporary Project"
                if current_project_is_temp and not self.persist_temp_project:
                    return

                project_settings = {
                    "suffix": self.user_agent_suffix,
                    "use_browser_ua": self.use_browser_user_agent,
                    "selected_ua": self.selected_user_agent,
                    "scope_only": self.apply_to_scope_only,
                    "device_filter": self.current_device_filter,
                    "browser_filter": self.current_browser_filter,
                    "version_filter": self.current_version_filter
                }

                save_project_settings(
                    self._callbacks,
                    self.current_project_name,
                    self.SETTING_NAME,
                    self.projects_settings,
                    project_settings
                )

            except Exception as e:
                print("Error saving settings: " + str(e))

        timer = threading.Timer(0.5, lambda: SwingUtilities.invokeLater(delayed_save))
        timer.start()

    def on_ua_source_changed(self, event):
        """Handle change of User-Agent source (browser or predefined)"""
        if (hasattr(self, 'ui') and
                self.ui and
                hasattr(self.ui, 'use_browser_ua_checkbox') and
                self.ui.use_browser_ua_checkbox and
                hasattr(self.ui, 'user_agent_combo') and
                self.ui.user_agent_combo and
                hasattr(self.ui, 'filter_field') and
                self.ui.filter_field):
            is_browser_ua = self.ui.use_browser_ua_checkbox.isSelected()
            self.ui.user_agent_combo.setEnabled(not is_browser_ua)
            self.ui.filter_field.setEnabled(not is_browser_ua)
            self.use_browser_user_agent = is_browser_ua
            self.schedule_auto_save()

    def on_combo_changed(self, event):
        """Handle change in the user agent combo box"""
        if (hasattr(self, 'ui') and
                self.ui and
                hasattr(self.ui, 'user_agent_combo') and
                self.ui.user_agent_combo):
            
            # Get the selected item or typed text
            selected_item = self.ui.user_agent_combo.getSelectedItem()
            
            # Also check if text was typed directly in the combo box
            editor = self.ui.user_agent_combo.getEditor()
            if editor and hasattr(editor, 'getEditorComponent'):
                text_field = editor.getEditorComponent()
                if text_field:
                    typed_text = text_field.getText()
                    if typed_text and typed_text.strip():
                        # Use typed text if available
                        self.selected_user_agent = typed_text
                    elif selected_item and selected_item != "Select a user agent or directly type a user agent you want to use":
                        # Use selected item if no typed text
                        self.selected_user_agent = selected_item
                    else:
                        self.selected_user_agent = None
                else:
                    # Fallback to selected item
                    if selected_item and selected_item != "Select a user agent or directly type a user agent you want to use":
                        self.selected_user_agent = selected_item
                    else:
                        self.selected_user_agent = None
            else:
                # Fallback to selected item
                if selected_item and selected_item != "Select a user agent or directly type a user agent you want to use":
                    self.selected_user_agent = selected_item
                else:
                    self.selected_user_agent = None

        # Schedule auto-save
        self.schedule_auto_save()

    def on_scope_changed(self, event):
        """Handle change in the scope checkbox"""
        self.schedule_auto_save()

    def on_persist_temp_changed(self, event):
        """Handle change in the persist temp project checkbox"""

        if (hasattr(self, 'ui') and
                self.ui and
                hasattr(self.ui, 'persist_temp_project_checkbox') and
                self.ui.persist_temp_project_checkbox):

            old_persist_state = self.persist_temp_project
            new_persist_state = self.ui.persist_temp_project_checkbox.isSelected()

            # Update the state
            self.persist_temp_project = new_persist_state

            # Save this preference IMMEDIATELY in Burp user preferences (not project settings)
            self.save_persist_temp_preference()

            # Handle project switching and cleanup
            if self.persist_temp_project and not old_persist_state:
                # KEEP current settings and save them to temporary project
                # Don't load temporary project settings - use current ones
                old_project_name = self.current_project_name
                self.current_project_name = "Temporary Project"

                # Get current UI values and save them to temporary project
                self.sync_current_ui_values()

                # Save current settings to temporary project
                project_settings = {
                    "suffix": self.user_agent_suffix,
                    "use_browser_ua": self.use_browser_user_agent,
                    "selected_ua": self.selected_user_agent,
                    "scope_only": self.apply_to_scope_only,
                    "device_filter": self.current_device_filter,
                    "browser_filter": self.current_browser_filter,
                    "version_filter": self.current_version_filter
                }

                save_project_settings(
                    self._callbacks,
                    self.current_project_name,
                    self.SETTING_NAME,
                    self.projects_settings,
                    project_settings
                )

            elif not self.persist_temp_project and old_persist_state:
                # Clear temporary project settings completely
                self.clear_temporary_project_settings()

                # Reload real project name
                self.current_project_name = get_project_name(self._callbacks)

                # Load settings for the real project but PRESERVE current UI settings
                project_settings, self.projects_settings = load_project_settings(
                    self._callbacks, self.current_project_name, self.SETTING_NAME
                )

                # PRESERVE ALL current settings - only load suffix from project
                saved_device_filter = self.current_device_filter
                saved_browser_filter = self.current_browser_filter
                saved_use_browser_ua = self.use_browser_user_agent
                saved_selected_ua = self.selected_user_agent
                saved_apply_to_scope_only = self.apply_to_scope_only

                # Only load suffix from project settings
                self.user_agent_suffix = project_settings.get("suffix", "")

                # RESTORE all current settings (don't load from project)
                self.use_browser_user_agent = saved_use_browser_ua
                self.selected_user_agent = saved_selected_ua
                self.apply_to_scope_only = saved_apply_to_scope_only
                self.current_device_filter = saved_device_filter
                self.current_browser_filter = saved_browser_filter
                self.current_version_filter = project_settings.get("version_filter", "All")

                # Update UI to reflect current settings
                self.refresh_ui_from_settings()


    def clear_temporary_project_settings(self):
        """Clear all settings saved for the Temporary project"""
        try:
            # Load current projects settings
            current_settings_json = self._callbacks.loadExtensionSetting(self.SETTING_NAME)

            if current_settings_json:
                try:
                    all_projects_settings = json.loads(current_settings_json)

                    # Remove Temporary project from settings if it exists
                    if "Temporary Project" in all_projects_settings:
                        deleted_settings = all_projects_settings["Temporary Project"]
                        del all_projects_settings["Temporary Project"]

                        # Save the updated settings (without Temporary project)
                        updated_settings_json = json.dumps(all_projects_settings)
                        self._callbacks.saveExtensionSetting(self.SETTING_NAME, updated_settings_json)

                        # Also update our internal projects_settings to prevent re-saving
                        if "Temporary Project" in self.projects_settings:
                            del self.projects_settings["Temporary Project"]

                    else:
                        print("No Temporary Project settings found to clear")

                except json.JSONDecodeError:
                    print("Error parsing settings JSON during cleanup")
            else:
                print("No extension settings found - nothing to clear")

        except Exception as e:
            print("Error clearing Temporary Project settings: " + str(e))
            import traceback
            traceback.print_exc()

    def sync_current_ui_values(self):
        """Sync current UI values to internal variables"""
        try:
            if not hasattr(self, 'ui') or not self.ui:
                return

            # Get current values from UI fields
            if hasattr(self.ui, 'user_agent_suffix_field') and self.ui.user_agent_suffix_field:
                current_text = self.ui.user_agent_suffix_field.getText()
                field_color = self.ui.user_agent_suffix_field.getForeground()
                placeholder_color = Color.GRAY

                # Check if it's placeholder text (exact match on both color and text)
                if (field_color == placeholder_color and 
                    current_text == "Enter your bugbounty suffix here"):
                    self.user_agent_suffix = ""
                else:
                    # Accept any text content, including single characters
                    self.user_agent_suffix = current_text

            # Get checkbox states
            if hasattr(self.ui, 'use_browser_ua_checkbox') and self.ui.use_browser_ua_checkbox:
                self.use_browser_user_agent = self.ui.use_browser_ua_checkbox.isSelected()

            if hasattr(self.ui, 'scope_only_checkbox') and self.ui.scope_only_checkbox:
                self.apply_to_scope_only = self.ui.scope_only_checkbox.isSelected()

            # Get selected user agent (handle both selection and direct typing)
            if (hasattr(self.ui, 'user_agent_combo') and self.ui.user_agent_combo and
                    not self.use_browser_user_agent):
                
                # Check if text was typed directly in the combo box
                editor = self.ui.user_agent_combo.getEditor()
                typed_text = None
                
                if editor and hasattr(editor, 'getEditorComponent'):
                    text_field = editor.getEditorComponent()
                    if text_field:
                        typed_text = text_field.getText()
                
                # Use typed text if available, otherwise use selected item
                if typed_text and typed_text.strip() and typed_text != "Select a user agent or directly type a user agent you want to use":
                    self.selected_user_agent = typed_text
                else:
                    selected_item = self.ui.user_agent_combo.getSelectedItem()
                    if selected_item and selected_item != "Select a user agent or directly type a user agent you want to use":
                        self.selected_user_agent = selected_item
                    else:
                        self.selected_user_agent = None

        except Exception as e:
            print("Error syncing UI values: " + str(e))

    def refresh_ui_from_settings(self):
        """Refresh the UI components from current settings"""
        try:
            if not hasattr(self, 'ui') or not self.ui:
                return

            # Update suffix field
            if hasattr(self.ui, 'user_agent_suffix_field') and self.ui.user_agent_suffix_field:
                if self.user_agent_suffix:
                    # Set actual suffix value
                    self.ui.user_agent_suffix_field.setText(self.user_agent_suffix)
                    
                    # Use Burp Suite foreground color
                    burp_foreground = UIManager.getColor("Panel.foreground")
                    if burp_foreground:
                        self.ui.user_agent_suffix_field.setForeground(burp_foreground)
                else:
                    # Only reset to placeholder if field is currently empty or already a placeholder
                    current_text = self.ui.user_agent_suffix_field.getText()
                    current_color = self.ui.user_agent_suffix_field.getForeground()
                    placeholder_color = Color.GRAY

                    # Check if current content is placeholder or truly empty
                    if (current_color == Color.GRAY and 
                        current_text == "Enter your bugbounty suffix here") or not current_text:
                        from utils.placeholder_utils import add_placeholder
                        add_placeholder(self.ui.user_agent_suffix_field, "Enter your bugbounty suffix here", "", self,
                                        'suffix')

            # Update use browser UA checkbox
            if hasattr(self.ui, 'use_browser_ua_checkbox') and self.ui.use_browser_ua_checkbox:
                self.ui.use_browser_ua_checkbox.setSelected(self.use_browser_user_agent)

            # Update scope checkbox
            if hasattr(self.ui, 'scope_only_checkbox') and self.ui.scope_only_checkbox:
                self.ui.scope_only_checkbox.setSelected(self.apply_to_scope_only)

            # Update combo box state
            if hasattr(self.ui, 'user_agent_combo') and self.ui.user_agent_combo:
                self.ui.user_agent_combo.setEnabled(not self.use_browser_user_agent)
                if self.selected_user_agent and not self.use_browser_user_agent:
                    self.ui.user_agent_combo.setSelectedItem(self.selected_user_agent)

            # Update filter field state
            if hasattr(self.ui, 'filter_field') and self.ui.filter_field:
                self.ui.filter_field.setEnabled(not self.use_browser_user_agent)

            # Update device filter buttons
            if hasattr(self.ui, 'device_buttons') and self.ui.device_buttons:
                # Reset all buttons first
                for device_type, button in self.ui.device_buttons.items():
                    button.setSelected(False)

                # Select the correct device filter
                if self.current_device_filter in self.ui.device_buttons:
                    self.ui.device_buttons[self.current_device_filter].setSelected(True)

                # Select the correct browser filter  
                browser_key = self.current_browser_filter + "_browser"
                if browser_key in self.ui.device_buttons:
                    self.ui.device_buttons[browser_key].setSelected(True)

        except Exception as e:
            print("Error refreshing UI: " + str(e))

    def save_persist_temp_preference(self):
        """Save the persist temp project preference in Burp user settings"""
        try:
            # Save in Burp Suite user preferences (persistent across all projects)
            preference_key = "bb_user_agent_persist_temp"
            preference_value = "true" if self.persist_temp_project else "false"

            # Use Burp's preference storage
            self._callbacks.saveExtensionSetting(preference_key, preference_value)

        except Exception as e:
            print("Error saving persist temp preference: " + str(e))

    def load_persist_temp_preference(self):
        """Load the persist temp project preference from Burp user settings"""
        try:
            preference_key = "bb_user_agent_persist_temp"
            preference_value = self._callbacks.loadExtensionSetting(preference_key)

            if preference_value:
                self.persist_temp_project = preference_value == "true"
            else:
                self.persist_temp_project = False

            return self.persist_temp_project

        except Exception as e:
            print("Error loading persist temp preference: " + str(e))
            self.persist_temp_project = False
            return False

    def processProxyMessage(self, messageIsRequest, message):
        """Process proxy messages and modify User-Agent if needed"""
        try:
            # Only process outgoing requests
            if not messageIsRequest:
                return

            # Sync UI values first to ensure we have current settings
            self.sync_current_ui_values()

            # Skip if extension is disabled
            if not self.extension_enabled:
                return

            # Skip if using browser UA and no suffix (nothing to change)
            if self.use_browser_user_agent and (not self.user_agent_suffix or not self.user_agent_suffix.strip()):
                return

            # Skip if using predefined UA but no UA selected and no suffix
            if (not self.use_browser_user_agent and
                not self.selected_user_agent and
                (not self.user_agent_suffix or not self.user_agent_suffix.strip())):
                return

            # Debug info - can be removed later
            print("Processing request - use_browser_ua: {}, selected_ua: {}, suffix: '{}'".format(
                self.use_browser_user_agent,
                self.selected_user_agent if self.selected_user_agent else "None",
                self.user_agent_suffix if self.user_agent_suffix else ""))

            try:
                messageinfo = message.getMessageInfo()
                request = messageinfo.getRequest()
                request_info = self._helpers.analyzeRequest(request)
                headers = request_info.getHeaders()

                # Skip CONNECT requests
                if headers and headers[0].startswith("CONNECT"):
                    return

                # Check scope if enabled
                if self.apply_to_scope_only:
                    scope_check_passed = False
                    try:
                        # Try to get the service and then analyze with service
                        service = messageinfo.getHttpService()
                        if service:
                            request_info_with_service = self._helpers.analyzeRequest(service, request)
                            url = request_info_with_service.getUrl()
                            scope_check_passed = self._callbacks.isInScope(url)
                        else:
                            # Fallback: try to construct URL from host header
                            scope_check_passed = True  # Default to allow if we can't check

                        if not scope_check_passed:
                            return
                    except Exception as e:
                        print("Scope check failed: {}".format(str(e)))
                        # Fallback method using host header
                        try:
                            host = None
                            for header in headers:
                                if header.lower().startswith("host:"):
                                    host = header.split(":", 1)[1].strip()
                                    break

                            if host:
                                path = "/"
                                first_line = headers[0]
                                if first_line.startswith("GET ") or first_line.startswith("POST "):
                                    path_part = first_line.split(" ")[1]
                                    if path_part.startswith("/"):
                                        path = path_part

                                from java.net import URL
                                url = URL("https://" + host + path)

                                scope_check_passed = self._callbacks.isInScope(url)
                                if not scope_check_passed:
                                    return
                            else:
                                scope_check_passed = True
                        except Exception as e2:
                            scope_check_passed = True

                # Modify the request
                new_request = modify_request_user_agent(
                    self._helpers,
                    request,
                    self.user_agent_suffix,
                    self.use_browser_user_agent,
                    self.selected_user_agent,
                    self.extension_enabled
                )

                # Update if modified
                if new_request != request:
                    messageinfo.setRequest(new_request)

            except Exception as e:
                print("Error processing proxy request: " + str(e))
                import traceback
                traceback.print_exc()

        except Exception as e:
            print("Main proxy error: " + str(e))
            import traceback
            traceback.print_exc()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Process HTTP messages from all Burp tools (including other extensions)
        This handler applies User-Agent only if it hasn't already been set by the proxy listener
        """
        try:
            # Only process outgoing requests
            if not messageIsRequest:
                return

            # Sync UI values first to ensure we have current settings
            self.sync_current_ui_values()

            # Skip if extension is disabled
            if not self.extension_enabled:
                return

            # Skip if using browser UA and no suffix (nothing to change)
            if self.use_browser_user_agent and (not self.user_agent_suffix or not self.user_agent_suffix.strip()):
                return

            # Skip if using predefined UA but no UA selected and no suffix
            if (not self.use_browser_user_agent and
                not self.selected_user_agent and
                (not self.user_agent_suffix or not self.user_agent_suffix.strip())):
                return

            try:
                request = messageInfo.getRequest()
                request_info = self._helpers.analyzeRequest(request)
                headers = request_info.getHeaders()

                # Skip CONNECT requests
                if headers and headers[0].startswith("CONNECT"):
                    return

                # Check scope if enabled
                if self.apply_to_scope_only:
                    try:
                        service = messageInfo.getHttpService()
                        if service:
                            request_info_with_service = self._helpers.analyzeRequest(service, request)
                            url = request_info_with_service.getUrl()
                            if not self._callbacks.isInScope(url):
                                return
                    except Exception as e:
                        print("HTTP Listener - Scope check failed: {}".format(str(e)))
                        return

                # Get the current User-Agent from the request
                current_ua = None
                for header in headers:
                    if header.lower().startswith("user-agent:"):
                        current_ua = header.split(":", 1)[1].strip()
                        break

                # Determine what the target User-Agent should be
                target_ua = None
                if self.use_browser_user_agent:
                    # Get browser UA and add suffix if needed
                    browser_ua = get_browser_user_agent(self._helpers, self._callbacks)
                    if browser_ua:
                        if self.user_agent_suffix and self.user_agent_suffix.strip():
                            target_ua = browser_ua + " " + self.user_agent_suffix
                        else:
                            target_ua = browser_ua
                    else:
                        # If we can't get browser UA, use current UA as base
                        if current_ua:
                            if self.user_agent_suffix and self.user_agent_suffix.strip():
                                target_ua = current_ua + " " + self.user_agent_suffix
                            else:
                                target_ua = current_ua
                else:
                    # Use predefined UA
                    if self.selected_user_agent:
                        if self.user_agent_suffix and self.user_agent_suffix.strip():
                            target_ua = self.selected_user_agent + " " + self.user_agent_suffix
                        else:
                            target_ua = self.selected_user_agent

                # Only modify if the current UA doesn't match the target UA
                if target_ua and current_ua != target_ua:
                    # Modify the request
                    new_request = modify_request_user_agent(
                        self._helpers,
                        request,
                        self.user_agent_suffix,
                        self.use_browser_user_agent,
                        self.selected_user_agent,
                        self.extension_enabled
                    )

                    # Update if modified
                    if new_request != request:
                        messageInfo.setRequest(new_request)

            except Exception as e:
                print("Error processing HTTP request: " + str(e))
                import traceback
                traceback.print_exc()

        except Exception as e:
            print("Main HTTP listener error: " + str(e))
            import traceback
            traceback.print_exc()

    def extensionUnloaded(self):
        """Handle extension unloading"""
        # Make sure settings are saved
        project_settings = {
            "suffix": self.user_agent_suffix,
            "use_browser_ua": self.use_browser_user_agent,
            "selected_ua": self.selected_user_agent,
            "scope_only": self.apply_to_scope_only,
            "device_filter": self.current_device_filter,
            "browser_filter": self.current_browser_filter,
            "version_filter": self.current_version_filter
            # persist_temp_project is saved separately in user preferences
        }
        save_project_settings(
            self._callbacks,
            self.current_project_name,
            self.SETTING_NAME,
            self.projects_settings,
            project_settings
        )

    def createMenuItems(self, invocation):
        """Create context menu items"""
        try:
            context = invocation.getInvocationContext()

            # Show in multiple contexts where requests are available
            valid_contexts = [
                invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
                invocation.CONTEXT_PROXY_HISTORY,
                invocation.CONTEXT_TARGET_SITE_MAP_TREE,
                invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
                invocation.CONTEXT_SCANNER_RESULTS,
                invocation.CONTEXT_INTRUDER_ATTACK_RESULTS,
                invocation.CONTEXT_SEARCH_RESULTS
            ]

            if context in valid_contexts:
                # Check if we have selected messages
                selected_messages = invocation.getSelectedMessages()
                if selected_messages and len(selected_messages) > 0:
                    menu_list = []

                    # Create ActionListener class for the menu item
                    class CopyUAActionListener(ActionListener):
                        def __init__(self, extension, invocation):
                            self.extension = extension
                            self.invocation = invocation

                        def actionPerformed(self, event):
                            self.extension.copy_user_agent_from_request(self.invocation)

                    # Add menu to set User-Agent from selected request
                    copy_ua_menu = JMenuItem("Set this User-Agent in BB Extension")
                    copy_ua_menu.addActionListener(CopyUAActionListener(self, invocation))
                    menu_list.append(copy_ua_menu)

                    return menu_list

            return None

        except Exception as e:
            print("Error creating context menu: " + str(e))
            return None

    def copy_user_agent_from_request(self, invocation):
        """Set User-Agent from the selected request in the extension"""
        try:
            http_requests = invocation.getSelectedMessages()
            if http_requests and len(http_requests) > 0:
                # Get the first selected request
                request = http_requests[0]
                request_info = self._helpers.analyzeRequest(request)
                headers = request_info.getHeaders()

                # Find User-Agent header
                for header in headers:
                    if header.lower().startswith("user-agent:"):
                        user_agent = header.split(":", 1)[1].strip()

                        # First, switch to predefined User-Agent mode if we're using browser UA
                        if (hasattr(self, 'ui') and self.ui and
                                hasattr(self.ui, 'use_browser_ua_checkbox') and
                                self.ui.use_browser_ua_checkbox):

                            # Switch to predefined mode
                            self.ui.use_browser_ua_checkbox.setSelected(False)
                            self.use_browser_user_agent = False

                            # Enable the combo box and filter field
                            if hasattr(self.ui, 'user_agent_combo') and self.ui.user_agent_combo:
                                self.ui.user_agent_combo.setEnabled(True)
                            if hasattr(self.ui, 'filter_field') and self.ui.filter_field:
                                self.ui.filter_field.setEnabled(True)

                        # Now set the User-Agent in the combo box
                        if (hasattr(self, 'ui') and self.ui and
                                hasattr(self.ui, 'user_agent_combo') and
                                self.ui.user_agent_combo):

                            # Try to find in current combo box model first
                            found = False
                            model = self.ui.user_agent_combo.getModel()
                            for i in range(model.getSize()):
                                if str(model.getElementAt(i)) == user_agent:
                                    self.ui.user_agent_combo.setSelectedIndex(i)
                                    found = True
                                    break

                            # If not found in current model, add it to the all_user_agents list and update combo
                            if not found:
                                # Add to the complete list if not already there
                                if user_agent not in self.all_user_agents:
                                    self.all_user_agents.append(user_agent)

                                # Get current items from combo box
                                current_items = []
                                for i in range(model.getSize()):
                                    item = model.getElementAt(i)
                                    if item and str(item).strip():  # Only add non-empty items
                                        current_items.append(str(item))

                                # Add the new User-Agent if not already in current items
                                if user_agent not in current_items:
                                    current_items.append(user_agent)

                                # Update the combo box model
                                new_model = DefaultComboBoxModel(current_items)
                                self.ui.user_agent_combo.setModel(new_model)

                                # Select the new User-Agent
                                self.ui.user_agent_combo.setSelectedItem(user_agent)

                            # Update internal state
                            self.selected_user_agent = user_agent

                        # Save the changes
                        self.schedule_auto_save()
                        return

                print("No User-Agent header found in request")
            else:
                print("No requests selected")

        except Exception as e:
            print("Error copying User-Agent from request: " + str(e))
            import traceback
            traceback.print_exc()

    def getActionName(self):
        """Return the name of this session handling action"""
        return "BB User Agent Modifier"

    def performAction(self, currentRequest, macroItems):
        """Perform the session handling action - modify User-Agent"""
        if not self.extension_enabled:
            return

        try:
            # Force sync current UI values
            self.sync_current_ui_values()

            request = currentRequest.getRequest()
            request_info = self._helpers.analyzeRequest(request)
            url = request_info.getUrl()

            # Check scope if enabled
            if self.apply_to_scope_only:
                if not self._callbacks.isInScope(url):
                    return

            # Modify the request
            modified_request = modify_request_user_agent(
                self._helpers,
                request,
                self.user_agent_suffix,
                self.use_browser_user_agent,
                self.selected_user_agent,
                self.extension_enabled
            )

            # Update the request if it was modified
            if modified_request != request:
                currentRequest.setRequest(modified_request)

        except Exception as e:
            print("SESSION: Error in performAction: " + str(e))

    def getTabCaption(self):
        """Return the tab caption"""
        return self.NAME

    def getUiComponent(self):
        """Return the UI component"""
        # Create the UI if it hasn't been created yet (this should not happen as we create in registerExtenderCallbacks)
        if not self.ui:
            self.ui = ConfigTab(self)

        return self.ui.create_ui()
