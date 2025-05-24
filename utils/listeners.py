# -*- coding: utf-8 -*-
"""
Event listeners for BB User Agent extension
"""

from java.awt.event import ActionListener, KeyAdapter, KeyEvent
from javax.swing.event import DocumentListener

class UAFilterKeyAdapter(KeyAdapter):
    """Key adapter for a filtering User-Agent list"""
    
    def __init__(self, extension):
        """
        Initialize key adapter
        
        Args:
            extension: Extension object with filter_user_agents method
        """
        self.extension = extension
        
    def keyReleased(self, e):
        # Check if the filter field contains placeholder text
        if (hasattr(self.extension, 'ui') and 
            self.extension.ui and 
            hasattr(self.extension.ui, 'filter_field') and 
            self.extension.ui.filter_field):
            
            current_text = self.extension.ui.filter_field.getText()
            field_color = self.extension.ui.filter_field.getForeground()
            
            from java.awt import Color
            
            # If it's placeholder text (gray color) or the placeholder text itself, don't filter
            if (field_color == Color.GRAY or 
                current_text == "Enter keywords to filter User-Agents (e.g., chrome 137)" or
                not current_text.strip()):
                # Reset to show all user agents when placeholder is active
                if hasattr(self.extension, 'all_user_agents') and self.extension.all_user_agents:
                    self.extension.filter_user_agents_combo_with_text("")
            else:
                # Use the actual user input for filtering
                self.extension.filter_user_agents_combo_with_text(current_text)

class SuffixDocumentListener(DocumentListener):
    """Document listener for User-Agent suffix field"""
    
    def __init__(self, extension):
        """
        Initialize document listener
        
        Args:
            extension: Extension object with on_suffix_changed method
        """
        self.extension = extension
        
    def insertUpdate(self, e):
        self.update()
        
    def removeUpdate(self, e):
        self.update()
        
    def changedUpdate(self, e):
        self.update()
        
    def update(self):
        # Get the current text from suffix field
        if (hasattr(self.extension, 'ui') and 
            self.extension.ui and 
            hasattr(self.extension.ui, 'user_agent_suffix_field') and 
            self.extension.ui.user_agent_suffix_field):
            
            current_text = self.extension.ui.user_agent_suffix_field.getText()
            
            # Check if it's placeholder text (gray color indicates placeholder)
            field_color = self.extension.ui.user_agent_suffix_field.getForeground()
            from java.awt import Color
            placeholder_color = Color.GRAY
            
            # Only consider it placeholder if color matches AND text is exact placeholder text
            if (field_color == placeholder_color and 
                current_text == "Enter your bugbounty suffix here"):
                # If it's placeholder text, treat as empty suffix
                self.extension.user_agent_suffix = ""
            else:
                # It's real user input - accept any text including single characters
                self.extension.user_agent_suffix = current_text
            
            # Check if we should skip saving for temporary projects
            current_project_is_temp = self.extension.current_project_name == "Temporary Project"
            if current_project_is_temp and not self.extension.persist_temp_project:
                return
        
        # Update immediately
        self.extension.on_suffix_changed()

class AutoSaveDocumentListener(DocumentListener):
    """Document listener for auto-save functionality"""
    
    def __init__(self, extension):
        """
        Initialize document listener
        
        Args:
            extension: Extension object with schedule_auto_save method
        """
        self.extension = extension
        
    def insertUpdate(self, e):
        self.update()
        
    def removeUpdate(self, e):
        self.update()
        
    def changedUpdate(self, e):
        self.update()
        
    def update(self):
        # Create a small delay to avoid saving on every keystroke
        self.extension.schedule_auto_save()

class ComboDocumentListener(DocumentListener):
    """Document listener for User-Agent combo box text field"""
    
    def __init__(self, extension):
        """
        Initialize document listener
        
        Args:
            extension: Extension object with update methods
        """
        self.extension = extension
        
    def insertUpdate(self, e):
        self.update()
        
    def removeUpdate(self, e):
        self.update()
        
    def changedUpdate(self, e):
        self.update()
        
    def update(self):
        # Update the selected user agent and display when text is typed
        if (hasattr(self.extension, 'ui') and 
            self.extension.ui and 
            hasattr(self.extension.ui, 'user_agent_combo') and 
            self.extension.ui.user_agent_combo):
            
            # Get the editor component and its text
            editor = self.extension.ui.user_agent_combo.getEditor()
            if editor and hasattr(editor, 'getEditorComponent'):
                text_field = editor.getEditorComponent()
                if text_field:
                    typed_text = text_field.getText()
                    if typed_text:
                        # Update the selected user agent
                        self.extension.selected_user_agent = typed_text
                        # Schedule auto-save
                        self.extension.schedule_auto_save()

class DeviceFilterActionListener(ActionListener):
    """Action listener for device filter buttons"""
    
    def __init__(self, extension, device_type):
        """
        Initialize action listener
        
        Args:
            extension: Extension object with filter_by_device_type method
            device_type: The type of device to filter for
        """
        self.extension = extension
        self.device_type = device_type
    
    def actionPerformed(self, e):
        # Call the filter method on the extension
        self.extension.filter_by_device_type(self.device_type)

class BrowserFilterActionListener(ActionListener):
    """Action listener for browser filter buttons"""
    
    def __init__(self, extension, browser_type):
        """
        Initialize action listener
        
        Args:
            extension: Extension object with filter_by_browser_type method
            browser_type: The type of browser to filter for
        """
        self.extension = extension
        self.browser_type = browser_type
    
    def actionPerformed(self, e):
        # Call the filter method on the extension
        self.extension.filter_by_browser_type(self.browser_type)

class VersionFilterActionListener(ActionListener):
    """Action listener for version filter combo box"""
    
    def __init__(self, extension):
        """
        Initialize action listener
        
        Args:
            extension: Extension object with filter_by_version method
        """
        self.extension = extension
    
    def actionPerformed(self, e):
        # Get the selected version from the combo box
        if e.getSource():
            selected_version = e.getSource().getSelectedItem()
            # Call the filter method on the extension
            self.extension.filter_by_version(selected_version)
