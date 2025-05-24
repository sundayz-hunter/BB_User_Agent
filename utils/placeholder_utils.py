# -*- coding: utf-8 -*-
"""
Placeholder utility functions for text fields
"""

from java.awt.event import FocusListener
from java.awt import Color
from javax.swing import UIManager


class PlaceholderFocusListener(FocusListener):
    """Focus listener to handle placeholder text behavior"""
    
    def __init__(self, field, placeholder_text, extension=None, field_type=None):
        self.field = field
        self.placeholder_text = placeholder_text
        self.is_placeholder = True
        self.extension = extension
        self.field_type = field_type  # 'suffix' or 'filter'
        
    def focusGained(self, e):
        if self.is_placeholder:
            self.field.setText("")
            
            # Use Burp Suite foreground color
            burp_foreground = UIManager.getColor("Panel.foreground")
            if burp_foreground:
                self.field.setForeground(burp_foreground)
            else:
                self.field.setForeground(Color.WHITE)
            
            self.is_placeholder = False
            
            # If it's the suffix field, update the extension
            if self.extension and self.field_type == 'suffix':
                self.extension.user_agent_suffix = ""
                self.extension.on_suffix_changed()
            # If it's the filter field, reset to show all user agents
            elif self.extension and self.field_type == 'filter':
                if hasattr(self.extension, 'filter_user_agents_combo_with_text'):
                    self.extension.filter_user_agents_combo_with_text("")
        
    def focusLost(self, e):
        text_content = self.field.getText()
        if not text_content or not text_content.strip():
            self.field.setText(self.placeholder_text)
            self.field.setForeground(Color.GRAY)  # Simple gray for placeholder
            self.is_placeholder = True
            
            # If it's the suffix field, update the extension
            if self.extension and self.field_type == 'suffix':
                self.extension.user_agent_suffix = ""
                self.extension.on_suffix_changed()
            # If it's the filter field, reset to show all user agents
            elif self.extension and self.field_type == 'filter':
                if hasattr(self.extension, 'filter_user_agents_combo_with_text'):
                    self.extension.filter_user_agents_combo_with_text("")
        else:
            # Field has content, keep it as real text (not placeholder)
            self.is_placeholder = False
            if self.extension and self.field_type == 'suffix':
                self.extension.user_agent_suffix = text_content
                self.extension.on_suffix_changed()

def add_placeholder(text_field, placeholder_text, initial_value="", extension=None, field_type=None):
    """Add placeholder functionality to a text field"""
    if not initial_value:
        # Set placeholder initially
        text_field.setText(placeholder_text)
        text_field.setForeground(Color.GRAY)  # Simple gray for placeholder
        
        # Add focus listener
        placeholder_listener = PlaceholderFocusListener(text_field, placeholder_text, extension, field_type)
        text_field.addFocusListener(placeholder_listener)
        
        return placeholder_listener
    else:
        # Set actual value
        text_field.setText(initial_value)
        
        # Use Burp Suite foreground color
        burp_foreground = UIManager.getColor("Panel.foreground")
        if burp_foreground:
            text_field.setForeground(burp_foreground)
        else:
            text_field.setForeground(Color.WHITE)
        
        return None
