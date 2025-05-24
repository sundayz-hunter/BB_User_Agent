# -*- coding: utf-8 -*-
"""
UI utility functions for BB User Agent extension
"""

from java.awt import FlowLayout, Font, Dimension, Color
from javax.swing import JPanel, JLabel, JSeparator, BorderFactory, UIManager


def create_section_title(parent_panel, title_text):
    """Create a section title with consistent styling"""
    titlePanel = JPanel(FlowLayout(FlowLayout.CENTER))
    titlePanel.setBackground(parent_panel.getBackground())

    titleLabel = JLabel(title_text)
    
    # Use Burp Suite colors - simple section title color
    burp_background = UIManager.getColor("Panel.background")
    if burp_background:
        red = burp_background.getRed()
        green = burp_background.getGreen()
        blue = burp_background.getBlue()
        brightness = (red + green + blue) / 3
        
        if brightness < 128:  # Dark theme
            titleLabel.setForeground(Color(173, 216, 230))  # Light blue
        else:  # Light theme
            titleLabel.setForeground(Color(70, 130, 180))   # Steel blue
    else:
        titleLabel.setForeground(Color(173, 216, 230))  # Default light blue
    
    titleLabel.setFont(Font(titleLabel.getFont().getName(), Font.BOLD, 16))
    titlePanel.add(titleLabel)

    return titlePanel


def create_separator(parent_panel, width=1050):
    """Create a separator with consistent styling"""
    separatorPanel = JPanel(FlowLayout(FlowLayout.CENTER))
    separatorPanel.setBackground(parent_panel.getBackground())
    separator = JSeparator()
    separator.setPreferredSize(Dimension(width, 1))
    
    # Use Burp Suite colors - simple separator color
    burp_background = UIManager.getColor("Panel.background")
    if burp_background:
        red = burp_background.getRed()
        green = burp_background.getGreen()
        blue = burp_background.getBlue()
        brightness = (red + green + blue) / 3
        
        if brightness < 128:  # Dark theme
            separator.setForeground(Color(100, 100, 100))
        else:  # Light theme
            separator.setForeground(Color(200, 200, 200))
    else:
        separator.setForeground(Color(100, 100, 100))  # Default gray
    
    separatorPanel.add(separator)
    return separatorPanel
