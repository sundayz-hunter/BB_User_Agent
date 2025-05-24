# -*- coding: utf-8 -*-
"""
Utility functions for working with Burp Suite projects and settings
"""

import os
import re
import json
import java.io.File as File
from java.lang import System
import java.awt.Frame as Frame
import java.awt.Window as Window

def get_project_name(callbacks):
    """
    Determine the current Burp project name from the window title
    Returns "Temporary Project" for temporary projects, otherwise project name
    
    Args:
        callbacks: Burp Suite callbacks object
        
    Returns:
        str: Name of the current project
    """
    # Try to enumerate all frames to find Burp's window
    try:
        frames = Frame.getFrames()
        
        for frame in frames:
            try:
                if frame.isVisible():
                    title = frame.getTitle()
                    
                    if "Burp Suite" in title:
                        return extract_project_name_from_title(title)
            except:
                continue
    except Exception as e:
        print("Error enumerating frames: " + str(e))
    
    # Default fallback - assume temporary project if we can't find anything
    return "Temporary Project"

def extract_project_name_from_title(title):
    """
    Extract project name from Burp Suite window title
    
    Args:
        title: Window title string
        
    Returns:
        str: Project name
    """
    if not title:
        return "Temporary Project"
    
    # Check for temporary project first (most common pattern)
    if "Temporary Project" in title:
        return "Temporary Project"
    
    # Pattern for titles like "Burp Suite Professional v2025.5 - ProjectName"
    # This captures everything after the last " - "
    if " - " in title and "Burp Suite" in title:
        # Split by " - " and take the last part
        parts = title.split(" - ")
        if len(parts) >= 2:
            project_name = parts[-1].strip()
            
            # If the last part is "Temporary Project", return it
            if project_name == "Temporary Project":
                return "Temporary Project"
            
            # If it's not empty and doesn't look like a version number
            if project_name and not re.match(r'^v?\d+\.\d+', project_name):
                return project_name
    
    # Pattern for titles with "Project:" (legacy format if it exists)
    match = re.search(r'Project:\s*([^-\n]+)', title)
    if match:
        project_name = match.group(1).strip()
        if project_name:  # Removed "Default Project" check since it doesn't exist
            return project_name
    
    # If we can't extract a meaningful project name, it's likely temporary
    return "Temporary Project"

def load_project_settings(callbacks, current_project_name, setting_name):
    """
    Load settings for the current project
    
    Args:
        callbacks: Burp Suite callbacks object
        current_project_name: Name of the current project
        setting_name: Name of the setting to load
        
    Returns:
        dict: Project settings for the current project
        dict: All projects settings
    """
    projects_settings = {}
    # First load all projects settings
    settings_json = callbacks.loadExtensionSetting(setting_name)
    if settings_json:
        try:
            projects_settings = json.loads(settings_json)
        except:
            projects_settings = {}
    
    # Default settings
    default_settings = {
        "suffix": "",
        "use_browser_ua": True,
        "selected_ua": None,
        "scope_only": True
    }
    
    # Load settings for current project
    if current_project_name in projects_settings:
        project_settings = projects_settings[current_project_name]
        # Ensure all expected keys exist with fallback to defaults
        for key in default_settings:
            if key not in project_settings:
                project_settings[key] = default_settings[key]
        return project_settings, projects_settings
    else:
        # Return defaults if no settings for this project
        return default_settings, projects_settings

def save_project_settings(callbacks, current_project_name, setting_name, projects_settings, project_settings):
    """
    Save settings for the current project
    
    Args:
        callbacks: Burp Suite callbacks object
        current_project_name: Name of the current project
        setting_name: Name of the setting to save
        projects_settings: All projects settings
        project_settings: Current project settings
        
    Returns:
        bool: Success or failure
    """
    try:
        # Special handling for Temporary Project - never save if it shouldn't persist
        if current_project_name == "Temporary Project":
            # Try to get the extension instance to check persist_temp_project
            # This is a bit of a hack, but necessary to access the setting
            preference_key = "bb_user_agent_persist_temp"
            preference_value = callbacks.loadExtensionSetting(preference_key)
            persist_temp_project = preference_value == "true" if preference_value else False
            
            if not persist_temp_project:
                return False
        
        # Update project settings
        projects_settings[current_project_name] = project_settings
        
        # Save all projects settings
        settings_json = json.dumps(projects_settings)
        callbacks.saveExtensionSetting(setting_name, settings_json)
        return True
    except Exception as e:
        print("Error saving project settings: " + str(e))
        return False
