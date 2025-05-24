# -*- coding: utf-8 -*-
"""
Utility functions for working with User-Agents

This module contains core User-Agent processing functions:
- get_browser_user_agent: Extracts User-Agent from proxy history (no validation)
- modify_request_user_agent: Main function for modifying HTTP requests (only if UA exists)
- filter_user_agents: Filters User-Agent lists with keywords

Note: User agent loading functionality has been moved to utils/user_agent_manager.py
This file now contains only utility functions for processing and filtering user agents.
The is_likely_browser_ua function has been removed - no validation is performed on User-Agents.
"""
import re
from java.awt import Color


def filter_user_agents(user_agents, filter_text):
    """
    Filter User-Agents list based on multiple keywords
    
    Args:
        user_agents: Complete list of User-Agents
        filter_text: Filter text with multiple keywords (space-separated)
        
    Returns:
        list: Filtered list of User-Agents that contain ALL keywords
    """
    if not filter_text or not filter_text.strip():
        return user_agents
    
    # Split the filter text into individual keywords and convert to lowercase
    keywords = [keyword.strip().lower() for keyword in filter_text.split() if keyword.strip()]
    
    if not keywords:
        return user_agents
    
    # Filter user agents that contain ALL keywords (case-insensitive)
    filtered = []
    for ua in user_agents:
        ua_lower = ua.lower()
        # Check if ALL keywords are present in the user agent
        if all(keyword in ua_lower for keyword in keywords):
            filtered.append(ua)
    
    return filtered


def get_browser_user_agent(helpers, callbacks):
    """
    Try to get the User-Agent from browser requests
    Returns None if no requests found
    
    Args:
        helpers: Burp Suite helpers object
        callbacks: Burp Suite callbacks object
        
    Returns:
        str or None: User-Agent string or None if not found
    """
    try:
        proxy_history = callbacks.getProxyHistory()
        if proxy_history and len(proxy_history) > 0:
            check_count = min(50, len(proxy_history))
            
            for i in range(check_count):
                try:
                    request = proxy_history[i]
                    request_info = helpers.analyzeRequest(request)
                    headers = request_info.getHeaders()
                    
                    for header in headers:
                        if header.lower().startswith("user-agent:"):
                            ua = header.split(":", 1)[1].strip()
                            # Return the first User-Agent found, no validation needed
                            if ua and len(ua.strip()) > 0:
                                return ua
                            break
                            
                except Exception:
                    continue
        
        return None
        
    except Exception as e:
        print("Error getting User-Agent: " + str(e))
        return None


def modify_request_user_agent(helpers, request, user_agent_suffix, use_browser_user_agent, selected_user_agent, extension_enabled=True):
    """
    Modify a request's User-Agent header
    
    Args:
        helpers: Burp Suite helpers object
        request: HTTP request to modify
        user_agent_suffix: Suffix to add to User-Agent
        use_browser_user_agent: Whether to use browser User-Agent
        selected_user_agent: Selected predefined User-Agent (when not using browser UA)
        extension_enabled: Whether the extension is enabled
        
    Returns:
        bytes: Modified request (or original if no changes needed)
    """
    try:
        if not extension_enabled:
            return request
        
        request_info = helpers.analyzeRequest(request)
        headers = request_info.getHeaders()
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]
        
        # Find User-Agent header
        has_user_agent = False
        original_user_agent = None
        modified_headers = list(headers)
        
        for i in range(len(headers)):
            header = headers[i]
            if header.lower().startswith("user-agent:"):
                has_user_agent = True
                original_user_agent = header.split(":", 1)[1].strip()
                
                # Determine base User-Agent to use
                if use_browser_user_agent:
                    # Use the original User-Agent from the request
                    base_ua = original_user_agent
                else:
                    # Use selected predefined User-Agent if available, otherwise keep original
                    if selected_user_agent and selected_user_agent != "Select a user agent or directly type a user agent you want to use":
                        base_ua = selected_user_agent
                    else:
                        base_ua = original_user_agent
                
                # Determine final User-Agent
                new_user_agent = base_ua
                
                # Add suffix if provided and not already present
                if user_agent_suffix and user_agent_suffix.strip():
                    suffix_clean = user_agent_suffix.strip()
                    # Only add suffix if it's not already at the end of the base User-Agent
                    if not base_ua.endswith(suffix_clean):
                        new_user_agent = "{} {}".format(base_ua, suffix_clean)
                
                # Only modify if the new User-Agent is different from the original
                if new_user_agent != original_user_agent:
                    # Replace the header
                    new_header = "User-Agent: {}".format(new_user_agent)
                    modified_headers[i] = new_header
                    
                    # Build and return modified request
                    try:
                        new_request = helpers.buildHttpMessage(modified_headers, body)
                        return new_request
                    except Exception as e:
                        print("Error rebuilding request: " + str(e))
                        return request
                else:
                    # No change needed
                    return request
                    
                break
        
        # If no User-Agent header exists and we have a suffix or predefined UA, add one
        if not has_user_agent:
            if not use_browser_user_agent and selected_user_agent and selected_user_agent != "Select a user agent or directly type a user agent you want to use":
                # Add User-Agent header with selected predefined UA
                new_user_agent = selected_user_agent
                if user_agent_suffix and user_agent_suffix.strip():
                    new_user_agent = "{} {}".format(selected_user_agent, user_agent_suffix.strip())
                    
                # Add the new header
                modified_headers.append("User-Agent: {}".format(new_user_agent))
                
                # Build and return modified request
                try:
                    new_request = helpers.buildHttpMessage(modified_headers, body)
                    return new_request
                except Exception as e:
                    print("Error rebuilding request: " + str(e))
                    return request
        
        # No modification needed
        return request
            
    except Exception as e:
        print("Error modifying request: " + str(e))
        return request
