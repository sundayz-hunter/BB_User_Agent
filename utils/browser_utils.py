# -*- coding: utf-8 -*-
"""
Browser detection utilities for User-Agent filtering
"""

class BrowserDetector:
    """Handles browser detection and filtering logic"""
    
    # Simplified and focused browser keywords
    BROWSER_PATTERNS = {
        "Chrome": ["Chrome/", "CriOS/"],  # Chrome + Chrome for iOS
        "Firefox": ["Firefox/"],
        "Safari": ["Safari/"],
        "GSA": ["GSA/"]  # Google Search App
    }
    
    @classmethod
    def get_available_browsers(cls, user_agents):
        """
        Get a list of browsers that have user agents available
        
        Args:
            user_agents: List of user agent strings
            
        Returns:
            List of browser names including "All" in correct order
        """
        if not user_agents:
            return ["All"]
            
        available_browsers = ["All"]
        
        # Define the desired order explicitly
        desired_order = ["Chrome", "Firefox", "Safari", "GSA"]
        
        # Add browsers in the specified order if they have user agents
        for browser_name in desired_order:
            if browser_name in cls.BROWSER_PATTERNS:
                patterns = cls.BROWSER_PATTERNS[browser_name]
                # Check if at least one user agent matches this browser
                if any(cls._matches_browser(ua, browser_name, patterns) for ua in user_agents):
                    available_browsers.append(browser_name)
                
        return available_browsers
    
    @classmethod
    def _matches_browser(cls, user_agent, browser_name, patterns):
        """
        Check if user agent matches a specific browser
        
        Args:
            user_agent: User agent string to check
            browser_name: Name of browser to check for
            patterns: List of patterns to match
            
        Returns:
            bool: True if user agent matches browser
        """
        if browser_name == "Safari":
            # Safari: must contain Safari but NOT Chrome/Chromium/CriOS/GSA
            return (any(pattern in user_agent for pattern in patterns) and 
                   "Chrome" not in user_agent and 
                   "Chromium" not in user_agent and 
                   "CriOS" not in user_agent and 
                   "GSA" not in user_agent)
        elif browser_name == "GSA":
            # GSA: must contain GSA pattern
            return any(pattern in user_agent for pattern in patterns)
        else:
            # Standard pattern matching for other browsers
            return any(pattern in user_agent for pattern in patterns)
    
    @classmethod
    def filter_by_browser(cls, user_agents, browser_name):
        """
        Filter user agents by browser type
        
        Args:
            user_agents: List of user agent strings
            browser_name: Browser name to filter by
            
        Returns:
            List of filtered user agent strings
        """
        if browser_name == "All" or browser_name not in cls.BROWSER_PATTERNS:
            return user_agents
            
        patterns = cls.BROWSER_PATTERNS[browser_name]
        return [ua for ua in user_agents 
                if cls._matches_browser(ua, browser_name, patterns)]
