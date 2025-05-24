# -*- coding: utf-8 -*-
"""
User-Agent management utilities
Handles downloading, caching, and loading of user agent lists
"""

import os
import json
import threading


class UserAgentManager:
    """Manages user agent lists - downloading, caching, and loading"""
    
    REPO_URL = "https://raw.githubusercontent.com/intoli/user-agents/main/src/user-agents.json.gz"
    
    def __init__(self, extension):
        """
        Initialize the UserAgent manager
        
        Args:
            extension: Reference to main extension object
        """
        self.extension = extension
        self._file_path = self._get_json_file_path()
    
    def _get_json_file_path(self):
        """Get the path to the user-agents.json file"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.dirname(current_dir)
        return os.path.join(root_dir, "user-agents.json")
    
    def load_user_agents(self):
        """
        Load user agents from file or download if needed
        
        Returns:
            List of user agent strings
        """
        try:
            if os.path.exists(self._file_path):
                user_agents = self._load_from_file()
                if user_agents:
                    # Start background update for existing file
                    self._start_background_update(user_agents)
                    return user_agents
            
            # File doesn't exist or is empty, download immediately
            print("User agents file not found, downloading...")
            downloaded_agents = self._download_user_agents()
            
            # Start background update for fresh download as well
            if downloaded_agents and len(downloaded_agents) > 0:
                self._start_background_update(downloaded_agents)
            
            return downloaded_agents
            
        except Exception as e:
            print("Error loading user agents: " + str(e))
            return self._download_user_agents()
    
    def _load_from_file(self):
        """Load user agents from JSON file"""
        try:
            with open(self._file_path, 'r') as f:
                user_agents = json.load(f)
                
            if not user_agents:
                return None
                
            # Always return sorted list
            return sorted(user_agents)
            
        except Exception as e:
            print("Error reading user agents file: " + str(e))
            return None
    
    def _download_user_agents(self, silent=False):
        """
        Download user agents from repository
        
        Args:
            silent (bool): If True, suppress print messages for background updates
        
        Returns:
            List of user agent strings
        """
        try:
            import urllib2
            import gzip
            import StringIO
            
            if not silent:
                print("Downloading user agents from repository...")
            
            response = urllib2.urlopen(self.REPO_URL, timeout=15)
            compressed_data = response.read()
            
            # Decompress gzip content
            compressed_stream = StringIO.StringIO(compressed_data)
            gzip_file = gzip.GzipFile(fileobj=compressed_stream)
            json_data = gzip_file.read()
            
            # Parse JSON and extract user agents
            user_agents_data = json.loads(json_data)
            user_agents = []
            
            for item in user_agents_data:
                if 'userAgent' in item:
                    user_agent = item['userAgent']
                    if user_agent not in user_agents:
                        user_agents.append(user_agent)
            
            # Sort and save
            user_agents.sort()
            
            if user_agents:
                self._save_to_file(user_agents)
                if not silent:
                    print("Downloaded {} user agents".format(len(user_agents)))
                return user_agents
            else:
                if not silent:
                    print("No user agents found in repository")
                return ["No user agents available - check internet connection"]
                
        except Exception as e:
            if not silent:
                print("Error downloading user agents: " + str(e))
            return ["Loading user agents failed - check internet connection"] if not silent else None
    
    def _save_to_file(self, user_agents):
        """Save user agents to JSON file"""
        try:
            # Always sort before saving
            sorted_user_agents = sorted(user_agents)
            
            with open(self._file_path, 'w') as f:
                json.dump(sorted_user_agents, f, indent=2)
                
        except Exception as e:
            print("Error saving user agents to file: " + str(e))
    
    def _start_background_update(self, current_user_agents):
        """Start background update thread"""
        def update_background():
            try:
                print("Starting background user agents update...")
                new_user_agents = self._download_user_agents(silent=True)
                if new_user_agents and len(new_user_agents) > 0:
                    if (len(new_user_agents) != len(current_user_agents) or 
                        new_user_agents != current_user_agents):
                        print("User agents updated in background - {} agents available".format(len(new_user_agents)))
                    else:
                        print("Background update completed - user agents are up to date")
                else:
                    print("Background update failed - no new user agents received")
                    
            except Exception as e:
                print("Background update error: " + str(e))
        
        threading.Thread(target=update_background).start()
