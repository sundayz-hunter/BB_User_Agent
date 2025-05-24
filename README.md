<h1 align="center">BB User Agent</h1>

<p align="center">
  <img src=".github/images/Logo Portswigger.png" alt="PortSwigger Logo" width="150">
</p>

<p align="center">A Burp Suite extension for managing User-Agent headers in bug bounty testing. <br> This extension allows security testers to customize User-Agent headers with custom suffixes and choose from thousands of real browser User-Agents, with per-project settings management.</p>

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## ✨ Features

- **Custom BugBounty Suffix**: Add your own suffix to User-Agent headers (perfect for bug bounty identification)
- **Real Browser User-Agents**: Use your default browser user agent or access thousands of real browser User-Agents from the Intoli dataset
- **Smart Filtering**: Filter User-Agents by device type (Windows, Mac, Linux, iPhone, iPad, Android), browser (Chrome, Firefox, Safari), and version
- **Per-Project Settings**: Automatically save different configurations for each Burp project
- **Scope-Aware**: Apply changes only to in-scope requests
- **Context Menu Integration**: Set User-Agent to the extension from any request with right-click menu 

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 🔧 Installation

1. Download the extension files from the repository
2. In Burp Suite, go to **Extensions** > **Add**
3. Select **Python** as the extension type
4. Choose the `main.py` file as the entry point
5. The extension will appear as a new tab called **"BB User Agent"**

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## ⚙️ Configuration

### User Agent Sources

The extension supports two User-Agent sources:

#### Browser User-Agent (Default)
- Use the User-Agent from your browser's requests
- Ideal for maintaining consistency with your actual browser

#### Predefined User-Agents
- Access to thousands of real browser User-Agents from the Intoli dataset
- Automatically downloads and save the latest User-Agent database
- Updates in the background to ensure you have the latest browser versions

### Filtering Options

- Device Type Filters
- Browser Filters
- Version Filters

### BugBounty Suffix

Add a custom suffix to your User-Agent headers for:
- Bug bounty program identification
- Researcher attribution
- Custom tracking and monitoring
- Program-specific requirements

Example: `- BugBounty by YourHandle`

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 🚀 Usage

### Basic Setup

1. Open the **"BB User Agent"** tab in Burp Suite
2. Enable the extension using the **Enable/Disable** button
3. Configure your BugBounty suffix in the text field
4. Choose between browser User-Agent or predefined User-Agents
5. Set the **"Apply only to in-scope requests"** option as needed

### Advanced Filtering

1. **Filter by Device**: Click device type buttons to show only specific platforms
2. **Filter by Browser**: Select browser-specific User-Agents 
3. **Filter by Version**: Choose specific browser versions
4. **Keyword Search**: Use the search field to find specific User-Agents (e.g., "chrome 120")

### Custom User-Agent Input

You can **directly type or paste any User-Agent** of your choice:

1. **Switch to Predefined Mode**: Uncheck "Use default browser User-Agent"
2. **Direct Input**: Click in the User-Agent dropdown field and directly type or paste your custom User-Agent


### Project Management

- Settings are automatically saved per Burp project
- Switch between projects to maintain different configurations
- Enable **"Save settings for temporary project"** to persist settings in temporary projects

### Context Menu Usage

1. Right-click on any HTTP request in Proxy History or other tools
2. Select **"Set this User-Agent in BB Extension"** to extract and configure that User-Agent
3. The extracted User-Agent will be automatically selected and configured in the extension

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 💡 Tips

### 🔍 Viewing Modified Requests (Important!)

To properly see and work with modified User-Agent headers:

1. **Set Proxy History Display to "Edited"**:
   - In Proxy > HTTP History, change the **Message display** dropdown from "Original" to **"Edited"**
   - This allows you to see the actual modified requests with your custom User-Agent headers

<p align="center">
  <img src=".github/images/proxy-history-edited.png" alt="Proxy History Edited View" width="600">
</p>

2. **Send Modified Requests to Other Tools**:
   - Right-click on requests in Proxy History (with "Edited" view enabled)
   - Send to Repeater, Intruder, or other tools to use the modified User-Agent
   - The tools will receive the request with your custom User-Agent configuration

3. **Verify Modifications**:
   - Check the request headers in Repeater to confirm User-Agent changes
   - Use the "Raw" tab to see the complete modified request
   - Compare with original requests to validate suffix addition

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 📝 User-Agent Database

The extension uses the high-quality User-Agent database from [Intoli](https://github.com/intoli/user-agents):

- **Automatic Updates**: Downloads the latest User-Agents in the background
- **Real Browser Data**: All User-Agents are from real browser instances
- **Comprehensive Coverage**: Includes all major browsers and platforms

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 👨‍💻 Development

- Written in Python for Burp Suite's Jython environment
- Modular architecture for easy maintenance and extension

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with proper testing
4. Submit a pull request with a clear description

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 📂 Project Structure

```
BB User Agent/
├── main.py                    # Main extension entry point
├── user-agents.json           # Cached User-Agent database
├── ui/                        # User interface components
│   ├── __init__.py
│   └── config_tab.py          # Main configuration tab UI
├── utils/                     # Utility modules
│   ├── __init__.py
│   ├── browser_utils.py       # Advanced browser detection and filtering utilities
│   ├── user_agent_manager.py  # User-Agent downloading and caching
│   ├── user_agent_utils.py    # Core User-Agent processing functions
│   ├── project_utils.py       # Project settings management
│   ├── placeholder_utils.py   # Placeholder text management 
│   ├── ui_utils.py            # UI helper functions
│   └── listeners.py           # Event listeners for UI components
└── .github/                   # GitHub configuration
```

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 📋 Requirements

- **Burp Suite Professional or Community Edition**
- **Python/Jython support**

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 📄 License

This project is open source and available under the MIT License.

![-----------------------------------------------------](https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png)

## 🙏 Acknowledgments

- **PortSwigger** for the excellent Burp Suite platform
- **Intoli** for maintaining the comprehensive User-Agent database
- The **bug bounty community** for feedback and testing
