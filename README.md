# Phishing URL Monitoring

A Python-based SOC tool for monitoring and analyzing phishing URLs with a Tkinter GUI. Features include URL status checking, redirect tracing, risk analysis, VirusTotal and URLScan integration, auto-monitoring, and optional email notifications for status changes.

## Features
- **URL Monitoring**: Check URLs for active/inactive status and track redirect chains.
- **Risk Analysis**: Score URLs based on suspicious patterns (e.g., TLDs, keywords).
- **API Integrations**: Query VirusTotal and URLScan for external threat intelligence.
- **Auto-Monitoring**: Continuously check URLs in the background without GUI freezes.
- **Telegram Notifications**: Send telegram messages for status changes (e.g., Inactive → Active) when enabled.
- **Database Storage**: Persist URL data in SQLite with caching for API results.
- **Export Options**: Export URL history as CSV or JSON.
- **GUI**: User-friendly interface with progress bar, status bar, and detailed URL views.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/sauron666/Phishing-URL-Monitoring.git
   cd Phishing-URL-Monitoring
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `config.json` file (see [Configuration](#configuration)).

## Configuration
Create a `config.json` file in the project root with the following structure:
```json
{
  "api_keys": {
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "urlscan": "YOUR_URLSCAN_API_KEY"
  },
  "smtp_config": {
    "host": "smtp.example.com",
    "port": "587",
    "user": "your_email@example.com",
    "password": "your_password",
    "recipient": "recipient@example.com"
  },
  "telegram_config": {
    "bot_token": "YOUR_API_TOKEN",
    "chat_ids": [
      "YOUR_CHAT_ID",
      "YOUR_CHAT_ID"
	]
	},
  "check_interval": 3600,
  "cache_ttl": 86400,
  "batch_size": 10,
  "risk_colors": {
    "High": "#ffcccc",
    "Medium": "#ffffcc",
    "Low": "#ccffcc"
  }
}
```
- **API Keys**: Obtain keys from [VirusTotal](https://www.virustotal.com/) and [URLScan](https://urlscan.io/). Leave empty if not using these features.
- To activate Telegram notifications, we need to create a Telegram bot. Search for @BotFather in Telegram and send it /newbot. Enter a name and a username for the bot. You will receive a token (example: 123456789:ABCdefGHIjkLmNoPQRstuVWxyz123456789)
- To get the Chat ID of the recipients – For a group, we add the bot to the group as an admin. Send a message in the group. Use the API:
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
and you will see something like:

"chat": {
  "id": -123456789,
  "title": "Your Group Name",
  ...
}
For a personal user – Write to the bot from your main account with /start
Use getUpdates as above. You will get:

"chat": {
  "id": 123456789,
  "first_name": "",
  ...
}


- **Other Settings**:
  - `check_interval`: Auto-check interval in seconds (default: 1 hour).
  - `cache_ttl`: Cache duration for API results in seconds (default: 24 hours).
  - `batch_size`: Number of URLs processed per batch (default: 10).

## Usage
1. Run the application:
   ```bash
   python phishing_monitor.py
   ```
2. **GUI Overview**:
   - **Check URLs**: Enter a single URL or text containing URLs, or import a file.
   - **Analysis Tools**: Trace redirects, check VirusTotal/URLScan, or analyze risk.
   - **URL History**: View monitored URLs with status, risk level, and comments.
   - **Actions**: Re-check URLs, delete selected URLs, toggle auto-check, auto-remove inactive URLs, or enable email notifications.
   - **Export**: Save history as CSV or JSON.
3. **Enable Telegram Notifications**:
   - Click "Telegram Notify Toggle" to enable/disable notifications.
   - Notifications are sent during auto-checks for status changes (e.g., Inactive → Active or Active → Inactive).

## Notes
- **API Limits**: VirusTotal (4 requests/minute) and URLScan (2 requests/minute) are rate-limited. The tool respects these limits.
- **Telegram Notifications**: Require valid API token and chat id.
- **Database**: Stores data in `phishing_urls.db`. Logs are written to `phishing_monitor.log` with rotation.
- **Performance**: Optimized for nonstop monitoring with batch processing and thread-safe GUI updates.
  Example Screenshot

  ![image](https://github.com/user-attachments/assets/9fac23c9-0a16-4a48-8386-bda1605b8176)


## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments
- Built with [Tkinter](https://docs.python.org/3/library/tkinter.html), [aiohttp](https://docs.aiohttp.org/), and [SQLite](https://www.sqlite.org/).
- Inspired by the SOC needs for phishing URL monitoring.
