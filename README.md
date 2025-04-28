# VirusTotal-Discord-Bot
A Python-based Discord bot that makes scanning files easy and fast using the VirusTotal API — without ever leaving Discord.

## What it does:
- Upload any file to Discord, and the bot will automatically send it to VirusTotal for scanning.

- View detailed scan results directly in Discord, showing which antivirus engines detect the file as malicious, undetected, or unsupported.

- Use interactive buttons to easily navigate through multiple pages of scan results.

- Get a direct link to the full VirusTotal analysis for deeper insights, including community comments, file behavior, and technical details.

## Usage:
To use, simply invite the bot to your server and use the slash command /upload_file to upload the file for scanning. [TO BE IMPLEMENTED]

- The file bot.py contains the source code for the bot.
- The .env file, which should contain the bot token, guild ID, and VirusTotal API key, is not included.
- Anyone wishing to use the bot must create their own .env file and add the respective fields.

## Screenshots: 
- File check in-progress:


   ![image](https://github.com/user-attachments/assets/5db198ee-f9f2-40f2-be1d-d25685fa4bd0)

- Main result page:


  ![image](https://github.com/user-attachments/assets/69d21647-a2e5-4f8c-bae0-028368c448b1)

- Undetected page:

  
  ![image](https://github.com/user-attachments/assets/a19f003f-561e-4bd3-8d80-841702fc45b2)

- Detected page (if no AV services detect the file as malicious it will display the following):


  ![image](https://github.com/user-attachments/assets/c936528c-5f6c-48ba-a7a2-e26b628f0c91)

- Unsupported file type page:


  ![image](https://github.com/user-attachments/assets/37416582-dd85-4f4e-afb7-ae22ed69edc7)

## Why I built it:
I built this bot to make it easier and faster to scan files shared in Discord servers. Usually, you would have to manually download a file, visit the VirusTotal site, upload it, and wait for results.
With this bot, everything happens inside Discord — saving time, improving server security, and making it more convenient for users to check files before opening them.
I also wanted to create a fun project using APIs and practice working with Discord bots, file handling, and API pagination.

## Credits:
[VirusTotal API](https://docs.virustotal.com/reference/overview) — for providing the file scanning service.

[Discord API](https://discord.com/developers/docs/intro) — for enabling interaction through slash commands and file uploads.


