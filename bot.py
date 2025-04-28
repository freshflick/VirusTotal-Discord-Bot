"""
Author: Shayan (Shay/Freshflick)
"""

import os
import discord
from discord import app_commands
from dotenv import load_dotenv
import requests
import asyncio

from discord.ext import commands

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD_ID = int(os.getenv('DISCORD_GUILD'))
VT_API_KEY = os.getenv('VT_API_KEY')


#enabling needed intents
intents = discord.Intents.all()
intents.members = True
intents.messages = True

class SecureCheck(commands.Bot):
    def __init__(self):
        super().__init__(command_prefix="!", intents=intents)
        
    
    async def setup_hook(self) -> None:
        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)
    
bot = SecureCheck()


class PageView(discord.ui.View):
    def __init__(self, embeds):
        super().__init__(timeout=180)
        self.embeds = embeds
        self.current = 0

        if len(embeds) == 1:
            self.previous_button.disabled = True
            self.next_button.disabled = True
        else:
            self.previous_button.disabled = True

    @discord.ui.button(label="⏮️ Previous", style=discord.ButtonStyle.secondary)
    async def previous_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.current -= 1
        if self.current <= 0:
            self.current = 0
            self.previous_button.disabled = True
        self.next_button.disabled = False
        await interaction.response.edit_message(embed=self.embeds[self.current], view=self)

    @discord.ui.button(label="⏭️ Next", style=discord.ButtonStyle.secondary)
    async def next_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.current += 1
        if self.current >= len(self.embeds) - 1:
            self.current = len(self.embeds) - 1
            self.next_button.disabled = True
        self.previous_button.disabled = False
        await interaction.response.edit_message(embed=self.embeds[self.current], view=self)
        
@bot.event
async def on_ready():
    guild = discord.utils.get(bot.guilds, id=GUILD_ID)
    print(
        f'{bot.user.name} is connected to the following guild:\n'
        f'{guild.name}(id: {guild.id})'
    )

    members = [member async for member in guild.fetch_members(limit=None)]
    members_names = '\n - '.join([member.name for member in guild.members])
    print(f'Guild Members:\n - {members_names}')
        
@bot.event
async def on_member_join(member):
    await member.create_dm()
    await member.dm_channel.send(
        f"Hi, {member.name}, welcome to the server, feel free to check your files using me!"
    )

@bot.event
async def on_error(event, *args, **kwargs):
    with open('error.log', 'a') as file:
        if event == "on_message":
            file.write(f"Unhandled message: {args[0]}\n")
        else:
            raise

@bot.command(name = 'upload_file', help = "Upload file for checking")
async def upload(ctx):
    await ctx.send("Please upload the file in an appropriate format (zip, png, pdf...)")

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    
    if message.attachments:
        attachments = message.attachments[0]
        if attachments.filename.endswith(".zip"):
            await message.channel.send(f"File: {attachments.filename} received for checking")
        else:
            await message.channel.send("Please upload the file in the specified format.")
    
    await bot.process_commands(message)


@bot.tree.command(name = "upload_file", description = "Upload file for checking")
async def upload(interaction: discord.Interaction, file: discord.Attachment):
    guild = interaction.guild
    member = guild.get_member(interaction.user.id)
    grandmaster_role = discord.utils.get(guild.roles, name="Grandmaster")
    
    if grandmaster_role not in member.roles:
        await interaction.response.send_message("You are not eligible to check files with the current role permissions.")
        return

    # Acknowledge the interaction (defer)
    await interaction.response.defer()
    
    #saving the file
    file_path = f"./{file.filename}"
    await file.save(file_path)
    
    try:
    #virus-total API request
        url = "https://www.virustotal.com/api/v3/files"    
        
        with open(file_path, "rb") as f:
            files = { "file": (file.filename, f, "application/zip")}
            headers = {
                "accept": "application/json",
                "x-apikey": VT_API_KEY
            }
        
            response = requests.post(url, files=files, headers=headers)
            print(f"Upload response: {response.text}")
        
        #response based on api response
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            
            while True:
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_result = analysis_response.json()
                print(f"Analysis response: {analysis_response.text}")
            
                if analysis_result['data']['attributes']['status'] == 'completed':
                    break
                
                await asyncio.sleep(5)
                
            analysis_info = analysis_result['data']['attributes']
            detection_ratio = (
                "------------------------\n"
                f"🔴 Detected: {analysis_info['stats']['malicious']}\n"
                f"🟢 Undetected: {analysis_info['stats']['undetected']}"
            )
            verbose_msg = analysis_info['status'].capitalize()
            note = ("Disclaimer: \n"
                "• This bot is unofficial and not hosted by VirusTotal\n"
                "• Avoid uploading sensitive files\n"
                "• Some results may be incomplete — click the analysis link for full details"
            )
            link = analysis_result['data']['links']['item']
            file_id = link.split('/')[-1]
            
            web_analysis_url = f"https://www.virustotal.com/gui/file/{file_id}"
            
            
            #printing results for all services
            results = analysis_result['data']['attributes']['results']
            
            list_undetected = []
            list_detected = []
            list_unsupported = []
            
            for key, value in results.items():
                if value['category'] == 'undetected':
                    list_undetected.append(key)
                elif value['category'] == 'type-unsupported':
                    list_unsupported.append(key)
                elif value['category'] == 'malicious':
                    list_detected.append(key)
   
   
            def format_list(items, max_chars = 1024, num_columns = 3):
                if not items:
                    return ["No items to display."]

                total_rows = (len(items) + num_columns - 1) // num_columns

                #create columns
                columns = []
                for i in range(num_columns):
                    start = i * total_rows
                    end = start + total_rows
                    column = items[start:end]
                    while len(column) < total_rows:
                        column.append("")
                    columns.append(column)

                #build rows
                rows = []
                for row_items in zip(*columns):
                    row = "   ".join(item.ljust(25) for item in row_items)
                    rows.append(row.rstrip())

                page = "\n".join(rows)

                if len(page) > max_chars:
                    #split into pages if needed
                    pages = []
                    current_page = ""
                    for line in rows:
                        if len(current_page) + len(line) + 1 > max_chars:
                            pages.append(current_page.strip())
                            current_page = ""
                        current_page += line + "\n"
                    if current_page:
                        pages.append(current_page.strip())
                    return pages
                else:
                    return [page]
            
            formatted_undetected = format_list(list_undetected)
            formatted_unsupported = format_list(list_unsupported)
            formatted_detected = format_list(list_detected)
            
            embeds = []

            #first page: the main info
            main_embed = discord.Embed(title="File Analysis Result", color=discord.Colour.dark_teal())
            main_embed.add_field(name="Detection Ratio:", value=detection_ratio, inline=False)
            main_embed.add_field(name="Status:", value=verbose_msg, inline=False)
            main_embed.add_field(name="\u200b", value=f"[Analysis Link]({web_analysis_url})", inline=False)
            main_embed.set_thumbnail(url='https://cdn.icon-icons.com/icons2/2699/PNG/512/virustotal_logo_icon_171247.png')
            main_embed.set_footer(text=f"{note}\n\nPowered by VirusTotal")
            embeds.append(main_embed)

            #add other pages
            for idx, page in enumerate(formatted_undetected):
                embed = discord.Embed(title=f"Undetected (Page {idx+1})", color=discord.Colour.dark_teal())
                embed.add_field(name="", value=f"```\n{page}\n```", inline=False)
                embeds.append(embed)

            for idx, page in enumerate(formatted_detected):
                embed = discord.Embed(title=f"Detected (Page {idx+1})", color=discord.Colour.dark_red())
                embed.add_field(name="", value=f"```\n{page}\n```", inline=False)
                embeds.append(embed)

            for idx, page in enumerate(formatted_unsupported):
                embed = discord.Embed(title=f"Unsupported File Type (Page {idx+1})", color=discord.Colour.yellow())
                embed.add_field(name="", value=f"```\n{page}\n```", inline=False)
                embeds.append(embed)

            view = PageView(embeds)
            await interaction.followup.send(embed=embeds[0], view=view)
        else:
            await interaction.followup.send(f"Failed to upload file: {response.text}")
    finally:
        os.remove(file_path)
    
bot.run(TOKEN)
