# petgo-daily-login
Standalone script for scheduled daily login

It has the following features:
- No Logs
- Automatic VerCode Update
- Region JP and NA
- Discord Webhook Notification (TBA)

# Extract your auth data
You need to extract your authentication data to do this.
It's simple, all you need to do is navigate to the following path and get the following file: 

| Region | Path | File |
| --- | --- | --- | 
| NA | `android/data/com.aniplex.fategrandorder.en/files/data/` | 54cc790bf952ea710ed7e8be08049531 |
| JP | `android/data/com.aniplex.fategrandorder/files/data/` | 54cc790bf952ea710ed7e8be08049531 |

# Discord Webhook 
To create webhook discord you need create a server in discord and create a text channel, in settings of that channel search
`integration > webhook > create webhook > copy url webhook`

# Secrets
Add this enviroment variables into `Repository > settings > secrets > actions`
| Secret | Example |
| --- | --- |
| CERTIFICATE | Zsv... (from 54cc790bf952ea710ed7e8be08049531 file) |
| USER_AGENT_SECRET_2 | Dalvik/2.1.0 (Linux; U; Android 9 Build/PQ3A.190605.09261202) or Your User Agent |
| DEVICE_INFO_SECRET |   / Android OS 9 / API-28 (PQ3A.190605.09261202 release-keys/3793265) or Your Device Info |
| GAME_REGION | NA or JP (Must be in upper case) |
| DISCORD_WEBHOOK | https://discord.com/api/webhooks/randomNumber/randomString |
| BUY_BLUE_APPLE | Y or N |

For multiple accs, put `;` between Zsv string (e.g: `ZsvAbC123;ZsvDeF456;ZsvGhI678`)
# Credits
- [hexstr](https://github.com/hexstr)
- [O-Isaac](https://github.com/O-Isaac)
- [DNNDHH](https://github.com/DNNDHH)
