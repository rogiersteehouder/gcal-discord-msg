# Post discord messages

## discord-msg.py

In the toml file, you can define preset channels, messages and roles to mention.

To get the channel url, go to the discord channel you want to post in. Go to
the integration settings of the channel and create a webhook (or use an
existing one). There is a "Copy Webhook URL" button, so copy and paste it into
the toml file.

Now you can use the script to quickly post preset messages onto the discord
channel.

	> discord-msg.py -c <channel> -m <message> [-r <mention>]

To find the role ids, you need to go to your user settings and under advanced
settings, activate developer mode. That adds a "Copy ID" option to the roles
in the server settings.


## gcal-msg.py

This script downloads events from a Google calendar and schedules messages to
send from those. It downloads all future events from the calendar and tries to
parse the description as json. It expects a root key `discord-msg` as follows:

	{
		"discord-msg": {
			"name": "<name in task scheduler (windows)>",
			"channel": "<channel as defined in config>",
			"message": "<message as defined in config>",
			"mention": "<mention (role) as defined in config (optional)>",
			"offset": 300
		}
	}

`offset` being the time in seconds before the start of the event to send the
message.

The script assumes cron and needs to be called as editor by crontab:

	> EDITOR='python gcal-msg.py --crontab' crontab -e

### Calendar ID

Go into the settings of the calendar you want to use. Under the integration
header is the calendar-id. Put this in the toml file.

### Client ID and Client Secret

To get access to that calendar from the script is a bit more involved. You are
going to become a developer.

Go to https://console.cloud.google.com/ and create a project.

In that project's dashboard, you choose APIs & Services and create an OAuth
consent screen. This is the page users see to allow access to the calendar.
Fill in the form. The scope you need for this is
`https://www.googleapis.com/auth/calendar.readonly`.
Unless you want to make a public service, add yourself as a test user.

Next, Go to Credentials and add an OAuth Client ID. Choose application type
Desktop App and choose a name.

This will generate a client id and a client secret that you need to copy into
the toml file.

### Refresh token

You only need to consent to access once. The refresh token is then used by the
script to recieve access tokens and access the calendar.

`gcal-msg-consent.html` should give you the refresh token to put in the toml
file. (This is untested.)
