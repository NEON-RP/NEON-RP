NEON RP backend configuration bundle

1. Upload server.js and package.json to the FadeHost app repository/root.
2. Set the start command to: npm start
3. In FadeHost environment variables, copy values from .env.example, but replace DISCORD_BOT_TOKEN and APPLICATION_SHARED_SECRET with real values directly in FadeHost. Do not commit real secrets to GitHub.
4. Confirm the GitHub Pages URL in repository Settings > Pages. If it is not https://neon-rp.github.io/NEON-RP/, update SITE_URL and ALLOWED_ORIGIN accordingly.
5. Make sure the Discord bot has View Channel, Send Messages, Embed Links, and Manage Roles permissions, and that its highest role is above Citizen and Police roles.

Important: this server.js is the applications receiver/reviewer backend. It does not implement Discord OAuth login routes by itself. OAuth-related environment variables alone will not create login functionality; that needs the matching OAuth-enabled server.js and website frontend integration.
