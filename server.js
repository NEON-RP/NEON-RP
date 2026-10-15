require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ModalBuilder, TextInputBuilder, TextInputStyle, Events } = require('discord.js');
const crypto = require('crypto');

const required = [
  'DISCORD_BOT_TOKEN', 'DISCORD_GUILD_ID',
  'DISCORD_GENERAL_APPLICATION_CHANNEL_ID', 'DISCORD_POLICE_APPLICATION_CHANNEL_ID',
  'ALLOWED_ORIGIN', 'APPLICATION_SHARED_SECRET', 'STAFF_ROLE_ID',
  'CITIZEN_ROLE_ID', 'POLICE_ROLE_ID'
];
const missing = required.filter(k => {
  const v = process.env[k];
  return !v || v.startsWith('PUT_') || v.startsWith('REPLACE_') || v.includes('YOUR-WEBSITE');
});
if (missing.length) {
  console.error('Missing configuration:', missing.join(', '));
  process.exit(1);
}
if (process.env.APPLICATION_SHARED_SECRET.length < 32) {
  console.error('APPLICATION_SHARED_SECRET must be at least 32 characters.');
  process.exit(1);
}
if (process.env.CITIZEN_ROLE_ID === process.env.POLICE_ROLE_ID) {
  console.error('CITIZEN_ROLE_ID and POLICE_ROLE_ID must be different.');
  process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '40kb', strict: true }));
app.use('/api/applications', rateLimit({
  windowMs: 10 * 60 * 1000, limit: 5, standardHeaders: 'draft-7',
  legacyHeaders: false, message: { error: 'محاولات كثيرة. حاول بعد قليل.' }
}));
app.use((req, res, next) => {
  const origin = req.get('origin');
  if (origin && origin !== process.env.ALLOWED_ORIGIN) return res.status(403).json({ error: 'Origin not allowed' });
  if (req.method === 'OPTIONS') {
    if (origin === process.env.ALLOWED_ORIGIN) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Content-Type');
    }
    return res.sendStatus(origin && origin !== process.env.ALLOWED_ORIGIN ? 403 : 204);
  }
  if (origin === process.env.ALLOWED_ORIGIN) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Vary', 'Origin');
  }
  next();
});

const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
client.once(Events.ClientReady, c => console.log(`Discord bot ready as ${c.user.tag}`));
client.login(process.env.DISCORD_BOT_TOKEN).catch(err => {
  console.error('Discord login failed:', err.message);
  process.exit(1);
});

function clean(s, max = 1000) {
  return String(s ?? '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').slice(0, max).trim();
}
function safeEqual(a, b) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

app.get('/health', (req, res) => res.json({ ok: true, discordReady: client.isReady() }));

// Discord OAuth2 login. The website is hosted on GitHub Pages, so the OAuth
// access token never leaves this backend. A one-time ticket is exchanged by the
// frontend for a minimal public Discord profile.
const oauthTickets = new Map();
const OAUTH_STATE_COOKIE = 'neon_discord_oauth_state';
const OAUTH_TICKET_TTL_MS = 60 * 1000;

function oauthConfigReady() {
  return Boolean(
    process.env.DISCORD_CLIENT_ID && !process.env.DISCORD_CLIENT_ID.startsWith('PUT_') &&
    process.env.DISCORD_CLIENT_SECRET && !process.env.DISCORD_CLIENT_SECRET.startsWith('PUT_') &&
    process.env.DISCORD_OAUTH_REDIRECT_URI &&
    process.env.SITE_URL
  );
}
function hmac(value) {
  return crypto.createHmac('sha256', process.env.APPLICATION_SHARED_SECRET).update(value).digest('hex');
}
function safeStringEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function siteRedirect(params = {}) {
  const target = new URL(process.env.SITE_URL || 'https://freefire5795in-bit.github.io/NEON-RP/');
  for (const [key, value] of Object.entries(params)) {
    if (value) target.searchParams.set(key, value);
  }
  return target.toString();
}

app.get('/auth/discord', (req, res) => {
  if (!oauthConfigReady()) {
    return res.status(503).type('text').send(
      'NEON RP: Discord OAuth is not configured. Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_OAUTH_REDIRECT_URI and SITE_URL in FadeHost.'
    );
  }
  const state = crypto.randomBytes(32).toString('hex');
  res.cookie(OAUTH_STATE_COOKIE, `${state}.${hmac(state)}`, {
    httpOnly: true, secure: true, sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/auth/discord'
  });
  const authorize = new URL('https://discord.com/oauth2/authorize');
  authorize.searchParams.set('client_id', process.env.DISCORD_CLIENT_ID);
  authorize.searchParams.set('redirect_uri', process.env.DISCORD_OAUTH_REDIRECT_URI);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('scope', 'identify');
  authorize.searchParams.set('state', state);
  res.redirect(302, authorize.toString());
});

app.get('/auth/discord/callback', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const state = String(req.query.state || '');
  const cookie = String(req.get('cookie') || '').split('; ').find(v => v.startsWith(`${OAUTH_STATE_COOKIE}=`))?.slice(OAUTH_STATE_COOKIE.length + 1) || '';
  const [cookieState, cookieMac] = decodeURIComponent(cookie).split('.');
  res.clearCookie(OAUTH_STATE_COOKIE, { httpOnly: true, secure: true, sameSite: 'lax', path: '/auth/discord' });

  if (!oauthConfigReady()) return res.redirect(302, siteRedirect({ discord_login: 'not_configured' }));
  if (!state || !cookieState || !cookieMac || !safeStringEqual(state, cookieState) || !safeStringEqual(cookieMac, hmac(cookieState))) {
    return res.redirect(302, siteRedirect({ discord_login: 'state_error' }));
  }
  if (req.query.error || typeof req.query.code !== 'string') {
    return res.redirect(302, siteRedirect({ discord_login: 'cancelled' }));
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: req.query.code,
        redirect_uri: process.env.DISCORD_OAUTH_REDIRECT_URI
      })
    });
    if (!tokenResponse.ok) throw new Error(`OAuth token exchange returned ${tokenResponse.status}`);
    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) throw new Error('OAuth token response did not include access_token');

    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    if (!userResponse.ok) throw new Error(`Discord profile returned ${userResponse.status}`);
    const user = await userResponse.json();
    if (!/^\d{17,20}$/.test(String(user.id || ''))) throw new Error('Discord profile ID was invalid');

    const ticket = crypto.randomBytes(32).toString('hex');
    oauthTickets.set(ticket, {
      expiresAt: Date.now() + OAUTH_TICKET_TTL_MS,
      profile: {
        id: String(user.id),
        username: String(user.global_name || user.username || 'Discord User').slice(0, 80),
        avatar: user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128` : null
      }
    });
    return res.redirect(302, siteRedirect({ discord_auth_ticket: ticket }));
  } catch (err) {
    console.error('Discord OAuth callback failed:', err.message);
    return res.redirect(302, siteRedirect({ discord_login: 'failed' }));
  }
});

app.post('/api/auth/discord/session', (req, res) => {
  res.set('Cache-Control', 'no-store');
  const ticket = String(req.body?.ticket || '');
  if (!/^[a-f0-9]{64}$/.test(ticket)) return res.status(400).json({ error: 'تذكرة تسجيل الدخول غير صالحة.' });
  const session = oauthTickets.get(ticket);
  oauthTickets.delete(ticket); // one-time use, even if expired
  if (!session || session.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'انتهت صلاحية تسجيل الدخول. سجّل الدخول مرة أخرى.' });
  }
  return res.json({ ok: true, user: session.profile });
});

setInterval(() => {
  const now = Date.now();
  for (const [ticket, session] of oauthTickets) if (session.expiresAt < now) oauthTickets.delete(ticket);
}, 30_000).unref();

app.post('/api/applications', async (req, res) => {
  try {
    if (!client.isReady()) return res.status(503).json({ error: 'بوت ديسكورد لسه بيبدأ. حاول بعد قليل.' });
    const auth = req.get('x-application-secret') || '';
    if (process.env.REQUIRE_SHARED_SECRET === 'true' &&
        !safeEqual(auth, process.env.APPLICATION_SHARED_SECRET)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const b = req.body || {};
    const playerName = clean(b.playerName, 17);
    const discordUsername = clean(b.discordUsername, 32);
    const discordId = clean(b.discordId, 20);
    const extra = clean(b.extra, 500);
    const applicationType = b.applicationType === 'police' ? 'police' : 'general';
    const isPolice = applicationType === 'police';
    const channelId = isPolice ? process.env.DISCORD_POLICE_APPLICATION_CHANNEL_ID : process.env.DISCORD_GENERAL_APPLICATION_CHANNEL_ID;
    const age = b.age === null || b.age === '' || typeof b.age === 'undefined' ? null : Number(b.age);

    if (playerName.length < 2 || playerName.length > 17 ||
        discordUsername.length < 2 || discordUsername.length > 32) {
      return res.status(400).json({ error: 'تحقق من اسم اللاعب واسم مستخدم ديسكورد.' });
    }
    if (age === null || !Number.isInteger(age) || age < 13 || age > 99) return res.status(400).json({ error: 'العمر مطلوب ويجب أن يكون من 13 إلى 99.' });
    if (!Array.isArray(b.answers) || b.answers.length < 1 || b.answers.length > 30) return res.status(400).json({ error: 'عدد الإجابات غير صالح.' });

    const answers = b.answers.map((a, i) => ({
      question: clean(a?.question, 300) || `السؤال ${i + 1}`,
      answer: clean(a?.answer, 1200) || 'لم تتم الإجابة',
      timedOut: !!a?.timedOut,
      correct: !!a?.correct
    }));
    const applicationId = crypto.randomUUID();
    const score = Number.isFinite(Number(b.score)) ? Math.max(0, Math.min(30, Math.trunc(Number(b.score)))) : 0;
    const channel = await client.channels.fetch(channelId);
    if (!channel || !channel.isTextBased() || !channel.send) {
      return res.status(500).json({ error: 'قناة استقبال الطلبات غير متاحة. راجع ID القناة وصلاحيات البوت.' });
    }

    const embed = new EmbedBuilder()
      .setColor(0xff2947)
      .setTitle(isPolice ? '👮 تقديم شرطة جديد — NEON RP' : '📝 تقديم جديد — NEON RP')
      .setDescription(isPolice ? 'طلب تقديم للشرطة من موقع NEON RP.' : 'طلب تقديم جديد من موقع NEON RP.')
      .addFields(
        { name: 'نوع التقديم', value: isPolice ? 'الشرطة' : 'عام', inline: true },
        { name: 'اسم اللاعب', value: playerName, inline: true },
        { name: 'اسم مستخدم ديسكورد', value: `@${discordUsername}`, inline: true },
        { name: 'العمر', value: age === null ? 'لم يُذكر' : String(age), inline: true },
        { name: 'نتيجة الاختيار من متعدد', value: `${score} / ${answers.length}`, inline: true },
        { name: 'المدة', value: `${Math.max(0, Math.min(7200, Number(b.elapsedSeconds) || 0))} ثانية`, inline: true },
        { name: 'معلومات إضافية', value: extra || 'لا توجد', inline: false }
      )
      .setFooter({ text: `NEON RP • Application ID: ${applicationId}` })
      .setTimestamp(new Date());

    const chunks = answers.map((a, i) => `**${i + 1}. ${a.question}**\n${a.answer}${a.timedOut ? '\n⏱️ انتهى الوقت' : ''}`);
    let description = '';
    const pages = [];
    for (const chunk of chunks) {
      if ((description + '\n\n' + chunk).length > 3900) {
        pages.push(description);
        description = '';
      }
      description += (description ? '\n\n' : '') + chunk;
    }
    if (description) pages.push(description);
    const embeds = [embed, ...pages.slice(0, 9).map((page, i) =>
      new EmbedBuilder().setColor(0x211014).setTitle(`إجابات التقديم • ${i + 1}/${Math.min(pages.length, 9)}`).setDescription(page)
    )];
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`neon_app_approve:${applicationId}`).setLabel('قبول').setStyle(ButtonStyle.Success),
      new ButtonBuilder().setCustomId(`neon_app_reject:${applicationId}`).setLabel('رفض').setStyle(ButtonStyle.Danger)
    );
    await channel.send({ embeds, components: [row], allowedMentions: { parse: [] } });
    return res.status(201).json({ ok: true, applicationId });
  } catch (err) {
    console.error('Application submit failed:', err.message);
    return res.status(500).json({ error: 'تعذر إرسال الطلب إلى ديسكورد. حاول لاحقًا.' });
  }
});

client.on(Events.InteractionCreate, async interaction => {
  if (!interaction.inGuild()) return;
  if (interaction.isButton() && interaction.customId.startsWith('neon_app_')) {
    console.log(`Application button clicked: ${interaction.customId} by ${interaction.user.tag}`);
  } else if (interaction.isModalSubmit() && interaction.customId.startsWith('neon_app_accept_id:')) {
    console.log(`Application acceptance modal submitted by ${interaction.user.tag}`);
  }

  const isApplicationButton = interaction.isButton() &&
    (interaction.customId.startsWith('neon_app_approve:') ||
     interaction.customId.startsWith('neon_app_reject:'));
  const isAcceptModal = interaction.isModalSubmit() &&
    interaction.customId.startsWith('neon_app_accept_id:');

  if (!isApplicationButton && !isAcceptModal) return;

  // Verify staff permissions for both buttons and the acceptance modal.
  let reviewer;
  try {
    const guild = await client.guilds.fetch(process.env.DISCORD_GUILD_ID);
    reviewer = await guild.members.fetch(interaction.user.id);
  } catch (err) {
    console.error('Could not verify application reviewer:', err.message);
    const message = 'تعذر التحقق من صلاحياتك. حاول مرة أخرى.';
    if (interaction.deferred || interaction.replied) {
      await interaction.followUp({ content: message, ephemeral: true }).catch(() => {});
    } else {
      await interaction.reply({ content: message, ephemeral: true }).catch(() => {});
    }
    return;
  }

  if (!reviewer.roles.cache.has(process.env.STAFF_ROLE_ID)) {
    const message = 'هذا الإجراء مخصص للإدارة فقط.';
    if (interaction.deferred || interaction.replied) {
      await interaction.followUp({ content: message, ephemeral: true }).catch(() => {});
    } else {
      await interaction.reply({ content: message, ephemeral: true }).catch(() => {});
    }
    return;
  }

  // Reject: update the application and remove both buttons.
  if (interaction.isButton() && interaction.customId.startsWith('neon_app_reject:')) {
    try {
      const updatedEmbeds = interaction.message.embeds.map((old, i) => {
        const next = EmbedBuilder.from(old);
        if (i === 0) {
          next.setTitle('❌ تم رفض التقديم — NEON RP')
            .addFields({
              name: 'قرار الإدارة',
              value: `مرفوض بواسطة ${interaction.user.tag}`,
              inline: false
            });
        }
        return next;
      });
      await interaction.update({ embeds: updatedEmbeds, components: [] });
    } catch (err) {
      console.error('Application rejection failed:', err);
      if (!interaction.replied && !interaction.deferred) {
        await interaction.reply({ content: 'تعذر تحديث الطلب. راجع سجل السيرفر.', ephemeral: true }).catch(() => {});
      }
    }
    return;
  }

  // Accept button: ask for the member's Discord ID.
  if (interaction.isButton() && interaction.customId.startsWith('neon_app_approve:')) {
    try {
      const modal = new ModalBuilder()
        .setCustomId(`neon_app_accept_id:${interaction.message.id}`)
        .setTitle('تأكيد قبول التقديم');
      const idInput = new TextInputBuilder()
        .setCustomId('discordId')
        .setLabel('معرّف العضو في ديسكورد')
        .setPlaceholder('أدخل Discord ID للعضو المقبول')
        .setStyle(TextInputStyle.Short)
        .setMinLength(17)
        .setMaxLength(20)
        .setRequired(true);
      modal.addComponents(new ActionRowBuilder().addComponents(idInput));
      await interaction.showModal(modal);
    } catch (err) {
      console.error('Could not open acceptance modal:', err);
      if (!interaction.replied && !interaction.deferred) {
        await interaction.reply({ content: 'تعذر فتح نافذة القبول. تأكد من تحديث السيرفر.', ephemeral: true }).catch(() => {});
      }
    }
    return;
  }

  // Modal submitted: validate ID, grant the correct role, and mark accepted.
  if (isAcceptModal) {
    const discordId = interaction.fields.getTextInputValue('discordId').trim();
    if (!/^\d{17,20}$/.test(discordId)) {
      await interaction.reply({ content: 'معرّف ديسكورد غير صالح. حاول مرة أخرى.', ephemeral: true });
      return;
    }

    const messageId = interaction.customId.slice('neon_app_accept_id:'.length);
    let originalMessage;
    try {
      originalMessage = await interaction.channel.messages.fetch(messageId);
    } catch (err) {
      console.error('Could not fetch original application:', err.message);
    }
    if (!originalMessage) {
      await interaction.reply({ content: 'لم أستطع العثور على رسالة التقديم الأصلية.', ephemeral: true });
      return;
    }

    try {
      const firstEmbed = originalMessage.embeds[0];
      if (!firstEmbed) {
        await interaction.reply({ content: 'رسالة التقديم لا تحتوي على بيانات صالحة.', ephemeral: true });
        return;
      }

      const typeField = firstEmbed.fields.find(f => f.name === 'نوع التقديم');
      const isPolice = String(typeField?.value || '').includes('الشرطة');
      const targetRoleId = isPolice ? process.env.POLICE_ROLE_ID : process.env.CITIZEN_ROLE_ID;
      const otherRoleId = isPolice ? process.env.CITIZEN_ROLE_ID : process.env.POLICE_ROLE_ID;
      const targetRoleName = isPolice ? 'شرطي' : 'مواطن';

      const guild = await client.guilds.fetch(process.env.DISCORD_GUILD_ID);
      const targetMember = await guild.members.fetch(discordId);

      if (targetMember.roles.cache.has(otherRoleId)) {
        await interaction.reply({
          content: `لا يمكن منح الرتبة؛ العضو لديه رتبة ${isPolice ? 'مواطن' : 'شرطي'} بالفعل.`,
          ephemeral: true
        });
        return;
      }
      if (targetMember.roles.cache.has(targetRoleId)) {
        await interaction.reply({ content: `العضو لديه بالفعل رتبة ${targetRoleName}.`, ephemeral: true });
        return;
      }

      await targetMember.roles.add(targetRoleId, `قبول تقديم ${targetRoleName} بواسطة ${interaction.user.tag}`);

      const updated = EmbedBuilder.from(firstEmbed)
        .addFields(
          { name: 'معرّف العضو الرقمي', value: discordId, inline: false },
          { name: 'قرار الإدارة', value: `مقبول بواسطة ${interaction.user.tag}\nتم منح رتبة ${targetRoleName} للعضو <@${discordId}>.`, inline: false }
        );
      await originalMessage.edit({
        embeds: [updated, ...originalMessage.embeds.slice(1)],
        components: []
      });
      await interaction.reply({ content: `تم قبول التقديم ومنح رتبة ${targetRoleName}.`, ephemeral: true });
    } catch (err) {
      console.error('Application acceptance/role assignment failed:', err);
      await interaction.reply({
        content: 'تعذر القبول أو منح الرتبة. تأكد من وجود العضو وصلاحيات Manage Roles وترتيب الرتب.',
        ephemeral: true
      }).catch(() => {});
    }
  }
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`NEON RP application API listening on port ${port}`));
