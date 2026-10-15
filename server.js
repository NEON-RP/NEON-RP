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
  'CITIZEN_ROLE_ID', 'POLICE_ROLE_ID', 'DISCORD_CLIENT_ID',
  'DISCORD_CLIENT_SECRET', 'DISCORD_OAUTH_REDIRECT_URI', 'SITE_URL'
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
// Short-lived in-memory OAuth sessions. Restarting the service logs users out safely.
const oauthStates = new Map();
const oauthSessions = new Map();

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
      res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
      res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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

app.get('/auth/discord', (req, res) => {
  const state = crypto.randomBytes(24).toString('hex');
  oauthStates.set(state, Date.now() + 10 * 60 * 1000);
  const url = new URL('https://discord.com/oauth2/authorize');
  url.searchParams.set('client_id', process.env.DISCORD_CLIENT_ID);
  url.searchParams.set('redirect_uri', process.env.DISCORD_OAUTH_REDIRECT_URI);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'identify');
  url.searchParams.set('state', state);
  res.redirect(url.toString());
});

app.get('/auth/discord/callback', async (req, res) => {
  const { code, state } = req.query;
  const expiry = oauthStates.get(String(state || ''));
  oauthStates.delete(String(state || ''));
  if (!code || !expiry || expiry < Date.now()) return res.redirect(process.env.SITE_URL + '#discord_login=failed');
  try {
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code',
        code: String(code), redirect_uri: process.env.DISCORD_OAUTH_REDIRECT_URI })
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) throw new Error('OAuth token exchange failed');
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userResponse.json();
    if (!userResponse.ok || !/^\d{17,20}$/.test(String(user.id || ''))) throw new Error('Discord user lookup failed');
    const sessionToken = crypto.randomBytes(32).toString('hex');
    oauthSessions.set(sessionToken, { id: user.id, username: user.username, expiresAt: Date.now() + 6 * 60 * 60 * 1000 });
    res.redirect(process.env.SITE_URL + '#discord_token=' + sessionToken);
  } catch (err) {
    console.error('Discord OAuth failed:', err.message);
    res.redirect(process.env.SITE_URL + '#discord_login=failed');
  }
});

function authenticatedDiscordUser(req) {
  const match = /^Bearer ([a-f0-9]{64})$/.exec(req.get('authorization') || '');
  if (!match) return null;
  const session = oauthSessions.get(match[1]);
  if (!session || session.expiresAt < Date.now()) { oauthSessions.delete(match[1]); return null; }
  return session;
}
app.get('/api/auth/me', (req, res) => {
  const user = authenticatedDiscordUser(req);
  if (!user) return res.status(401).json({ error: 'سجّل الدخول بديسكورد أولًا.' });
  res.json({ id: user.id, username: user.username });
});
app.post('/api/auth/logout', (req, res) => {
  const match = /^Bearer ([a-f0-9]{64})$/.exec(req.get('authorization') || '');
  if (match) oauthSessions.delete(match[1]);
  res.json({ ok: true });
});

app.post('/api/applications', async (req, res) => {
  try {
    if (!client.isReady()) return res.status(503).json({ error: 'بوت ديسكورد لسه بيبدأ. حاول بعد قليل.' });
    const verifiedUser = authenticatedDiscordUser(req);
    if (!verifiedUser) return res.status(401).json({ error: 'سجّل الدخول بديسكورد قبل إرسال التقديم.' });
    const b = req.body || {};
    const playerName = clean(b.playerName, 17);
    const discordUsername = clean(verifiedUser.username, 32);
    const discordId = clean(verifiedUser.id, 20);
    const extra = clean(b.extra, 500);
    const applicationType = b.applicationType === 'police' ? 'police' : 'general';
    const isPolice = applicationType === 'police';
    const channelId = isPolice ? process.env.DISCORD_POLICE_APPLICATION_CHANNEL_ID : process.env.DISCORD_GENERAL_APPLICATION_CHANNEL_ID;
    const age = b.age === null || b.age === '' || typeof b.age === 'undefined' ? null : Number(b.age);

    if (playerName.length < 2 || playerName.length > 17 ||
        discordUsername.length < 2 || discordUsername.length > 32) {
      return res.status(400).json({ error: 'تحقق من اسم اللاعب واسم مستخدم ديسكورد.' });
    }
    if (age !== null && (!Number.isInteger(age) || age < 13 || age > 99)) return res.status(400).json({ error: 'العمر اختياري، وإذا أُدخل فيجب أن يكون من 13 إلى 99.' });
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
        { name: 'Discord ID', value: discordId, inline: false },
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
  if (!isApplicationButton) return;

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

  // Reject: update the application and privately notify the applicant by DM.
  if (interaction.isButton() && interaction.customId.startsWith('neon_app_reject:')) {
    try {
      const firstEmbed = interaction.message.embeds[0];
      const discordId = firstEmbed?.fields.find(f => f.name === 'Discord ID')?.value?.trim();
      let dmSent = false;
      if (/^\d{17,20}$/.test(discordId || '')) {
        try {
          const applicant = await client.users.fetch(discordId);
          const notice = new EmbedBuilder()
            .setColor(0xff2947)
            .setTitle('📩 تحديث بخصوص تقديمك — NEON RP')
            .setDescription(`أهلًا بيك في **NEON RP**،\n\nبعد مراجعة طلب التقديم الخاص بك، نأسف لإبلاغك بأنه **لم تتم الموافقة على طلبك في الوقت الحالي**.\n\nده مش معناه إن باب السيرفر اتقفل قدامك؛ راجع شروط التقديم، وطوّر إجاباتك، وتقدر تتقدم مرة أخرى إذا كانت قواعد السيرفر تسمح بذلك.`)
            .addFields(
              { name: 'نوع التقديم', value: firstEmbed?.fields.find(f => f.name === 'نوع التقديم')?.value || 'غير محدد', inline: true },
              { name: 'حالة الطلب', value: '❌ غير مقبول حاليًا', inline: true },
              { name: 'ملاحظة', value: 'لو محتاج تعرف تفاصيل أكثر، تواصل مع الإدارة باحترام من خلال القنوات الرسمية.', inline: false }
            )
            .setFooter({ text: 'NEON RP • نتمنى لك التوفيق' })
            .setTimestamp();
          await applicant.send({ embeds: [notice] });
          dmSent = true;
        } catch (dmErr) {
          console.warn('Could not DM rejected applicant:', dmErr.message);
        }
      }
      const updatedEmbeds = interaction.message.embeds.map((old, i) => {
        const next = EmbedBuilder.from(old);
        if (i === 0) {
          next.setTitle('❌ تم رفض التقديم — NEON RP')
            .addFields({
              name: 'قرار الإدارة',
              value: `مرفوض بواسطة ${interaction.user.tag}\nإشعار خاص للعضو: ${dmSent ? 'تم الإرسال' : 'تعذر الإرسال (قد تكون الرسائل الخاصة مغلقة)'}`,
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

  // Accept button: use the Discord ID verified by OAuth during submission.
  if (interaction.isButton() && interaction.customId.startsWith('neon_app_approve:')) {
    const originalMessage = interaction.message;
    const discordId = originalMessage.embeds[0]?.fields.find(f => f.name === 'Discord ID')?.value?.trim();
    if (!/^\d{17,20}$/.test(discordId || '')) {
      await interaction.reply({ content: 'الطلب لا يحتوي على هوية ديسكورد موثقة؛ لم يتم منح أي رتبة.', ephemeral: true });
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

      let dmSent = false;
      try {
        const notice = new EmbedBuilder()
          .setColor(0x20c997)
          .setTitle('🎉 مبروك! تم قبول تقديمك في NEON RP')
          .setDescription(`أهلًا بيك في **NEON RP**!\n\nيسعدنا نبلغك إن **طلب التقديم بتاعك اتقبل بنجاح** بعد مراجعة الإدارة. نورت عيلتك الجديدة!\n\nتم تفعيل رتبتك داخل السيرفر، وتقدر تبدأ رحلتك وتلتزم بقوانين المدينة وتعليمات الإدارة.`)
          .addFields(
            { name: 'نوع التقديم', value: isPolice ? '👮 الشرطة' : '🏙️ مواطن', inline: true },
            { name: 'الرتبة الممنوحة', value: `<@&${targetRoleId}>`, inline: true },
            { name: 'الخطوة التالية', value: isPolice ? 'راجع تعليمات وقوانين الشرطة قبل مباشرة مهامك.' : 'راجع قوانين المدينة وابدأ الـ Roleplay باحترام والتزام.' , inline: false }
          )
          .setFooter({ text: 'NEON RP • أهلًا بيك وسطنا' })
          .setTimestamp();
        await targetMember.send({ embeds: [notice], allowedMentions: { roles: [targetRoleId] } });
        dmSent = true;
      } catch (dmErr) {
        console.warn('Could not DM accepted applicant:', dmErr.message);
      }

      const updated = EmbedBuilder.from(firstEmbed)
        .addFields(
          { name: 'معرّف العضو الرقمي', value: discordId, inline: false },
          { name: 'قرار الإدارة', value: `مقبول بواسطة ${interaction.user.tag}\nتم منح رتبة ${targetRoleName} للعضو <@${discordId}>.\nإشعار خاص للعضو: ${dmSent ? 'تم الإرسال' : 'تعذر الإرسال (قد تكون الرسائل الخاصة مغلقة)'}`, inline: false }
        );
      await originalMessage.edit({
        embeds: [updated, ...originalMessage.embeds.slice(1)],
        components: []
      });
      await interaction.reply({ content: `تم قبول التقديم ومنح رتبة ${targetRoleName}. ${dmSent ? 'وتم إرسال رسالة خاصة للعضو.' : 'لكن تعذر إرسال رسالة خاصة؛ قد تكون رسائل العضو مغلقة.'}`, ephemeral: true });
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
