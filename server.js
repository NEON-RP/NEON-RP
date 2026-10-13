require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, Events } = require('discord.js');
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
      res.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
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

app.post('/api/applications', async (req, res) => {
  try {
    if (!client.isReady()) return res.status(503).json({ error: 'بوت ديسكورد لسه بيبدأ. حاول بعد قليل.' });
    const auth = req.get('x-application-secret') || '';
    if (process.env.REQUIRE_SHARED_SECRET === 'true' &&
        !safeEqual(auth, process.env.APPLICATION_SHARED_SECRET)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const b = req.body || {};
    const playerName = clean(b.playerName, 8);
    const discordUsername = clean(b.discordUsername, 32);
    const discordId = clean(b.discordId, 20);
    const extra = clean(b.extra, 500);
    const applicationType = b.applicationType === 'police' ? 'police' : 'general';
    const isPolice = applicationType === 'police';
    const channelId = isPolice ? process.env.DISCORD_POLICE_APPLICATION_CHANNEL_ID : process.env.DISCORD_GENERAL_APPLICATION_CHANNEL_ID;
    const age = b.age === null || b.age === '' || typeof b.age === 'undefined' ? null : Number(b.age);

    if (playerName.length < 2 || playerName.length > 8 ||
        discordUsername.length < 2 || discordUsername.length > 32 ||
        !/^\d{17,20}$/.test(discordId)) {
      return res.status(400).json({ error: 'تحقق من اسم اللاعب واسم مستخدم ديسكورد والمعرّف الرقمي.' });
    }
    if (age !== null && (!Number.isInteger(age) || age < 13 || age > 99)) return res.status(400).json({ error: 'العمر غير صالح.' });
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
        { name: 'اسم مستخدم ديسكورد', value: `<@${discordId}>\n\`${discordId}\`\n@${discordUsername}`, inline: true },
        { name: 'معرّف العضو الرقمي', value: discordId, inline: false },
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
  if (!interaction.isButton() || !interaction.customId.startsWith('neon_app_') || !interaction.inGuild()) return;
  let reviewer;
  try {
    const guildForReview = await client.guilds.fetch(process.env.DISCORD_GUILD_ID);
    reviewer = await guildForReview.members.fetch(interaction.user.id);
  } catch (err) {
    console.error('Could not fetch reviewer member:', err.message);
    await interaction.reply({ content: 'تعذر التحقق من صلاحياتك. حاول مرة أخرى.', ephemeral: true }).catch(() => {});
    return;
  }
  if (!reviewer.roles.cache.has(process.env.STAFF_ROLE_ID)) {
    await interaction.reply({ content: 'هذا الإجراء مخصص للإدارة فقط.', ephemeral: true }).catch(() => {});
    return;
  }
  const approved = interaction.customId.startsWith('neon_app_approve:');
  const rejected = interaction.customId.startsWith('neon_app_reject:');
  if (!approved && !rejected) return;

  let roleMessage = 'لم تتم إضافة أي رتبة.';
  if (approved) {
    try {
      const firstEmbed = interaction.message.embeds[0];
      const idField = firstEmbed?.fields?.find(f => f.name === 'معرّف العضو الرقمي');
      const discordId = String(idField?.value || '').trim();
      if (!/^\d{17,20}$/.test(discordId)) {
        await interaction.reply({ content: 'لا يمكن قبول الطلب: معرّف ديسكورد الرقمي غير صالح.', ephemeral: true });
        return;
      }
      const typeField = firstEmbed?.fields?.find(f => f.name === 'نوع التقديم');
      const isPolice = String(typeField?.value || '').includes('الشرطة');
      const targetRoleId = isPolice ? process.env.POLICE_ROLE_ID : process.env.CITIZEN_ROLE_ID;
      const otherRoleId = isPolice ? process.env.CITIZEN_ROLE_ID : process.env.POLICE_ROLE_ID;
      const targetRoleName = isPolice ? 'شرطي' : 'مواطن';
      const guild = await client.guilds.fetch(process.env.DISCORD_GUILD_ID);
      const targetMember = await guild.members.fetch(discordId);

      if (targetMember.roles.cache.has(otherRoleId)) {
        await interaction.reply({
          content: `لم تتم إضافة رتبة: العضو لديه بالفعل رتبة ${isPolice ? 'مواطن' : 'شرطي'}، ولا يمكنه الجمع بين رتبتي مواطن وشرطي.`,
          ephemeral: true
        });
        return;
      }
      if (targetMember.roles.cache.has(targetRoleId)) {
        await interaction.reply({ content: `العضو لديه بالفعل رتبة ${targetRoleName}. لم تتم إضافة رتبة جديدة.`, ephemeral: true });
        return;
      }
      await targetMember.roles.add(targetRoleId, `قبول تقديم ${targetRoleName} بواسطة ${interaction.user.tag}`);
      roleMessage = `تم منح رتبة ${targetRoleName} للعضو <@${discordId}>.`;
    } catch (err) {
      console.error('Role assignment failed:', err.message);
      await interaction.reply({
        content: 'لم يتم تنفيذ القبول. تأكد أن العضو موجود في السيرفر، وأن IDs الرتب والسيرفر صحيحة، وأن للبوت صلاحية Manage Roles ورتبته أعلى من رتبتي مواطن وشرطي.',
        ephemeral: true
      }).catch(() => {});
      return;
    }
  }

  const updatedEmbeds = interaction.message.embeds.map((old, i) => {
    const next = EmbedBuilder.from(old);
    if (i === 0) {
      next.setTitle(`${approved ? '✅ تم قبول' : '❌ تم رفض'} التقديم — NEON RP`)
        .addFields({ name: 'قرار الإدارة', value: `${approved ? 'مقبول' : 'مرفوض'} بواسطة ${interaction.user.tag}\n${roleMessage}`, inline: false });
    }
    return next;
  });
  await interaction.update({ embeds: updatedEmbeds, components: [] }).catch(async () => {
    await interaction.reply({ content: 'تعذر تحديث حالة الطلب.', ephemeral: true }).catch(() => {});
  });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`NEON RP application API listening on port ${port}`));
