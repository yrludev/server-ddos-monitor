const fs = require('fs');
const { execSync } = require('child_process');
const axios = require('axios');

const raw = fs.readFileSync('config.json', 'utf8');
const data = JSON.parse(raw);

const webhook_url = data.webhook_url;
const mbit_threshold = Number(data.mbit_threshold || 0);
const cooldown = Number(data.cooldown || 60) * 1000;
const iface = data.interface || 'eth0';

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function readIfaceStats() {
  const content = fs.readFileSync('/proc/net/dev', 'utf8');
  const lines = content.split('\n').slice(2);
  for (const line of lines) {
    const parts = line.split(':');
    if (parts.length < 2) continue;
    const name = parts[0].trim();
    if (name !== iface) continue;
    const fields = parts[1].trim().split(/\s+/);
    const bytes = Number(fields[0]);
    const packets = Number(fields[1]);
    return { bytes, packets };
  }
  throw new Error(`/proc/net/dev does not contain interface ${iface}`);
}

function formatSize(B) {
  B = Number(B);
  const KB = 125;
  const MB = 125000;
  const GB = 1.25e+8;
  const TB = Math.pow(KB, 4);

  if (B < KB) return `${B} ${B === 1 ? 'Byte' : 'Bytes'}`;
  if (B >= KB && B < MB) return `${(B / KB).toFixed(2)} Kb/s`;
  if (B >= MB && B < GB) return `${(B / MB).toFixed(2)} Mb/s`;
  if (B >= GB && B < TB) return `${(B / GB).toFixed(2)} GB`;
  return `${(B / TB).toFixed(2)} TB`;
}

async function sendWebhook(attacksize, pps, pcapname) {
  if (!webhook_url) return console.warn('No webhook_url configured');
  const embed = {
    title: 'Attack Detected',
    description: 'Attack Is Being Mitigated!',
    color: 242424,
    fields: [
      { name: 'Server Identity', value: '`45.41.***.**` [New York]', inline: false },
      { name: 'Dump Result', value: pcapname, inline: false },
      { name: 'Attack Size', value: attacksize, inline: false },
      { name: 'Peak Packets Per Second', value: String(pps), inline: false }
    ],
    image: { url: 'https://media.discordapp.net/attachments/993213455114965034/1001512149258080276/download.jpeg' }
  };

  try {
    await axios.post(webhook_url, { embeds: [embed] }, { timeout: 10000 });
    console.log('Webhook sent');
  } catch (err) {
    console.error('Failed to send webhook:', err.message);
  }
}

(async function main() {
  console.log('Starting traffic monitor for interface', iface);

  while (true) {
    try {
      const old = readIfaceStats();
      await sleep(1000);
      const now = readIfaceStats();
      const incomingBytes = now.bytes - old.bytes;
      const incomingPackets = now.packets - old.packets;
      const incomingMbits = incomingBytes / 125000; // match original script

      process.stdout.write('\x1Bc'); // clear console
      console.log('Packets:', incomingPackets);
      console.log('Incoming:', formatSize(incomingBytes));

      if (incomingMbits > mbit_threshold) {
        console.log('Under Attack!');
        await sleep(2000);

        // double-check
        const old2 = readIfaceStats();
        await sleep(1000);
        const now2 = readIfaceStats();
        const incomingBytes2 = now2.bytes - old2.bytes;
        const incomingPackets2 = now2.packets - old2.packets;
        const incomingMbits2 = incomingBytes2 / 125000;

        if (incomingMbits2 > mbit_threshold) {
          const pcapName = `${new Date().toISOString().replace(/:/g, '-')}.pcap`;
          await sendWebhook(formatSize(incomingBytes2), incomingPackets2, pcapName);

          try {
            console.log('Starting tcpdump to capture 5000 packets ->', pcapName);
            execSync(`tcpdump -n -s0 -c 5000 -w '${pcapName}'`, { stdio: 'inherit' });
          } catch (e) {
            console.error('tcpdump failed or not available:', e.message);
          }

          await sleep(cooldown);
        } else {
          console.log('False positive.');
        }

        // check if still over threshold
        const old3 = readIfaceStats();
        await sleep(1000);
        const now3 = readIfaceStats();
        const incomingMbits3 = (now3.bytes - old3.bytes) / 125000;

        if (incomingMbits3 > mbit_threshold) {
          console.log('Attack not over yet!');
          await sleep(150000);
        } else {
          console.log('Attack Over!');
        }
      }
    } catch (err) {
      console.error('Error in monitor loop:', err.message);
      await sleep(5000);
    }
  }
})();
