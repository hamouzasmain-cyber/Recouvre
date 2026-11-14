const crypto = require('crypto');

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verify(raw, header, secret) {
  if (!header || !secret) return false;
  let t = '';
  const sigs = [];
  header.split(',').forEach((p) => {
    const [k, v] = p.split('=');
    if (k === 't') t = v;
    if (k === 'v1') sigs.push(v);
  });
  if (!t || !sigs.length) return false;
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(t + '.' + raw.toString('utf8'))
    .digest('hex');
  return sigs.some(
    (s) =>
      s.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))
  );
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();

  const raw = await readRaw(req);
  if (!verify(raw, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)) {
    return res.status(400).send('Signature invalide');
  }

  const event = JSON.parse(raw.toString('utf8'));

  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    const email = s.customer_details && s.customer_details.email;
    if (email) {
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + process.env.RESEND_API_KEY,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'Recouvre <onboarding@resend.dev>',
          to: [email],
          reply_to: process.env.REPLY_TO_EMAIL,
          subject: 'Votre abonnement Recouvre est actif',
          text:
            'Bonjour,\n\nMerci, votre abonnement Recouvre est bien enregistré.\n\n' +
            'Votre accès au tableau et aux relances automatiques arrive très bientôt : je vous écris dès qu’il est prêt.\n\n' +
            'Vous avez 14 jours pour changer d’avis : répondez simplement à cet email avec « Je veux être remboursé », sans justification. Le remboursement part sous 5 jours ouvrés.\n\n' +
            'Smain, Recouvre',
        }),
      });
      if (!r.ok) return res.status(500).send('Email non envoyé');
    }
  }

  return res.status(200).json({ received: true });
};
