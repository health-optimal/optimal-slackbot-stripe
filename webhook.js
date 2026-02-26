const crypto = require("crypto");
const https = require("https");

/**
 * Vercel Serverless Function: recibe eventos de Stripe y los postea a Slack
 * con nombre, email y monto del cliente.
 */

// Necesitamos el raw body para verificar la firma de Stripe
export const config = {
  api: {
    bodyParser: false,
  },
};

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).send("Method not allowed");
  }

  const signature = req.headers["stripe-signature"];
  if (!signature) {
    return res.status(400).send("No Stripe signature found");
  }

  const rawBody = await getRawBody(req);

  let event;
  try {
    event = verifyStripeSignature(rawBody.toString(), signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Signature verification failed:", err.message);
    return res.status(400).send(`Webhook signature verification failed: ${err.message}`);
  }

  if (event.type === "charge.succeeded") {
    const charge = event.data.object;

    const name = charge.billing_details?.name || "Sin nombre";
    const email = charge.billing_details?.email || charge.receipt_email || "Sin email";
    const amount = (charge.amount / 100).toFixed(2);
    const currency = charge.currency.toUpperCase();
    const chargeId = charge.id;
    const description = charge.description || "Sin descripción";
    const paymentMethod = charge.payment_method_details?.type || "desconocido";
    const receiptUrl = charge.receipt_url || null;
    const created = new Date(charge.created * 1000).toLocaleString("es-PE", {
      timeZone: "America/Lima",
    });

    const slackMessage = {
      blocks: [
        {
          type: "header",
          text: {
            type: "plain_text",
            text: "✅ Pago recibido",
            emoji: true,
          },
        },
        {
          type: "section",
          fields: [
            { type: "mrkdwn", text: `*Nombre:*\n${name}` },
            { type: "mrkdwn", text: `*Email:*\n${email}` },
            { type: "mrkdwn", text: `*Monto:*\n${amount} ${currency}` },
            { type: "mrkdwn", text: `*Método:*\n${paymentMethod}` },
            { type: "mrkdwn", text: `*Descripción:*\n${description}` },
            { type: "mrkdwn", text: `*Fecha:*\n${created}` },
          ],
        },
        {
          type: "context",
          elements: [
            {
              type: "mrkdwn",
              text: `Charge ID: \`${chargeId}\`${receiptUrl ? ` • <${receiptUrl}|Ver recibo>` : ""}`,
            },
          ],
        },
        { type: "divider" },
      ],
    };

    try {
      await postToSlack(slackMessage);
      console.log(`Notificación enviada: ${chargeId} - ${name} - ${amount} ${currency}`);
    } catch (err) {
      console.error("Error posting to Slack:", err.message);
      return res.status(500).send("Error posting to Slack");
    }
  }

  res.status(200).json({ received: true });
}

function verifyStripeSignature(payload, signatureHeader, secret) {
  const parts = signatureHeader.split(",").reduce((acc, part) => {
    const [key, value] = part.split("=");
    acc[key.trim()] = value;
    return acc;
  }, {});

  const timestamp = parts["t"];
  const expectedSig = parts["v1"];

  if (!timestamp || !expectedSig) {
    throw new Error("Invalid signature header format");
  }

  const tolerance = 300;
  const now = Math.floor(Date.now() / 1000);
  if (now - parseInt(timestamp) > tolerance) {
    throw new Error("Timestamp too old");
  }

  const signedPayload = `${timestamp}.${payload}`;
  const computedSig = crypto
    .createHmac("sha256", secret)
    .update(signedPayload, "utf8")
    .digest("hex");

  if (computedSig !== expectedSig) {
    throw new Error("Signatures do not match");
  }

  return JSON.parse(payload);
}

function postToSlack(message) {
  return new Promise((resolve, reject) => {
    const url = new URL(process.env.SLACK_WEBHOOK_URL);
    const data = JSON.stringify(message);

    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(data),
      },
    };

    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        if (res.statusCode === 200) resolve(body);
        else reject(new Error(`Slack responded with ${res.statusCode}: ${body}`));
      });
    });

    req.on("error", reject);
    req.write(data);
    req.end();
  });
}
