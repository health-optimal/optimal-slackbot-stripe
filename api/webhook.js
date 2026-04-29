const crypto = require("crypto");
const https = require("https");
const { URL } = require("url");

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

// ---------- Helpers ----------

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Verifica la firma de Stripe sin usar la librería oficial.
 * Stripe manda un header con formato: t=<ts>,v1=<sig>,v0=<sig>
 */
function verifyStripeSignature(payload, header, secret) {
  if (!secret) throw new Error("STRIPE_WEBHOOK_SECRET no configurado");
  if (!header) throw new Error("Falta header stripe-signature");

  const parts = Object.fromEntries(
    header.split(",").map((kv) => {
      const [k, ...rest] = kv.split("=");
      return [k.trim(), rest.join("=").trim()];
    })
  );

  const timestamp = parts.t;
  const v1 = parts.v1;
  if (!timestamp || !v1) throw new Error("Header de firma inválido");

  // Tolerancia de 5 minutos contra replay
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > 300) {
    throw new Error("Timestamp fuera de tolerancia");
  }

  const signed = `${timestamp}.${payload}`;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(signed, "utf8")
    .digest("hex");

  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(v1, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("Firma no coincide");
  }

  return JSON.parse(payload);
}

/**
 * Helper genérico para hacer requests HTTPS sin dependencias externas.
 */
function httpsRequest(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/**
 * Obtiene el Customer de Stripe vía REST API.
 */
async function getStripeCustomer(customerId) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY no configurado");

  const { status, body } = await httpsRequest({
    hostname: "api.stripe.com",
    path: `/v1/customers/${encodeURIComponent(customerId)}`,
    method: "GET",
    headers: {
      Authorization: `Bearer ${key}`,
    },
  });

  if (status >= 400) {
    throw new Error(`Stripe API ${status}: ${body}`);
  }
  return JSON.parse(body);
}

/**
 * Postea un mensaje (con blocks) a un Incoming Webhook de Slack.
 */
async function postToSlack(message) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) throw new Error("SLACK_WEBHOOK_URL no configurado");

  const url = new URL(webhookUrl);
  const payload = JSON.stringify(message);

  const { status, body } = await httpsRequest(
    {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    },
    payload
  );

  if (status >= 400) {
    throw new Error(`Slack webhook ${status}: ${body}`);
  }
}

// ---------- Handler principal ----------

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
    event = verifyStripeSignature(
      rawBody.toString("utf8"),
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error("Signature verification failed:", err.message);
    return res
      .status(400)
      .send(`Webhook signature verification failed: ${err.message}`);
  }

  try {
    if (event.type === "charge.succeeded") {
      const charge = event.data.object;

      // Nombre: priorizar el del Customer en Stripe, fallback a billing_details
      let name = charge.billing_details?.name || "Sin nombre";
      if (charge.customer) {
        try {
          const customer = await getStripeCustomer(charge.customer);
          if (customer?.name) name = customer.name;
        } catch (err) {
          console.error(
            "No se pudo obtener el Customer, uso billing_details:",
            err.message
          );
        }
      }

      const email =
        charge.billing_details?.email ||
        charge.receipt_email ||
        "Sin email";
      const amount = (charge.amount / 100).toFixed(2);
      const currency = charge.currency.toUpperCase();
      const chargeId = charge.id;
      const description = charge.description || "Sin descripción";
      const paymentMethod =
        charge.payment_method_details?.type || "desconocido";
      const receiptUrl = charge.receipt_url || null;
      const created = new Date(charge.created * 1000).toLocaleString("es-PE", {
        timeZone: "America/Lima",
      });

      const slackMessage = {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: "✅ Pago recibido", emoji: true },
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
                text: `Charge ID: \`${chargeId}\`${
                  receiptUrl ? ` • <${receiptUrl}|Ver recibo>` : ""
                }`,
              },
            ],
          },
          { type: "divider" },
        ],
      };

      try {
        await postToSlack(slackMessage);
        console.log(
          `Notificación enviada: ${chargeId} - ${name} - ${amount} ${currency}`
        );
      } catch (err) {
        console.error("Error posteando a Slack:", err.message);
        // Igual respondemos 200 para que Stripe no reintente en loop
      }
    } else {
      console.log(`Evento ignorado: ${event.type}`);
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error("Error procesando evento:", err);
    return res.status(500).send("Internal error");
  }
}
