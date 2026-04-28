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

    // Nombre: priorizar el del Customer en Stripe, fallback a billing_details
    let name = charge.billing_details?.name || "Sin nombre";
    if (charge.customer) {
      try {
        const customer = await getStripeCustomer(charge.customer);
        if (customer?.name) name = customer.name;
      } catch (err) {
        console.error("No se pudo obtener el Customer, uso billing_details:", err.message);
      }
    }

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
      console.error("Error
