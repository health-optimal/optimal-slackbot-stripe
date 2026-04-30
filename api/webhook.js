import crypto from "node:crypto";
import https from "node:https";
import { URL } from "node:url";

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

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(timestamp)) > 300) {
    throw new Error("Timestamp fuera de tolerancia");
  }

  const signedPayload = `${timestamp}.${payload}`;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(signedPayload, "utf8")
    .digest("hex");

  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(v1, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error("Firma no coincide");
  }

  return JSON.parse(payload);
}

function httpsRequest({ hostname, path, method, headers, payload }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { hostname, path, method, headers },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function getStripeCustomer(customerId) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY no configurado");

  const { status, body } = await httpsRequest({
    hostname: "api.stripe.com",
    path: `/v1/customers/${encodeURIComponent(customerId)}`,
    method: "GET",
    headers: { Authorization: `Bearer ${key}` },
  });

  if (status >= 400) throw new Error(`Stripe API ${status}: ${body}`);
  return JSON.parse(body);
}

async function getStripeCharge(chargeId) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error("STRIPE_SECRET_KEY no configurado");

  const { status, body } = await httpsRequest({
    hostname: "api.stripe.com",
    path: `/v1/charges/${encodeURIComponent(chargeId)}`,
    method: "GET",
    headers: { Authorization: `Bearer ${key}` },
  });

  if (status >= 400) throw new Error(`Stripe API ${status}: ${body}`);
  return JSON.parse(body);
}

async function postToSlack(message) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  if (!webhookUrl) throw new Error("SLACK_WEBHOOK_URL no configurado");

  const url = new URL(webhookUrl);
  const payload = JSON.stringify(message);

  const { status, body } = await httpsRequest({
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(payload),
    },
    payload,
  });

  if (status >= 400) throw new Error(`Slack webhook ${status}: ${body}`);
}

// ---------- Handler ----------

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
    // Solo procesamos charge.succeeded y charge.dispute.created.
    const handledTypes = ["charge.succeeded", "charge.dispute.created"];
    if (!handledTypes.includes(event.type)) {
      console.log(`Evento ignorado: ${event.type}`);
      return res.status(200).json({ received: true });
    }

    const fmtDate = (unixSec) =>
      new Date(
        (unixSec || Math.floor(Date.now() / 1000)) * 1000
      ).toLocaleString("es-PE", { timeZone: "America/Lima" });

    const fetchCustomer = async (customerId) => {
      if (!customerId) {
        console.log("fetchCustomer: customerId vacío");
        return null;
      }
      try {
        const c = await getStripeCustomer(customerId);
        console.log(
          `fetchCustomer OK: id=${customerId} name=${c?.name || "(vacío)"} email=${c?.email || "(vacío)"}`
        );
        return c;
      } catch (err) {
        console.error(`fetchCustomer FAIL: id=${customerId} err=${err.message}`);
        return null;
      }
    };

    const buildClientPayerFields = ({
      customerName,
      customerEmail,
      payerName,
      payerEmail,
    }) => [
      { type: "mrkdwn", text: `*Nombre del cliente:*\n${customerName || "—"}` },
      { type: "mrkdwn", text: `*Email del cliente:*\n${customerEmail || "—"}` },
      { type: "mrkdwn", text: `*Nombre de quien paga:*\n${payerName || "—"}` },
      { type: "mrkdwn", text: `*Email de quien paga:*\n${payerEmail || "—"}` },
    ];

    let slackMessage = null;

    // ========== CHARGE.SUCCEEDED ==========
    if (event.type === "charge.succeeded") {
      const charge = event.data.object;
      const customer = await fetchCustomer(charge.customer);

      const customerName = customer?.name || "Sin nombre";
      const customerEmail = customer?.email || "Sin email";
      const payerName = charge.billing_details?.name || "Sin nombre";
      const payerEmail =
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

      slackMessage = {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: "✅ Pago recibido", emoji: true },
          },
          {
            type: "section",
            fields: buildClientPayerFields({
              customerName,
              customerEmail,
              payerName,
              payerEmail,
            }),
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Monto:*\n${amount} ${currency}` },
              { type: "mrkdwn", text: `*Método:*\n${paymentMethod}` },
              { type: "mrkdwn", text: `*Descripción:*\n${description}` },
              { type: "mrkdwn", text: `*Fecha:*\n${fmtDate(charge.created)}` },
            ],
          },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `\`Charge ID: ${chargeId}\`${
                  receiptUrl ? ` • <${receiptUrl}|Ver recibo>` : ""
                }`,
              },
            ],
          },
          { type: "divider" },
        ],
      };
    }

    // ========== CHARGE.DISPUTE.CREATED ==========
    else if (event.type === "charge.dispute.created") {
      const dispute = event.data.object;

      // dispute.charge suele venir como string (charge id). Lo expandimos
      // contra la API para poder mostrar billing_details y customer info.
      const chargeId =
        typeof dispute.charge === "string"
          ? dispute.charge
          : dispute.charge?.id || null;

      let charge = null;
      if (typeof dispute.charge === "object" && dispute.charge !== null) {
        charge = dispute.charge;
      } else if (chargeId) {
        try {
          charge = await getStripeCharge(chargeId);
        } catch (err) {
          console.error(`getStripeCharge FAIL: id=${chargeId} err=${err.message}`);
        }
      }

      const customer = await fetchCustomer(charge?.customer);

      const customerName = customer?.name || "Sin nombre";
      const customerEmail = customer?.email || "Sin email";
      const payerName = charge?.billing_details?.name || "Sin nombre";
      const payerEmail =
        charge?.billing_details?.email ||
        charge?.receipt_email ||
        "Sin email";

      const amount = (dispute.amount / 100).toFixed(2);
      const currency = dispute.currency.toUpperCase();
      const reason = dispute.reason || "no especificada";
      const status = dispute.status || "needs_response";
      const dueBy = dispute.evidence_details?.due_by
        ? fmtDate(dispute.evidence_details.due_by)
        : "—";

      slackMessage = {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: "🚨 Disputa abierta", emoji: true },
          },
          {
            type: "section",
            fields: buildClientPayerFields({
              customerName,
              customerEmail,
              payerName,
              payerEmail,
            }),
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Monto disputado:*\n${amount} ${currency}` },
              { type: "mrkdwn", text: `*Razón:*\n${reason}` },
              { type: "mrkdwn", text: `*Estado:*\n${status}` },
              { type: "mrkdwn", text: `*Evidencia hasta:*\n${dueBy}` },
              { type: "mrkdwn", text: `*Charge:*\n\`${chargeId || "—"}\`` },
            ],
          },
          {
            type: "context",
            elements: [{ type: "mrkdwn", text: `\`Dispute ID: ${dispute.id}\`` }],
          },
          { type: "divider" },
        ],
      };
    }

    if (slackMessage) {
      try {
        await postToSlack(slackMessage);
        console.log(
          `Notificación enviada para ${event.type} (${event.id})`
        );
      } catch (err) {
        console.error("Error posteando a Slack:", err.message);
      }
    }

    return res.status(200).json({ received: true });
  } catch (err) {
    console.error("Error procesando evento:", err);
    return res.status(500).send("Internal error");
  }
}
