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
    let slackMessage = null;

    // Helper: formatear fechas en hora Lima
    const fmtDate = (unixSec) =>
      new Date(
        (unixSec || Math.floor(Date.now() / 1000)) * 1000
      ).toLocaleString("es-PE", { timeZone: "America/Lima" });

    // Helper: SIEMPRE resuelve el nombre desde el Stripe Customer (customer.name).
    // Devuelve "Sin nombre" si no hay customerId o el Customer no tiene name.
    const resolveCustomerName = async (customerId) => {
      if (!customerId) return "Sin nombre";
      try {
        const c = await getStripeCustomer(customerId);
        return c?.name || "Sin nombre";
      } catch (err) {
        console.error("No se pudo obtener el Customer:", err.message);
        return "Sin nombre";
      }
    };

    // Helper: resuelve email desde el Customer; si falla, usa fallback.
    const resolveCustomerEmail = async (customerId, fallback) => {
      if (!customerId) return fallback || "Sin email";
      try {
        const c = await getStripeCustomer(customerId);
        return c?.email || fallback || "Sin email";
      } catch {
        return fallback || "Sin email";
      }
    };

    // ========== CHARGE.SUCCEEDED ==========
    if (event.type === "charge.succeeded") {
      const charge = event.data.object;
      const name = await resolveCustomerName(charge.customer);
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

      slackMessage = {
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
      // El dispute no trae customer directamente; intentamos via charge expandido si está
      const customerId =
        typeof dispute.charge === "object"
          ? dispute.charge?.customer
          : null;
      const name = await resolveCustomerName(customerId);

      const amount = (dispute.amount / 100).toFixed(2);
      const currency = dispute.currency.toUpperCase();
      const reason = dispute.reason || "no especificada";
      const status = dispute.status || "needs_response";
      const chargeId =
        typeof dispute.charge === "string"
          ? dispute.charge
          : dispute.charge?.id || "—";
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
            fields: [
              { type: "mrkdwn", text: `*Nombre:*\n${name}` },
              { type: "mrkdwn", text: `*Monto disputado:*\n${amount} ${currency}` },
              { type: "mrkdwn", text: `*Razón:*\n${reason}` },
              { type: "mrkdwn", text: `*Estado:*\n${status}` },
              { type: "mrkdwn", text: `*Evidencia hasta:*\n${dueBy}` },
              { type: "mrkdwn", text: `*Charge:*\n\`${chargeId}\`` },
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

    // ========== CHECKOUT.SESSION.* ==========
    else if (
      event.type === "checkout.session.completed" ||
      event.type === "checkout.session.async_payment_succeeded" ||
      event.type === "checkout.session.async_payment_failed" ||
      event.type === "checkout.session.expired"
    ) {
      const session = event.data.object;
      const name = await resolveCustomerName(session.customer);
      const email =
        session.customer_details?.email ||
        session.customer_email ||
        "Sin email";
      const amount = ((session.amount_total ?? 0) / 100).toFixed(2);
      const currency = (session.currency || "usd").toUpperCase();
      const mode = session.mode || "payment";
      const paymentStatus = session.payment_status || "unknown";

      let header = "✅ Checkout completado";
      if (event.type === "checkout.session.async_payment_succeeded")
        header = "✅ Pago asíncrono confirmado";
      if (event.type === "checkout.session.async_payment_failed")
        header = "❌ Pago asíncrono falló";
      if (event.type === "checkout.session.expired")
        header = "⌛ Checkout expirado";

      slackMessage = {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: header, emoji: true },
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Nombre:*\n${name}` },
              { type: "mrkdwn", text: `*Email:*\n${email}` },
              { type: "mrkdwn", text: `*Monto:*\n${amount} ${currency}` },
              { type: "mrkdwn", text: `*Modo:*\n${mode}` },
              { type: "mrkdwn", text: `*Estado pago:*\n${paymentStatus}` },
              { type: "mrkdwn", text: `*Fecha:*\n${fmtDate(session.created)}` },
            ],
          },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `\`Session: ${session.id}\` • \`Event: ${event.type}\``,
              },
            ],
          },
          { type: "divider" },
        ],
      };
    }

    // ========== CUSTOMER.SUBSCRIPTION.* ==========
    else if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.deleted" ||
      event.type === "customer.subscription.paused"
    ) {
      const sub = event.data.object;
      const name = await resolveCustomerName(sub.customer);
      const email = await resolveCustomerEmail(sub.customer, null);
      const status = sub.status || "—";
      const item = sub.items?.data?.[0];
      const price = item?.price;
      const amount =
        price?.unit_amount != null
          ? (price.unit_amount / 100).toFixed(2)
          : "—";
      const currency = (price?.currency || "usd").toUpperCase();
      const interval = price?.recurring?.interval
        ? `${price.recurring.interval_count || 1}/${price.recurring.interval}`
        : "—";
      const productName = item?.price?.nickname || price?.product || "—";
      const periodEnd = sub.current_period_end
        ? fmtDate(sub.current_period_end)
        : "—";

      let header = "🆕 Suscripción creada";
      if (event.type === "customer.subscription.deleted")
        header = "🗑️ Suscripción cancelada";
      if (event.type === "customer.subscription.paused")
        header = "⏸️ Suscripción pausada";

      slackMessage = {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: header, emoji: true },
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Nombre:*\n${name}` },
              { type: "mrkdwn", text: `*Email:*\n${email}` },
              { type: "mrkdwn", text: `*Plan:*\n${productName}` },
              {
                type: "mrkdwn",
                text: `*Precio:*\n${amount} ${currency} / ${interval}`,
              },
              { type: "mrkdwn", text: `*Estado:*\n${status}` },
              { type: "mrkdwn", text: `*Próxima renovación:*\n${periodEnd}` },
            ],
          },
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `\`Subscription: ${sub.id}\` • \`Customer: ${sub.customer}\``,
              },
            ],
          },
          { type: "divider" },
        ],
      };
    }

    // ========== INVOICE.* ==========
    else if (
      event.type === "invoice.paid" ||
      event.type === "invoice.payment_succeeded" ||
      event.type === "invoice.payment_failed"
    ) {
      const invoice = event.data.object;
      const name = await resolveCustomerName(invoice.customer);
      const email =
        invoice.customer_email ||
        (await resolveCustomerEmail(invoice.customer, null));
      const amount = (
        (invoice.amount_paid ?? invoice.amount_due ?? 0) / 100
      ).toFixed(2);
      const currency = (invoice.currency || "usd").toUpperCase();
      const status = invoice.status || "—";
      const number = invoice.number || invoice.id;
      const hostedUrl = invoice.hosted_invoice_url || null;
      const pdf = invoice.invoice_pdf || null;

      let header = "🧾 Factura pagada";
      if (event.type === "invoice.payment_succeeded")
        header = "✅ Pago de factura confirmado";
      if (event.type === "invoice.payment_failed")
        header = "❌ Pago de factura falló";

      const links = [
        hostedUrl ? `<${hostedUrl}|Ver factura>` : null,
        pdf ? `<${pdf}|PDF>` : null,
      ]
        .filter(Boolean)
        .join(" • ");

      slackMessage = {
        blocks: [
          {
            type: "header",
            text: { type: "plain_text", text: header, emoji: true },
          },
          {
            type: "section",
            fields: [
              { type: "mrkdwn", text: `*Nombre:*\n${name}` },
              { type: "mrkdwn", text: `*Email:*\n${email}` },
              { type: "mrkdwn", text: `*Monto:*\n${amount} ${currency}` },
              { type: "mrkdwn", text: `*Estado:*\n${status}` },
              { type: "mrkdwn", text: `*N° factura:*\n${number}` },
              { type: "mrkdwn", text: `*Fecha:*\n${fmtDate(invoice.created)}` },
            ],
          },
          ...(links
            ? [{ type: "context", elements: [{ type: "mrkdwn", text: links }] }]
            : []),
          {
            type: "context",
            elements: [
              {
                type: "mrkdwn",
                text: `\`Invoice: ${invoice.id}\` • \`Event: ${event.type}\``,
              },
            ],
          },
          { type: "divider" },
        ],
      };
    }

    // ========== Cualquier otro evento ==========
    else {
      console.log(`Evento ignorado: ${event.type}`);
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
