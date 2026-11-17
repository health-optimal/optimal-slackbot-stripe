// El webhook de punta a punta, sin red: https.request se reemplaza por un doble que anota cada llamada y responde
// lo que el test indique. Nada sale a Stripe ni a Slack.
import { beforeEach, afterEach, mock, test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import https from "node:https";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import handler from "../api/webhook.js";

const SECRET = "secreto-de-prueba";
const MAIN = "https://hooks.slack.test/services/principal";
const LEADS = "https://hooks.slack.test/services/leads";

let calls;
let responses; // por hostname+ruta: { status, body }

function respond(opts) {
  if (opts.hostname === "api.stripe.com" && opts.path.startsWith("/v1/checkout/sessions")) return responses.session;
  if (opts.hostname === "hooks.slack.test") return opts.path.endsWith("/leads") ? responses.leads : responses.main;
  return { status: 404, body: "{}" };
}

beforeEach(() => {
  calls = [];
  responses = {
    session: { status: 200, body: JSON.stringify({ data: [] }) },
    main: { status: 200, body: "ok" },
    leads: { status: 200, body: "ok" },
  };
  process.env.STRIPE_WEBHOOK_SECRET_MX = SECRET;
  process.env.STRIPE_SECRET_KEY_MX = "clave-de-prueba";
  process.env.SLACK_WEBHOOK_URL = MAIN;
  process.env.SLACK_WEBHOOK_URL_LEADS = LEADS;
  delete process.env.STRIPE_WEBHOOK_SECRET;
  mock.method(console, "log", () => {});
  mock.method(console, "error", () => {});
  mock.method(https, "request", (opts, cb) => {
    const call = { ...opts, payload: null };
    calls.push(call);
    let onError = () => {};
    let onTimeout = null;
    return {
      on(name, fn) { if (name === "error") onError = fn; },
      setTimeout(ms, fn) { call.timeoutMs = ms; onTimeout = fn; },
      destroy(err) { onError(err); },
      write(p) { call.payload = p; },
      end() {
        const { status, body, hang, error } = respond(opts);
        if (error) return onError(new Error(error));
        // Nunca responde: lo único que puede pasar es que venza el tope que haya puesto quien llama.
        if (hang) return onTimeout?.();
        const res = new EventEmitter();
        res.statusCode = status;
        cb(res);
        res.emit("data", Buffer.from(body));
        res.emit("end");
      },
    };
  });
});
afterEach(() => mock.restoreAll());

async function send(event) {
  const payload = JSON.stringify(event);
  const t = Math.floor(Date.now() / 1000);
  const v1 = crypto.createHmac("sha256", SECRET).update(`${t}.${payload}`, "utf8").digest("hex");
  const req = Readable.from([Buffer.from(payload)]);
  req.method = "POST";
  req.headers = { "stripe-signature": `t=${t},v1=${v1}` };
  const res = { code: null, status(c) { this.code = c; return this; }, json() { return this; }, send() { return this; } };
  await handler(req, res);
  return res.code;
}

const charge = (over = {}) => ({
  id: "evt_1",
  type: "charge.succeeded",
  data: {
    object: {
      id: "ch_1", amount: 239920, currency: "mxn", created: 1794000000, customer: null, payment_intent: "pi_1",
      metadata: { origin: "optimal_web", plan: "Core", country: "MX", name: "Ana Prueba", phone: "+52 999 000 6002" },
      billing_details: { name: "Ana Prueba", email: "ana@correo.test" },
      ...over,
    },
  },
});
const withCoupon = () => {
  responses.session.body = JSON.stringify({
    data: [{
      amount_subtotal: 299900, amount_total: 239920, total_details: { amount_discount: 59980 },
      discounts: [{ coupon: "co_1", promotion_code: { id: "promo_1", code: "HOTBOOK20" } }],
    }],
  });
};

const slackPosts = () => calls.filter((c) => c.hostname === "hooks.slack.test");
const stripeLookups = () => calls.filter((c) => c.hostname === "api.stripe.com" && c.path.startsWith("/v1/checkout/sessions"));
const texts = (post) => JSON.parse(post.payload).blocks.flatMap((b) => (b.fields || []).map((f) => f.text));

test("cobro de la web con cupón: el canal de siempre sale igual y #leads-web lleva cupón y descuento", async () => {
  withCoupon();
  assert.equal(await send(charge()), 200);

  const [lookup] = stripeLookups();
  assert.match(lookup.path, /payment_intent=pi_1/);
  assert.equal(lookup.headers.Authorization, "Bearer clave-de-prueba");

  const [main, leads] = slackPosts();
  assert.deepEqual([main.path, leads.path], ["/services/principal", "/services/leads"]);
  // El canal de siempre no cambia: el monto, y nada del cupón.
  const t = texts(main);
  assert.ok(t.includes("*Monto:*\n2399.20 MXN"));
  assert.equal(t.some((x) => /Cupón|Descuento|Precio de lista/.test(x)), false);
  // #leads-web: el formato corto de los avisos de lead, con los datos del metadata del cobro.
  assert.deepEqual(JSON.parse(leads.payload), {
    text: [
      "💰 *Pago recibido · <https://www.optimal.lat|Optimal Web>*",
      "👤 *Nombre:* Ana Prueba",
      "🌎 *País:* México",
      "📋 *Plan:* Core",
      "💵 *Monto:* 2399.20 MXN",
      "🎟️ *Cupón:* HOTBOOK20",
      "🏷️ *Descuento:* 20 % (599.80 MXN)",
      "📱 *Teléfono (WhatsApp):* <https://wa.me/529990006002|+529990006002>",
      "✉️ *Correo:* <mailto:ana@correo.test|ana@correo.test>",
    ].join("\n"),
  });
});

test("cobro de la web sin cupón: los dos canales, sin líneas de cupón", async () => {
  assert.equal(await send(charge()), 200);
  const [main, leads] = slackPosts();
  assert.equal(texts(main).some((t) => /Cupón|Descuento|Precio de lista/.test(t)), false);
  assert.doesNotMatch(JSON.parse(leads.payload).text, /Cupón|Descuento/);
  assert.match(JSON.parse(leads.payload).text, /\n💵 \*Monto:\* 2399\.20 MXN\n/);
});

test("cobro de un origen sin etiqueta ni país conocido: se muestran tal cual, escapados", async () => {
  const meta = { origin: "otro <!channel>", plan: "Apex", country: "AR", name: "", phone: "" };
  assert.equal(await send(charge({ metadata: meta, receipt_email: "recibo@correo.test", billing_details: { name: "Quien Paga", email: null } })), 200);
  assert.deepEqual(JSON.parse(slackPosts()[1].payload).text.split("\n"), [
    "💰 *Pago recibido · otro &lt;!channel&gt;*",
    "👤 *Nombre:* Quien Paga",
    "🌎 *País:* AR",
    "📋 *Plan:* Apex",
    "💵 *Monto:* 2399.20 MXN",
    "📱 *Teléfono (WhatsApp):* —",
    "✉️ *Correo:* <mailto:recibo@correo.test|recibo@correo.test>",
  ]);
});

test("sin SLACK_WEBHOOK_URL_LEADS: nada nuevo, ni la consulta a Stripe", async () => {
  delete process.env.SLACK_WEBHOOK_URL_LEADS;
  withCoupon();
  assert.equal(await send(charge()), 200);
  assert.equal(stripeLookups().length, 0);
  assert.deepEqual(slackPosts().map((p) => p.path), ["/services/principal"]);
});

test("el aviso del canal de siempre es idéntico con cupón, sin cupón, con la consulta fallida y sin #leads-web", async () => {
  const mainPayload = async (setup) => {
    calls.length = 0;
    setup();
    await send(charge());
    return slackPosts().find((p) => p.path === "/services/principal").payload;
  };
  const sinCupon = await mainPayload(() => {});
  assert.equal(await mainPayload(withCoupon), sinCupon);
  assert.equal(await mainPayload(() => { responses.session = { status: 500, body: "{}" }; }), sinCupon);
  assert.equal(await mainPayload(() => { delete process.env.SLACK_WEBHOOK_URL_LEADS; }), sinCupon);
});

test("cobro que no es de los sitios (sin origin): no consulta la sesión ni avisa en leads", async () => {
  withCoupon();
  assert.equal(await send(charge({ metadata: {} })), 200);
  assert.equal(stripeLookups().length, 0);
  assert.deepEqual(slackPosts().map((p) => p.path), ["/services/principal"]);
});

test("cobro de la web sin payment_intent: no consulta la sesión y avisa igual", async () => {
  assert.equal(await send(charge({ payment_intent: null })), 200);
  assert.equal(stripeLookups().length, 0);
  assert.equal(slackPosts().length, 2);
});

test("Stripe falla al consultar la sesión: el aviso sale igual, sin cupón", async () => {
  responses.session = { status: 500, body: "{}" };
  assert.equal(await send(charge()), 200);
  const [main, leads] = slackPosts();
  // No se confunde con «no hubo cupón»: #leads-web dice que no se pudo consultar. El canal de siempre, nada.
  assert.equal(texts(main).some((x) => /Cupón/.test(x)), false);
  assert.ok(JSON.parse(leads.payload).text.split("\n").includes("🎟️ *Cupón:* no se pudo consultar"));
});

test("Stripe no responde al consultar la sesión: vence el tope y el aviso sale igual", async () => {
  responses.session = { hang: true };
  assert.equal(await send(charge()), 200);
  assert.equal(stripeLookups()[0].timeoutMs, 3000);
  assert.equal(slackPosts().length, 2);
});

test("error de red al consultar la sesión: el aviso sale igual", async () => {
  responses.session = { error: "ECONNRESET" };
  assert.equal(await send(charge()), 200);
  assert.equal(slackPosts().length, 2);
});

test("el webhook de leads falla: el canal de siempre ya recibió el aviso y Stripe ve 200", async () => {
  responses.leads = { status: 500, body: "no" };
  assert.equal(await send(charge()), 200);
  assert.equal(slackPosts().length, 2);
});

test("el canal de siempre falla: leads se intenta igual", async () => {
  responses.main = { status: 500, body: "no" };
  assert.equal(await send(charge()), 200);
  assert.deepEqual(slackPosts().map((p) => p.path), ["/services/principal", "/services/leads"]);
});

test("disputa: solo el canal de siempre", async () => {
  const dispute = { id: "evt_2", type: "charge.dispute.created", data: { object: { id: "dp_1", amount: 100, currency: "mxn", charge: null } } };
  assert.equal(await send(dispute), 200);
  assert.deepEqual(slackPosts().map((p) => p.path), ["/services/principal"]);
});
