import { test } from "node:test";
import assert from "node:assert/strict";
import { leadsPaymentText } from "../lib/leads.js";

const base = {
  originLabel: "<https://www.optimal.lat|Optimal Web>", name: "Ana Prueba", country: "México", plan: "Core",
  phone: "+52 999 000 6002", email: "ana@correo.test", amount: "2999.00 MXN", discount: null, currency: "MXN",
};
const lines = (over = {}) => leadsPaymentText({ ...base, ...over }).split("\n");

test("sin cupón: título y un campo por línea", () => {
  assert.deepEqual(lines(), [
    "💰 *Pago recibido · <https://www.optimal.lat|Optimal Web>*",
    "👤 *Nombre:* Ana Prueba",
    "🌎 *País:* México",
    "📋 *Plan:* Core",
    "💵 *Monto:* 2999.00 MXN",
    "📱 *Teléfono (WhatsApp):* <https://wa.me/529990006002|+529990006002>",
    "✉️ *Correo:* <mailto:ana@correo.test|ana@correo.test>",
  ]);
});

test("con cupón: cupón y descuento van después del monto", () => {
  const discount = { discount: 59980, listPrice: 299900, percent: 20, code: "HOTBOOK20" };
  assert.deepEqual(lines({ amount: "2399.20 MXN", discount }).slice(4, 7), [
    "💵 *Monto:* 2399.20 MXN",
    "🎟️ *Cupón:* HOTBOOK20",
    "🏷️ *Descuento:* 20 % (599.80 MXN)",
  ]);
});

test("descuento sin código ni porcentaje: raya y solo el monto descontado", () => {
  const discount = { discount: 12345, listPrice: null, percent: null, code: null };
  assert.deepEqual(lines({ discount, currency: "PEN", amount: "100.00 PEN" }).slice(5, 7), ["🎟️ *Cupón:* —", "🏷️ *Descuento:* 123.45 PEN"]);
});

test("datos faltantes: raya en cada uno", () => {
  assert.deepEqual(lines({ name: " ", country: undefined, plan: null, phone: "", email: null }).slice(1), [
    "👤 *Nombre:* —", "🌎 *País:* —", "📋 *Plan:* —", "💵 *Monto:* 2999.00 MXN", "📱 *Teléfono (WhatsApp):* —", "✉️ *Correo:* —",
  ]);
});

test("el texto de quien pagó se escapa y no puede mencionar ni enlazar", () => {
  const l = lines({ name: "<!channel> & Cía", plan: "<https://x.test|Core>", email: "a@b.test|<!here>" });
  assert.equal(l[1], "👤 *Nombre:* &lt;!channel&gt; &amp; Cía");
  assert.equal(l[3], "📋 *Plan:* &lt;https://x.test|Core&gt;");
  assert.equal(l[6], "✉️ *Correo:* a@b.test|&lt;!here&gt;");
});

test("no se pudo consultar el cupón: lo dice, después del monto", () => {
  assert.deepEqual(lines({ discountUnknown: true }).slice(4, 6), ["💵 *Monto:* 2999.00 MXN", "🎟️ *Cupón:* no se pudo consultar"]);
});

test("con descuento conocido no se agrega el aviso de «no se pudo consultar»", () => {
  const discount = { discount: 59980, listPrice: 299900, percent: 20, code: "HOTBOOK20" };
  assert.equal(lines({ discount, discountUnknown: true }).filter((l) => l.includes("Cupón")).length, 1);
});
