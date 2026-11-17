import { test } from "node:test";
import assert from "node:assert/strict";
import { discountFields, sessionDiscount, sessionLookupPath } from "../lib/discount.js";

const session = (over = {}) => ({
  amount_subtotal: 299900,
  amount_total: 239920,
  total_details: { amount_discount: 59980 },
  discounts: [{ coupon: "co_1", promotion_code: { id: "promo_1", code: "HOTBOOK20" } }],
  ...over,
});

test("la consulta busca la sesión por payment_intent y pide el código expandido", () => {
  const url = new URL(sessionLookupPath("pi_1 &x"), "https://api.stripe.com");
  assert.equal(url.pathname, "/v1/checkout/sessions");
  assert.equal(url.searchParams.get("payment_intent"), "pi_1 &x");
  assert.equal(url.searchParams.get("limit"), "1");
  assert.deepEqual(url.searchParams.getAll("expand[]"), ["data.discounts.promotion_code", "data.total_details.breakdown"]);
});

test("cupón del 20 %: descuento, precio de lista, porcentaje y código", () => {
  assert.deepEqual(sessionDiscount(session()), { discount: 59980, listPrice: 299900, percent: 20, code: "HOTBOOK20" });
});

test("sin descuento, o sin sesión: null", () => {
  assert.equal(sessionDiscount(session({ total_details: { amount_discount: 0 } })), null);
  assert.equal(sessionDiscount(session({ total_details: null })), null);
  assert.equal(sessionDiscount(null), null);
});

test("porcentaje con decimales: se redondea a 2", () => {
  assert.equal(sessionDiscount(session({ total_details: { amount_discount: 60000 } })).percent, 20.01);
});

test("sin subtotal: el precio de lista es lo cobrado más lo descontado", () => {
  const d = sessionDiscount(session({ amount_subtotal: null, amount_total: 239922, total_details: { amount_discount: 26658 } }));
  assert.equal(d.listPrice, 266580);
  assert.equal(d.percent, 10);
});

test("sin subtotal ni total: sin precio de lista ni porcentaje", () => {
  const d = sessionDiscount(session({ amount_subtotal: null, amount_total: null }));
  assert.deepEqual(d, { discount: 59980, listPrice: null, percent: null, code: "HOTBOOK20" });
});

test("código sin expandir (solo el id) o descuento sin código: code null", () => {
  assert.equal(sessionDiscount(session({ discounts: [{ coupon: "co_1", promotion_code: "promo_1" }] })).code, null);
  assert.equal(sessionDiscount(session({ discounts: [{ coupon: "co_1", promotion_code: null }] })).code, null);
  assert.equal(sessionDiscount(session({ discounts: null })).code, null);
});

test("código informado solo en el desglose: se toma de ahí", () => {
  const total_details = { amount_discount: 59980, breakdown: { discounts: [{ amount: 59980, discount: { promotion_code: { code: "DESGLOSE20" }, coupon: { name: "Hotbook 20 %" } } }] } };
  assert.equal(sessionDiscount(session({ discounts: [], total_details })).code, "DESGLOSE20");
});

test("sin código pero con el nombre del cupón: se muestra el nombre", () => {
  const total_details = { amount_discount: 59980, breakdown: { discounts: [{ amount: 59980, discount: { promotion_code: "promo_1", coupon: { name: " Hotbook 20 % " } } }] } };
  assert.equal(sessionDiscount(session({ discounts: [{ coupon: "co_1", promotion_code: "promo_1" }], total_details })).code, "Hotbook 20 %");
});

test("el mismo código en los dos lugares: una sola vez; el código gana al nombre", () => {
  const total_details = { amount_discount: 59980, breakdown: { discounts: [{ discount: { promotion_code: { code: "HOTBOOK20" }, coupon: { name: "Hotbook 20 %" } } }] } };
  assert.equal(sessionDiscount(session({ total_details })).code, "HOTBOOK20");
});

test("varios códigos: se listan todos, sin espacios sobrantes", () => {
  const discounts = [{ promotion_code: { code: " UNO " } }, { promotion_code: { code: "DOS" } }];
  assert.equal(sessionDiscount(session({ discounts })).code, "UNO, DOS");
});

test("campos de Slack: precio de lista, cupón y descuento con porcentaje y monto", () => {
  assert.deepEqual(
    discountFields({ discount: 59980, listPrice: 299900, percent: 20, code: "HOTBOOK20" }, "MXN").map((f) => f.text),
    ["*Precio de lista:*\n2999.00 MXN", "*Cupón:*\nHOTBOOK20", "*Descuento:*\n20 % (599.80 MXN)"],
  );
});

test("campos de Slack sin código ni porcentaje: raya y solo el monto", () => {
  assert.deepEqual(
    discountFields({ discount: 12345, listPrice: null, percent: null, code: null }, "PEN").map((f) => f.text),
    ["*Cupón:*\n—", "*Descuento:*\n123.45 PEN"],
  );
});

test("el código se escapa para Slack", () => {
  const [coupon] = discountFields({ discount: 1, listPrice: null, percent: null, code: "<!channel>&" }, "MXN");
  assert.equal(coupon.text, "*Cupón:*\n&lt;!channel&gt;&amp;");
});
