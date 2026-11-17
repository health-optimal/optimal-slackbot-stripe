// Descuento de un cobro de los sitios (Core/Apex). El evento charge.succeeded trae lo cobrado pero no si hubo
// cupón: eso vive en la sesión de Checkout del cobro, que se consulta por su payment_intent.
// Sin efectos: aquí solo se arma la consulta y se interpreta la respuesta (webhook.js hace la llamada).

/**
 * Ruta de la API de Stripe que devuelve la sesión de Checkout de un payment_intent. Stripe informa el descuento en dos
 * lugares de la sesión y se piden los dos: `discounts` (con el código promocional expandido) y el desglose
 * `total_details.breakdown` (que trae el cupón de cada descuento).
 */
export function sessionLookupPath(paymentIntentId) {
  const q = new URLSearchParams({ payment_intent: paymentIntentId, limit: "1" });
  q.append("expand[]", "data.discounts.promotion_code");
  q.append("expand[]", "data.total_details.breakdown");
  return `/v1/checkout/sessions?${q}`;
}

/**
 * Lo descontado en una sesión de Checkout, o null si no hubo descuento.
 * Montos en centavos, como los da Stripe. `percent` es sobre el precio antes del descuento (hasta 2 decimales);
 * `code` es el código que escribió la persona; si la sesión no lo trae, el nombre del cupón; si tampoco, null.
 */
export function sessionDiscount(session) {
  const discount = session?.total_details?.amount_discount ?? 0;
  if (!(discount > 0)) return null;

  const subtotal = session.amount_subtotal;
  const listPrice =
    subtotal > 0 ? subtotal : session.amount_total != null ? session.amount_total + discount : null;
  // Cada descuento, venga de `discounts` o del desglose (ahí va dentro de `discount`).
  const applied = [
    ...(session.discounts || []),
    ...(session.total_details?.breakdown?.discounts || []).map((b) => b?.discount),
  ].filter(Boolean);
  const unique = (values) => [...new Set(values.map((v) => String(v ?? "").trim()).filter(Boolean))];
  // Sin expandir, promotion_code y coupon son solo un id (string): no sirven como texto.
  const codes = unique(applied.map((d) => (typeof d.promotion_code === "object" ? d.promotion_code?.code : null)));
  const names = unique(applied.map((d) => (typeof d.coupon === "object" ? d.coupon?.name : null)));
  const shown = codes.length ? codes : names;

  return {
    discount,
    listPrice,
    percent: listPrice ? Math.round((discount * 10000) / listPrice) / 100 : null,
    code: shown.length ? shown.join(", ") : null,
  };
}

const money = (cents, currency) => `${(cents / 100).toFixed(2)} ${currency}`;
// Slack interpreta & < > en mrkdwn; el código lo escribe quien paga.
export const escapeMrkdwn = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** El descuento ya en texto para Slack (mrkdwn): cupón y descuento. */
export function discountLabels(d, currency) {
  const amount = money(d.discount, currency);
  return {
    coupon: d.code ? escapeMrkdwn(d.code) : "—",
    discount: d.percent != null ? `${d.percent} % (${amount})` : amount,
  };
}
