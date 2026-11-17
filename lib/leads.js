// Aviso corto de un pago de los sitios para #leads-web: los mismos datos que el «Nuevo lead» de ese canal
// (n8n wf0007), un campo por línea. Sin efectos.
import { discountLabels, escapeMrkdwn } from "./discount.js";

const text = (v) => (v == null || String(v).trim() === "" ? "—" : escapeMrkdwn(String(v).trim()));
// Solo se enlaza un correo sin caracteres que rompan el enlace de Slack (<url|texto>).
const EMAIL_RE = /^[^\s<>|&]+@[^\s<>|&]+$/;

/**
 * `originLabel` ya viene en mrkdwn (un enlace); `amount` ya formateado («2399.20 MXN»); `discount` es el de
 * sessionDiscount o null; `discountUnknown` avisa que no se pudo consultar (distinto de «no hubo cupón»).
 * Lo demás es texto de quien pagó: se escapa.
 */
export function leadsPaymentText({ originLabel, name, country, plan, phone, email, amount, discount, discountUnknown, currency }) {
  const digits = String(phone || "").replace(/\D/g, "");
  const mail = String(email || "").trim();
  const d = discount ? discountLabels(discount, currency) : null;
  return [
    `💰 *Pago recibido · ${originLabel}*`,
    `👤 *Nombre:* ${text(name)}`,
    `🌎 *País:* ${text(country)}`,
    `📋 *Plan:* ${text(plan)}`,
    `💵 *Monto:* ${amount}`,
    ...(d ? [`🎟️ *Cupón:* ${d.coupon}`, `🏷️ *Descuento:* ${d.discount}`] : []),
    ...(!d && discountUnknown ? ["🎟️ *Cupón:* no se pudo consultar"] : []),
    `📱 *Teléfono (WhatsApp):* ${digits ? `<https://wa.me/${digits}|+${digits}>` : "—"}`,
    `✉️ *Correo:* ${EMAIL_RE.test(mail) ? `<mailto:${mail}|${mail}>` : text(mail)}`,
  ].join("\n");
}
