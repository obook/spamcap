// Carte d'identité du courriel : expéditeur, domaine, destinataires, origine.

import { el, identity } from "./dom.js";
import {
  extractEmails,
  flagEmoji,
  formatDay,
  formatInstant,
} from "./format.js";

export function renderIdentity(data) {
  identity.replaceChildren();
  addCardRow("Expéditeur", data.from_address || "inconnu");
  if (data.from_domain) {
    addCardRow("Domaine expéditeur", domainLabel(data));
  }
  if (data.return_path) {
    addCardRow("Retour (enveloppe)", extractEmails(data.return_path));
  }
  addCardRow("Destinataire(s)", data.to_recipients || "inconnu");
  if (data.cc_recipients) {
    addCardRow("Copie", data.cc_recipients);
  }
  addCardRow("Objet", data.subject || "non précisé");
  addCardRow("Date d'expédition", formatInstant(data.date));
  const origin = firstGeoHop(data.hops);
  if (origin) {
    addCardRow("Origine probable", originLabel(origin));
  }
  if (data.is_bulk) {
    const type = data.bulk_esp
      ? "Courriel de masse (via " + data.bulk_esp + ")"
      : "Courriel de masse";
    addCardRow("Type", type);
  }
  if (data.bulk_unsubscribe) {
    addCardRow("Désabonnement", data.bulk_unsubscribe);
  }
  if (data.geoip_warning) {
    addCardRow("Note", data.geoip_warning);
  }
}

function domainLabel(data) {
  const domain = data.from_domain;
  const parts = [];
  if (data.from_domain_created) {
    parts.push("créé le " + formatDay(data.from_domain_created));
  }
  if (data.from_domain_updated) {
    parts.push("mis à jour le " + formatDay(data.from_domain_updated));
  }
  if (data.from_domain_registrar) {
    parts.push("bureau d'enregistrement : " + data.from_domain_registrar);
  }
  return parts.length ? domain + " (" + parts.join(", ") + ")" : domain;
}

function firstGeoHop(hops) {
  return hops.find((hop) => hop.country_code || hop.country) || null;
}

function originLabel(hop) {
  const flag = flagEmoji(hop.country_code);
  const place =
    [hop.city, hop.country].filter(Boolean).join(", ") ||
    hop.country_code ||
    "inconnu";
  const when = hop.timestamp ? formatInstant(hop.timestamp) : "date inconnue";
  return (flag ? flag + " " : "") + place + " (" + when + ")";
}

function addCardRow(label, value) {
  identity.appendChild(el("dt", null, label));
  identity.appendChild(el("dd", null, value));
}
