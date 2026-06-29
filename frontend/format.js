// Fonctions de formatage pures : dates, fuseaux, délais, drapeaux, libellés.
// Aucune ne touche au DOM ; elles transforment des données en chaînes.

export function padTwo(n) {
  return String(n).padStart(2, "0");
}

export function flagEmoji(code) {
  if (!code || code.length !== 2) {
    return "";
  }
  const base = 0x1f1e6;
  const a = "A".charCodeAt(0);
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((c) => base + c.charCodeAt(0) - a)
  );
}

export function extractEmails(header) {
  const matches = header.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g);
  return matches ? matches.join(", ") : header;
}

export function formatDay(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return (
    padTwo(date.getUTCDate()) +
    "/" +
    padTwo(date.getUTCMonth() + 1) +
    "/" +
    date.getUTCFullYear()
  );
}

// Affiche un instant dans le fuseau d'origine de l'en-tête (sans le convertir
// dans celui du navigateur), avec le décalage explicite.
export function formatInstant(value) {
  if (!value) {
    return "inconnue";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const offsetMinutes = parseOffset(value);
  if (offsetMinutes === null) {
    return date.toLocaleString("fr-FR") + " (votre heure locale)";
  }
  const shifted = new Date(date.getTime() + offsetMinutes * 60000);
  const wall =
    padTwo(shifted.getUTCDate()) +
    "/" +
    padTwo(shifted.getUTCMonth() + 1) +
    "/" +
    shifted.getUTCFullYear() +
    " " +
    padTwo(shifted.getUTCHours()) +
    ":" +
    padTwo(shifted.getUTCMinutes()) +
    ":" +
    padTwo(shifted.getUTCSeconds());
  return wall + " (" + offsetLabel(offsetMinutes) + ")";
}

function parseOffset(value) {
  // Retirer un éventuel commentaire de zone, par exemple "+0200 (CEST)".
  const trimmed = value.replace(/\s*\([^)]*\)\s*$/, "").trim();
  if (/[zZ]$/.test(trimmed)) {
    return 0;
  }
  const match = trimmed.match(/([+-])(\d{2}):?(\d{2})$/);
  if (match) {
    const sign = match[1] === "-" ? -1 : 1;
    return sign * (parseInt(match[2], 10) * 60 + parseInt(match[3], 10));
  }
  if (/\b(UT|UTC|GMT)$/i.test(trimmed)) {
    return 0;
  }
  return null;
}

function offsetLabel(minutes) {
  if (minutes === 0) {
    return "UTC";
  }
  const sign = minutes < 0 ? "-" : "+";
  const abs = Math.abs(minutes);
  return "UTC" + sign + padTwo(Math.floor(abs / 60)) + ":" + padTwo(abs % 60);
}

export function formatDelay(seconds) {
  const sign = seconds < 0 ? "-" : "+";
  const abs = Math.abs(seconds);
  if (abs < 60) {
    return sign + abs + " s";
  }
  if (abs < 3600) {
    return sign + Math.round(abs / 60) + " min";
  }
  return sign + (abs / 3600).toFixed(1) + " h";
}

export function messageForStatus(status) {
  if (status === 413) {
    return "En-tête trop volumineux. Collez uniquement les en-têtes.";
  }
  if (status === 429) {
    return "Trop de requêtes. Patientez un instant.";
  }
  return "Erreur du serveur (code " + status + ").";
}

export function ptrLabel(hop) {
  if (hop.ptr) {
    return hop.ptr;
  }
  if (hop.has_reverse === false) {
    return "aucun reverse DNS";
  }
  if (hop.is_private) {
    return "non applicable";
  }
  return "inconnu";
}

export function placeLabel(hop) {
  if (hop.is_private) {
    let base =
      hop.ip && hop.ip.includes(":")
        ? "Adresse IPv6 locale (lien-local ou unique-local)"
        : "Réseau privé (RFC 1918)";
    if (hop.country) {
      base += " - " + hop.country + " (via le domaine)";
    }
    return base;
  }
  const parts = [hop.city, hop.country].filter(Boolean);
  let label = parts.join(", ");
  if (label && !hop.ip && hop.resolved_ip) {
    label += " (via le nom d'hôte)";
  }
  return label;
}

export function authState(value) {
  if (value === "pass") {
    return "pass";
  }
  if (value === "fail") {
    return "fail";
  }
  if (value === "softfail" || value === "neutral") {
    return "warn";
  }
  return "absent";
}
