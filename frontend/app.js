// SpamCap - logique de l'interface.
// Appelle POST /analyze et rend le résultat. Le DOM est construit avec
// createElement et textContent : aucune donnée réseau n'est injectée en HTML.

"use strict";

const STORAGE_KEY = "spamcap:dernier-entete";

const form = document.getElementById("analyze-form");
const rawField = document.getElementById("raw");
const button = document.getElementById("analyze-btn");
const formError = document.getElementById("form-error");

const report = document.getElementById("report");
const identity = document.getElementById("identity");
const spine = document.getElementById("route-spine");
const routeEmpty = document.getElementById("route-empty");
const authStamps = document.getElementById("auth-stamps");
const filterSection = document.getElementById("filter-section");
const filterStamps = document.getElementById("filter-stamps");
const filterDetails = document.getElementById("filter-details");
const filterNote = document.getElementById("filter-note");
const anomaliesSection = document.getElementById("anomalies-section");
const anomaliesList = document.getElementById("anomalies-list");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const raw = rawField.value.trim();

  if (!raw) {
    showError("Collez d'abord un en-tête de courriel.");
    return;
  }

  setBusy(true);
  hideError();
  // Effacer le compte-rendu précédent pendant la nouvelle recherche.
  report.hidden = true;

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_headers: rawField.value }),
    });

    if (!response.ok) {
      showError(messageForStatus(response.status));
      return;
    }

    const data = await response.json();
    renderReport(data);
  } catch (error) {
    showError("Le service ne répond pas. Vérifiez que le serveur est lancé.");
  } finally {
    setBusy(false);
  }
});

// Conserve l'en-tête collé d'un rafraîchissement à l'autre, dans le navigateur.
rawField.addEventListener("input", () => {
  try {
    localStorage.setItem(STORAGE_KEY, rawField.value);
  } catch (error) {
    // localStorage indisponible (navigation privée) : on ignore silencieusement.
  }
});

function restoreSavedHeader() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && !rawField.value) {
      rawField.value = saved;
    }
  } catch (error) {
    // Rien à restaurer si localStorage est indisponible.
  }
}

function renderReport(data) {
  renderIdentity(data);
  renderRoute(data);
  renderAuth(data.auth);
  renderFilter(data.filter_verdict, data.auth);
  renderAnomalies(data.anomalies);

  report.hidden = false;
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderIdentity(data) {
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

function formatDay(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  const pad = (n) => String(n).padStart(2, "0");
  return (
    pad(date.getUTCDate()) +
    "/" +
    pad(date.getUTCMonth() + 1) +
    "/" +
    date.getUTCFullYear()
  );
}

function firstGeoHop(hops) {
  return hops.find((hop) => hop.country_code || hop.country) || null;
}

function originLabel(hop) {
  const flag = flagEmoji(hop.country_code);
  const place =
    [hop.city, hop.country].filter(Boolean).join(", ") || hop.country_code || "inconnu";
  const when = hop.timestamp ? formatInstant(hop.timestamp) : "date inconnue";
  return (flag ? flag + " " : "") + place + " (" + when + ")";
}

function renderRoute(data) {
  const hops = data.hops;
  spine.replaceChildren();

  if (!hops.length) {
    routeEmpty.hidden = false;
    return;
  }
  routeEmpty.hidden = true;

  if (data.from_address) {
    spine.appendChild(buildEndpoint("FROM", data.from_address));
  }
  if (data.originating) {
    spine.appendChild(buildOriginNode(data.originating));
  }
  hops.forEach((hop, index) => {
    spine.appendChild(buildHop(hop, index));
  });
  if (data.to_recipients) {
    spine.appendChild(buildEndpoint("TO", data.to_recipients));
  }
}

function buildEndpoint(glyph, header) {
  const item = el("li", "hop hop--endpoint");

  const seal = el("div", "hop__seal hop__seal--endpoint");
  seal.appendChild(el("span", "hop__endpoint-glyph", glyph));
  item.appendChild(seal);

  const body = el("div", "hop__body");
  body.appendChild(el("div", "hop__ip", extractEmails(header)));
  item.appendChild(body);

  return item;
}

function extractEmails(header) {
  const matches = header.match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g);
  return matches ? matches.join(", ") : header;
}

function buildHop(hop, index) {
  const item = el("li", "hop");
  item.style.setProperty("--i", String(index));

  const listed =
    hop.dnsbl && (hop.dnsbl.spamcop === true || hop.dnsbl.spamhaus === true);

  const seal = el("div", listed ? "hop__seal hop__seal--listed" : "hop__seal");
  seal.appendChild(el("span", "hop__index", String(hop.hop_index)));
  const flag = flagEmoji(hop.country_code);
  if (flag) {
    seal.appendChild(el("span", "hop__flag", flag));
  } else if (hop.is_private) {
    seal.appendChild(el("span", "hop__flag", "local"));
  }
  item.appendChild(seal);
  item.appendChild(buildHopBody(hop));
  return item;
}

// Noeud du poste/serveur source declare par X-Originating-IP. Volontairement
// neutre : l'IP peut etre un poste de travail ou un relais SMTP interne.
function buildOriginNode(hop) {
  const item = el("li", "hop");

  const seal = el("div", "hop__seal");
  seal.appendChild(el("span", "hop__endpoint-glyph", "ORIG"));
  const flag = flagEmoji(hop.country_code);
  if (flag) {
    seal.appendChild(el("span", "hop__flag", flag));
  } else if (hop.is_private) {
    seal.appendChild(el("span", "hop__flag", "local"));
  }
  item.appendChild(seal);

  const body = buildHopBody(hop);
  body.insertBefore(
    el("p", "hop__place", "Origine déclarée (X-Originating-IP)"),
    body.firstChild
  );
  item.appendChild(body);
  return item;
}

function buildHopBody(hop) {
  const body = el("div", "hop__body");

  const ipLine = el("div", "hop__ip", hop.ip || hop.from_host || "Saut sans adresse IP");
  if (hop.ip && hop.ip_version) {
    ipLine.appendChild(el("span", "hop__ipver", "IPv" + hop.ip_version));
  }
  body.appendChild(ipLine);

  const place = placeLabel(hop);
  if (place) {
    body.appendChild(el("p", "hop__place", place));
  }

  const lines = el("dl", "hop__lines");
  if (hop.ip) {
    // Nom d'hote de l'en-tete (DNS inverse ou HELO), utile surtout pour une IP
    // privee sans PTR ; masque s'il double le PTR resolu.
    if (hop.from_host && hop.from_host !== (hop.ptr || "").toLowerCase()) {
      addHopLine(lines, "Hôte", hop.from_host);
    }
    addHopLine(lines, "PTR", ptrLabel(hop));
    addHopLine(lines, "Org", hop.org || "inconnue");
  } else if (hop.resolved_ip) {
    // Saut sans IP géolocalisé via le DNS actuel de son nom d'hôte.
    addHopLine(lines, "IP actuelle", hop.resolved_ip);
    if (hop.org) {
      addHopLine(lines, "Org", hop.org);
    }
  }
  if (hop.timestamp) {
    addHopLine(lines, "Heure", formatInstant(hop.timestamp));
  }
  if (lines.childNodes.length) {
    body.appendChild(lines);
  }

  const badges = el("div", "hop__badges");
  if (hop.is_private) {
    badges.appendChild(el("span", "badge badge--local", "Réseau local"));
  }
  if (hop.dnsbl && hop.dnsbl.spamcop === true) {
    badges.appendChild(el("span", "badge badge--listed", "Liste SCBL"));
  }
  if (hop.dnsbl && hop.dnsbl.spamhaus === true) {
    badges.appendChild(el("span", "badge badge--listed", "Liste Spamhaus"));
  }
  if (hop.delay_seconds !== null && hop.delay_seconds !== undefined) {
    badges.appendChild(el("span", "badge badge--delay", formatDelay(hop.delay_seconds)));
  }
  if (badges.childNodes.length) {
    body.appendChild(badges);
  }

  return body;
}

function renderAuth(auth) {
  authStamps.replaceChildren();
  authStamps.appendChild(buildAuthStamp("SPF", auth.spf));
  authStamps.appendChild(buildAuthStamp("DKIM", auth.dkim));
  authStamps.appendChild(buildAuthStamp("DMARC", auth.dmarc));
}

function buildAuthStamp(name, value) {
  const stamp = el("div", "auth__stamp auth__stamp--" + authState(value));
  stamp.appendChild(el("span", "auth__name", name));
  stamp.appendChild(el("span", "auth__value", value ? value : "absent"));
  return stamp;
}

function renderFilter(verdict, auth) {
  filterStamps.replaceChildren();
  filterDetails.hidden = true;
  filterNote.hidden = true;

  const hasData =
    verdict &&
    (verdict.source || verdict.is_spam !== null || (verdict.details && verdict.details.length));
  if (!hasData) {
    filterSection.hidden = true;
    return;
  }
  filterSection.hidden = false;

  const state =
    verdict.is_spam === true ? "fail" : verdict.is_spam === false ? "pass" : "absent";
  const label =
    verdict.is_spam === true
      ? "indésirable"
      : verdict.is_spam === false
      ? "propre"
      : "non concluant";

  const stamp = el("div", "auth__stamp auth__stamp--" + state);
  stamp.appendChild(el("span", "auth__name", verdict.source || "Filtre"));
  stamp.appendChild(el("span", "auth__value", label));
  filterStamps.appendChild(stamp);

  if (verdict.score) {
    const scoreStamp = el("div", "auth__stamp");
    scoreStamp.appendChild(el("span", "auth__name", "Score"));
    scoreStamp.appendChild(el("span", "auth__value", verdict.score));
    filterStamps.appendChild(scoreStamp);
  }

  if (verdict.details && verdict.details.length) {
    filterDetails.textContent = "Signaux : " + verdict.details.join(" - ");
    filterDetails.hidden = false;
  }

  // Sur un courriel interne Microsoft, l'absence de SPF/DKIM/DMARC est normale.
  const noAuth = !auth.spf && !auth.dkim && !auth.dmarc;
  if (verdict.source && verdict.source.indexOf("Microsoft") === 0 && noAuth) {
    filterNote.textContent =
      "Message interne Microsoft 365 : SPF, DKIM et DMARC ne s'appliquent pas à un " +
      "courriel qui n'a pas quitté le domaine.";
    filterNote.hidden = false;
  }
}

function renderAnomalies(anomalies) {
  anomaliesList.replaceChildren();

  if (!anomalies.length) {
    anomaliesSection.hidden = true;
    return;
  }
  anomaliesSection.hidden = false;

  anomalies.forEach((anomaly) => {
    const item = el("li", "anomaly anomaly--" + anomaly.severity);
    const tag = anomaly.severity === "major" ? "Majeure" : "Mineure";
    item.appendChild(el("span", "anomaly__tag", tag));
    item.appendChild(el("span", "anomaly__text", anomaly.description));
    anomaliesList.appendChild(item);
  });
}

// ---------------------------------------------------------------- Aides

function addCardRow(label, value) {
  identity.appendChild(el("dt", null, label));
  identity.appendChild(el("dd", null, value));
}

function addHopLine(list, label, value) {
  const row = el("div");
  row.appendChild(el("dt", null, label));
  row.appendChild(el("dd", null, value));
  list.appendChild(row);
}

function ptrLabel(hop) {
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

function placeLabel(hop) {
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

function authState(value) {
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

function flagEmoji(code) {
  if (!code || code.length !== 2) {
    return "";
  }
  const base = 0x1f1e6;
  const a = "A".charCodeAt(0);
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((c) => base + c.charCodeAt(0) - a)
  );
}

// Affiche un instant dans le fuseau d'origine de l'en-tête (sans le convertir
// dans celui du navigateur), avec le décalage explicite.
function formatInstant(value) {
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
  const pad = (n) => String(n).padStart(2, "0");
  const wall =
    pad(shifted.getUTCDate()) +
    "/" +
    pad(shifted.getUTCMonth() + 1) +
    "/" +
    shifted.getUTCFullYear() +
    " " +
    pad(shifted.getUTCHours()) +
    ":" +
    pad(shifted.getUTCMinutes()) +
    ":" +
    pad(shifted.getUTCSeconds());
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
  const pad = (n) => String(n).padStart(2, "0");
  return "UTC" + sign + pad(Math.floor(abs / 60)) + ":" + pad(abs % 60);
}

function formatDelay(seconds) {
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

function messageForStatus(status) {
  if (status === 413) {
    return "En-tête trop volumineux. Collez uniquement les en-têtes.";
  }
  if (status === 429) {
    return "Trop de requêtes. Patientez un instant.";
  }
  return "Erreur du serveur (code " + status + ").";
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = text;
  }
  return node;
}

function setBusy(busy) {
  button.disabled = busy;
  if (!busy) {
    button.textContent = "Analyser";
    return;
  }
  button.replaceChildren(document.createTextNode("Analyse"));
  const dots = el("span", "dots");
  dots.setAttribute("aria-hidden", "true");
  for (let i = 0; i < 3; i += 1) {
    dots.appendChild(el("span", "dots__dot", "."));
  }
  button.appendChild(dots);
}

function showError(message) {
  formError.textContent = message;
  formError.hidden = false;
}

function hideError() {
  formError.hidden = true;
  formError.textContent = "";
}

restoreSavedHeader();
