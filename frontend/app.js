// SpamCap - logique de l'interface.
// Appelle POST /analyze et rend le resultat. Le DOM est construit avec
// createElement et textContent : aucune donnee reseau n'est injectee en HTML.

"use strict";

const SPAMCOP_HEADER_LIMIT = 50 * 1024;
const STORAGE_KEY = "spamcap:dernier-entete";

const form = document.getElementById("analyze-form");
const rawField = document.getElementById("raw");
const button = document.getElementById("analyze-btn");
const formError = document.getElementById("form-error");

const report = document.getElementById("report");
const verdictStamp = document.getElementById("verdict-stamp");
const verdictWord = document.getElementById("verdict-word");
const verdictMeta = document.getElementById("verdict-meta");
const spine = document.getElementById("route-spine");
const routeEmpty = document.getElementById("route-empty");
const authStamps = document.getElementById("auth-stamps");
const filterSection = document.getElementById("filter-section");
const filterStamps = document.getElementById("filter-stamps");
const filterDetails = document.getElementById("filter-details");
const filterNote = document.getElementById("filter-note");
const anomaliesSection = document.getElementById("anomalies-section");
const anomaliesList = document.getElementById("anomalies-list");
const spamcopHeaders = document.getElementById("spamcop-headers");
const copyButton = document.getElementById("copy-btn");
const copiedNote = document.getElementById("copied-note");

const VERDICT_CLASS = {
  "LÉGITIME": "verdict__stamp--legit",
  SUSPECT: "verdict__stamp--suspect",
  DOUTEUX: "verdict__stamp--doubt",
};

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const raw = rawField.value.trim();

  if (!raw) {
    showError("Collez d'abord un en-tete de courriel.");
    return;
  }

  setBusy(true);
  hideError();

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
    renderReport(data, rawField.value);
  } catch (error) {
    showError("Le service ne repond pas. Verifiez que le serveur est lance.");
  } finally {
    setBusy(false);
  }
});

// Conserve l'en-tete colle d'un rafraichissement a l'autre, dans le navigateur.
rawField.addEventListener("input", () => {
  try {
    localStorage.setItem(STORAGE_KEY, rawField.value);
  } catch (error) {
    // localStorage indisponible (navigation privee) : on ignore silencieusement.
  }
});

function restoreSavedHeader() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && !rawField.value) {
      rawField.value = saved;
    }
  } catch (error) {
    // Rien a restaurer si localStorage est indisponible.
  }
}

copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(spamcopHeaders.value);
    copiedNote.hidden = false;
    window.setTimeout(() => {
      copiedNote.hidden = true;
    }, 2500);
  } catch (error) {
    spamcopHeaders.select();
  }
});

function renderReport(data, rawInput) {
  renderVerdict(data);
  renderRoute(data.hops);
  renderAuth(data.auth);
  renderFilter(data.filter_verdict, data.auth);
  renderAnomalies(data.anomalies);
  renderDispatch(rawInput);

  report.hidden = false;
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderVerdict(data) {
  verdictWord.textContent = data.verdict;
  verdictStamp.className = "verdict__stamp";
  const modifier = VERDICT_CLASS[data.verdict];
  if (modifier) {
    verdictStamp.classList.add(modifier);
  }

  verdictMeta.replaceChildren();
  addMetaRow("Objet", data.subject || "non precise");
  addMetaRow("De", data.from_domain || "inconnu");
  addMetaRow("A", data.to_domain || "inconnu");
  addMetaRow("Volume", formatVolume(data));
  if (data.geoip_warning) {
    addMetaRow("Note", data.geoip_warning);
  }
}

function renderRoute(hops) {
  spine.replaceChildren();

  if (!hops.length) {
    routeEmpty.hidden = false;
    return;
  }
  routeEmpty.hidden = true;

  hops.forEach((hop, index) => {
    spine.appendChild(buildHop(hop, index));
  });
}

function buildHop(hop, index) {
  const item = el("li", "hop");
  item.style.setProperty("--i", String(index));

  const listed =
    hop.dnsbl && (hop.dnsbl.spamcop === true || hop.dnsbl.spamhaus === true);

  const seal = el("div", listed ? "hop__seal hop__seal--listed" : "hop__seal");
  seal.appendChild(el("span", "hop__index", String(hop.hop_index)));
  if (hop.is_private) {
    seal.appendChild(el("span", "hop__flag", "local"));
  } else {
    const flag = flagEmoji(hop.country_code);
    if (flag) {
      seal.appendChild(el("span", "hop__flag", flag));
    }
  }
  item.appendChild(seal);

  const body = el("div", "hop__body");

  const ipLine = el("div", "hop__ip", hop.ip || "IP absente");
  if (hop.ip && hop.ip_version) {
    ipLine.appendChild(el("span", "hop__ipver", "IPv" + hop.ip_version));
  }
  body.appendChild(ipLine);

  const place = placeLabel(hop);
  if (place) {
    body.appendChild(el("p", "hop__place", place));
  }

  const lines = el("dl", "hop__lines");
  addHopLine(lines, "PTR", hop.ptr || "inconnu");
  addHopLine(lines, "Org", hop.org || "inconnue");
  addHopLine(lines, "Heure", formatTimestamp(hop.timestamp));
  body.appendChild(lines);

  const badges = el("div", "hop__badges");
  if (hop.is_private) {
    badges.appendChild(el("span", "badge badge--local", "Reseau local"));
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

  item.appendChild(body);
  return item;
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
      ? "indesirable"
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
      "Message interne Microsoft 365 : SPF, DKIM et DMARC ne s'appliquent pas a un " +
      "courriel qui n'a pas quitte le domaine.";
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

function renderDispatch(rawInput) {
  const headerBlock = rawInput.split(/\r?\n\r?\n/)[0];
  spamcopHeaders.value = headerBlock.slice(0, SPAMCOP_HEADER_LIMIT);
  copiedNote.hidden = true;
}

// ---------------------------------------------------------------- Aides

function addMetaRow(label, value) {
  verdictMeta.appendChild(el("dt", null, label));
  verdictMeta.appendChild(el("dd", null, value));
}

function addHopLine(list, label, value) {
  const row = el("div");
  row.appendChild(el("dt", null, label));
  row.appendChild(el("dd", null, value));
  list.appendChild(row);
}

function placeLabel(hop) {
  if (hop.is_private) {
    if (hop.ip && hop.ip.includes(":")) {
      return "Adresse IPv6 locale (lien-local ou unique-local)";
    }
    return "Reseau prive (RFC 1918)";
  }
  const parts = [hop.city, hop.country].filter(Boolean);
  return parts.join(", ");
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

function formatTimestamp(value) {
  if (!value) {
    return "inconnu";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "inconnu";
  }
  return date.toLocaleString("fr-FR");
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

function formatVolume(data) {
  const analyzed = formatBytes(data.analyzed_size_bytes);
  if (data.truncated) {
    return formatBytes(data.raw_size_bytes) + " recus, " + analyzed + " analyses";
  }
  return analyzed + " analyses";
}

function formatBytes(bytes) {
  if (bytes < 1024) {
    return bytes + " o";
  }
  if (bytes < 1024 * 1024) {
    return (bytes / 1024).toFixed(1) + " Ko";
  }
  return (bytes / (1024 * 1024)).toFixed(1) + " Mo";
}

function messageForStatus(status) {
  if (status === 413) {
    return "En-tete trop volumineux. Collez uniquement les en-tetes.";
  }
  if (status === 429) {
    return "Trop de requetes. Patientez un instant.";
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
  button.textContent = busy ? "Analyse..." : "Analyser";
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
