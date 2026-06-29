// Parcours du pli : nœuds FROM/TO, origine déclarée, et chaque saut résolu.

import { el, routeEmpty, spine } from "./dom.js";
import {
  extractEmails,
  flagEmoji,
  formatDelay,
  formatInstant,
  placeLabel,
  ptrLabel,
} from "./format.js";

export function renderRoute(data) {
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

// Nœud du poste/serveur source déclaré par X-Originating-IP. Volontairement
// neutre : l'IP peut être un poste de travail ou un relais SMTP interne.
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

  const label = hop.ip || hop.from_host || "Saut sans adresse IP";
  const ipLine = el("div", "hop__ip", label);
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
    // Nom d'hôte de l'en-tête (DNS inverse ou HELO), utile surtout pour une
    // IP privée sans PTR ; masqué s'il double le PTR résolu.
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

  const badges = buildBadges(hop);
  if (badges.childNodes.length) {
    body.appendChild(badges);
  }

  return body;
}

function buildBadges(hop) {
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
    const delay = formatDelay(hop.delay_seconds);
    badges.appendChild(el("span", "badge badge--delay", delay));
  }
  return badges;
}

function addHopLine(list, label, value) {
  const row = el("div");
  row.appendChild(el("dt", null, label));
  row.appendChild(el("dd", null, value));
  list.appendChild(row);
}
