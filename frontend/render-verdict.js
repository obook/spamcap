// Tampons d'authentification (SPF/DKIM/DMARC), verdict du filtre, anomalies.

import {
  anomaliesList,
  anomaliesSection,
  authStamps,
  el,
  filterDetails,
  filterNote,
  filterSection,
  filterStamps,
} from "./dom.js";
import { authState } from "./format.js";

export function renderAuth(auth) {
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

export function renderFilter(verdict, auth) {
  filterStamps.replaceChildren();
  filterDetails.hidden = true;
  filterNote.hidden = true;

  const hasData =
    verdict &&
    (verdict.source ||
      verdict.is_spam !== null ||
      (verdict.details && verdict.details.length));
  if (!hasData) {
    filterSection.hidden = true;
    return;
  }
  filterSection.hidden = false;

  filterStamps.appendChild(buildFilterStamp(verdict));
  if (verdict.score) {
    filterStamps.appendChild(buildScoreStamp(verdict.score));
  }
  if (verdict.details && verdict.details.length) {
    filterDetails.textContent = "Signaux : " + verdict.details.join(" - ");
    filterDetails.hidden = false;
  }
  showMicrosoftNote(verdict, auth);
}

function buildFilterStamp(verdict) {
  const state =
    verdict.is_spam === true
      ? "fail"
      : verdict.is_spam === false
      ? "pass"
      : "absent";
  const label =
    verdict.is_spam === true
      ? "indésirable"
      : verdict.is_spam === false
      ? "propre"
      : "non concluant";

  const stamp = el("div", "auth__stamp auth__stamp--" + state);
  stamp.appendChild(el("span", "auth__name", verdict.source || "Filtre"));
  stamp.appendChild(el("span", "auth__value", label));
  return stamp;
}

function buildScoreStamp(score) {
  const stamp = el("div", "auth__stamp");
  stamp.appendChild(el("span", "auth__name", "Score"));
  stamp.appendChild(el("span", "auth__value", score));
  return stamp;
}

// Sur un courriel interne Microsoft, l'absence de SPF/DKIM/DMARC est normale.
function showMicrosoftNote(verdict, auth) {
  const noAuth = !auth.spf && !auth.dkim && !auth.dmarc;
  if (verdict.source && verdict.source.indexOf("Microsoft") === 0 && noAuth) {
    filterNote.textContent =
      "Message interne Microsoft 365 : SPF, DKIM et DMARC ne s'appliquent " +
      "pas à un courriel qui n'a pas quitté le domaine.";
    filterNote.hidden = false;
  }
}

export function renderAnomalies(anomalies) {
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
