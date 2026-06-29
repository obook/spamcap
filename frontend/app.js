// SpamCap - point d'entrée de l'interface.
// Appelle POST /analyze, restaure l'en-tête collé et orchestre le rendu.
// Le DOM est construit avec createElement et textContent (voir dom.js) :
// aucune donnée réseau n'est injectée en HTML.

import {
  button,
  form,
  formError,
  rawField,
  report,
} from "./dom.js";
import { el } from "./dom.js";
import { messageForStatus } from "./format.js";
import { renderIdentity } from "./render-card.js";
import { renderRoute } from "./render-route.js";
import {
  renderAnomalies,
  renderAuth,
  renderFilter,
} from "./render-verdict.js";

const STORAGE_KEY = "spamcap:dernier-entete";

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
    // localStorage indisponible (navigation privée) : on ignore.
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
