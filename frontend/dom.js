// Références aux nœuds du document et fabrique d'éléments partagée.
// Les modules sont différés : le DOM est prêt quand ce fichier s'exécute.

export const form = document.getElementById("analyze-form");
export const rawField = document.getElementById("raw");
export const button = document.getElementById("analyze-btn");
export const formError = document.getElementById("form-error");

export const report = document.getElementById("report");
export const identity = document.getElementById("identity");
export const spine = document.getElementById("route-spine");
export const routeEmpty = document.getElementById("route-empty");
export const authStamps = document.getElementById("auth-stamps");
export const filterSection = document.getElementById("filter-section");
export const filterStamps = document.getElementById("filter-stamps");
export const filterDetails = document.getElementById("filter-details");
export const filterNote = document.getElementById("filter-note");
export const anomaliesSection = document.getElementById("anomalies-section");
export const anomaliesList = document.getElementById("anomalies-list");

// Crée un élément avec une classe et un texte optionnels. Le texte passe par
// textContent : aucune donnée réseau n'est jamais injectée comme du HTML.
export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined && text !== null) {
    node.textContent = text;
  }
  return node;
}
