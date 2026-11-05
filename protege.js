
(function () {
  const ITERATIONS = 250000;
  const fen = document.getElementById("fenetre");
  const champ = document.getElementById("mdp");
  const msg = document.getElementById("msg");
  const actions = document.getElementById("actions");
  let courant = null, urlCourante = null;

  function lireMdp(classe) { try { return localStorage.getItem("mdp-" + classe) || ""; } catch (e) { return ""; } }
  function garderMdp(classe, m) { try { localStorage.setItem("mdp-" + classe, m); } catch (e) {} }
  function oublierMdp(classe) { try { localStorage.removeItem("mdp-" + classe); } catch (e) {} }

  function formulaire(texte, erreur) {
    msg.className = erreur ? "erreur" : "";
    msg.textContent = texte;
    champ.style.display = "";
    actions.innerHTML = '<button class="secondaire" type="button" id="annuler">Annuler</button>' +
                        '<button class="principal" type="submit">Valider</button>';
    document.getElementById("annuler").onclick = fermer;
    champ.focus();
  }

  function fermer() {
    fen.classList.remove("ouverte");
    if (urlCourante) { URL.revokeObjectURL(urlCourante); urlCourante = null; }
  }

  async function dechiffrer(fichier, motdepasse) {
    const rep = await fetch(fichier);
    if (!rep.ok) throw new Error("introuvable");
    const tout = new Uint8Array(await rep.arrayBuffer());
    const sel = tout.slice(0, 16), nonce = tout.slice(16, 28), donnees = tout.slice(28);
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(motdepasse),
                                               "PBKDF2", false, ["deriveKey"]);
    const cle = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: sel, iterations: ITERATIONS, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, cle, donnees);
  }

  async function essayer(motdepasse) {
    msg.className = ""; msg.textContent = "Ouverture en cours…";
    champ.style.display = "none"; actions.innerHTML = "";
    try {
      const pdf = await dechiffrer(courant.fichier, motdepasse);
      garderMdp(courant.classe, motdepasse);
      urlCourante = URL.createObjectURL(new Blob([pdf], { type: "application/pdf" }));
      msg.textContent = "Document prêt.";
      actions.innerHTML =
        '<button class="secondaire" type="button" id="annuler">Fermer</button>' +
        '<a class="secondaire" href="' + urlCourante + '" download="' + courant.nom + '">Télécharger</a>' +
        '<a class="principal" href="' + urlCourante + '" target="_blank" rel="noopener">Ouvrir</a>';
      document.getElementById("annuler").onclick = fermer;
    } catch (err) {
      oublierMdp(courant.classe);
      champ.value = "";
      formulaire(err.message === "introuvable" ? "Document introuvable." : "Mot de passe incorrect.", true);
    }
  }

  document.querySelectorAll("a[data-protege]").forEach(function (lien) {
    lien.addEventListener("click", function (ev) {
      ev.preventDefault();
      courant = { fichier: lien.dataset.protege, classe: lien.dataset.classe, nom: lien.dataset.nom };
      document.getElementById("titre-fenetre").textContent = lien.dataset.titre;
      fen.classList.add("ouverte");
      const connu = lireMdp(courant.classe);
      if (connu) { essayer(connu); } else { champ.value = ""; formulaire("Ce document est protégé. Entre le mot de passe donné en classe."); }
    });
  });

  document.getElementById("form-mdp").addEventListener("submit", function (ev) {
    ev.preventDefault();
    if (champ.value) essayer(champ.value);
  });
  fen.addEventListener("click", function (ev) { if (ev.target === fen) fermer(); });
})();
