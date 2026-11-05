
(function () {
  const ITERATIONS = 250000;

  function lireMdp(classe) { try { return localStorage.getItem("mdp-" + classe) || ""; } catch (e) { return ""; } }
  function garderMdp(classe, m) { try { localStorage.setItem("mdp-" + classe, m); } catch (e) {} }
  function oublierMdp(classe) { try { localStorage.removeItem("mdp-" + classe); } catch (e) {} }

  // Format : sel (16 octets) + nonce (12 octets) + données chiffrées (AES-256-GCM)
  async function dechiffrerOctets(tout, motdepasse) {
    const sel = tout.slice(0, 16), nonce = tout.slice(16, 28), donnees = tout.slice(28);
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(motdepasse),
                                               "PBKDF2", false, ["deriveKey"]);
    const cle = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: sel, iterations: ITERATIONS, hash: "SHA-256" },
      base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, cle, donnees);
  }

  async function dechiffrerFichier(fichier, motdepasse) {
    const rep = await fetch(fichier);
    if (!rep.ok) throw new Error("introuvable");
    return dechiffrerOctets(new Uint8Array(await rep.arrayBuffer()), motdepasse);
  }

  // ----- Fenêtre d'ouverture d'un document protégé -----
  const fen = document.getElementById("fenetre");
  const champ = document.getElementById("mdp");
  const msg = document.getElementById("msg");
  const actions = document.getElementById("actions");
  let courant = null, urlCourante = null;

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

  async function essayer(motdepasse) {
    msg.className = ""; msg.textContent = "Ouverture en cours…";
    champ.style.display = "none"; actions.innerHTML = "";
    try {
      const pdf = await dechiffrerFichier(courant.fichier, motdepasse);
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

  function attacher(racine) {
    if (!fen) return;
    racine.querySelectorAll("a[data-protege]").forEach(function (lien) {
      lien.addEventListener("click", function (ev) {
        ev.preventDefault();
        courant = { fichier: lien.dataset.protege, classe: lien.dataset.classe, nom: lien.dataset.nom };
        document.getElementById("titre-fenetre").textContent = lien.dataset.titre;
        fen.classList.add("ouverte");
        const connu = lireMdp(courant.classe);
        if (connu) { essayer(connu); } else { champ.value = ""; formulaire("Ce document est protégé. Entre le mot de passe donné en classe."); }
      });
    });
  }

  if (fen) {
    document.getElementById("form-mdp").addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (champ.value) essayer(champ.value);
    });
    fen.addEventListener("click", function (ev) { if (ev.target === fen) fermer(); });
  }

  // ----- Page d'une classe entièrement protégée -----
  const bloc = document.getElementById("contenu-chiffre");
  if (bloc) {
    const classe = bloc.dataset.classe;
    const zone = document.getElementById("contenu");
    const verrou = document.getElementById("verrou");
    const form = document.getElementById("form-verrou");
    const champV = document.getElementById("mdp-verrou");
    const msgV = document.getElementById("msg-verrou");
    const attente = document.getElementById("attente-verrou");
    const octets = Uint8Array.from(atob(bloc.textContent.trim()), function (c) { return c.charCodeAt(0); });

    function montrerFormulaire(erreur) {
      attente.style.display = "none";
      form.style.display = "";
      msgV.textContent = erreur || "";
      champV.value = "";
      champV.focus();
    }

    async function ouvrir(motdepasse, tape) {
      attente.style.display = ""; form.style.display = "none";
      try {
        const clair = await dechiffrerOctets(octets, motdepasse);
        garderMdp(classe, motdepasse);
        zone.innerHTML = new TextDecoder().decode(clair);
        verrou.remove();
        attacher(zone);
      } catch (err) {
        oublierMdp(classe);
        montrerFormulaire(tape ? "Mot de passe incorrect." : "");
      }
    }

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (champV.value) ouvrir(champV.value, true);
    });
    const connu = lireMdp(classe);
    if (connu) { ouvrir(connu, false); } else { montrerFormulaire(""); }
  }

  attacher(document);
})();
