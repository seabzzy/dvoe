"use strict";
// Двое — звонки для двоих.
//
// Модель безопасности:
// 1. Из секретного кода (PBKDF2, 310 000 итераций) получаются два значения:
//    идентификатор комнаты (видит сервер связи) и ключ проверки (никуда не уходит).
//    Сервер связи не знает сам код.
// 2. Прежде чем отправить хоть один кадр, телефоны проверяют друг друга
//    по ключу (HMAC). Подпись привязана к отпечаткам шифрования DTLS обоих концов,
//    поэтому сервер связи не может незаметно встать посередине.
// 3. Звонок принимается только от проверенного собеседника. Пока проверка не пройдена,
//    камера и микрофон передают чёрный кадр и тишину, а чужое видео не показывается.
(() => {
  if (window.top !== window.self) { document.body.textContent = ""; return; } // защита от встраивания в чужие сайты

  const $ = id => document.getElementById(id);
  const enc = new TextEncoder();
  const store = {
    get(k) { try { return localStorage.getItem(k) || ""; } catch { return ""; } },
    set(k, v) { try { v ? localStorage.setItem(k, v) : localStorage.removeItem(k); } catch {} }
  };

  const SLOTS = "abcdef";
  const MIN_CODE = 10;

  // ---------- настройки ----------
  $("room").value = store.get("dvoe_room");
  $("remember").checked = !!store.get("dvoe_room");
  for (const id of ["turnUrl", "turnUser", "turnPass"]) $(id).value = store.get("dvoe_" + id);
  $("audioOnly").checked = store.get("dvoe_audioOnly") === "1";
  $("relayOnly").checked = store.get("dvoe_relayOnly") === "1";

  $("gen").onclick = () => {
    const a = "abcdefghjkmnpqrstuvwxyz23456789"; // 31 символ, без похожих
    let s = "";
    // равномерная выборка без смещения
    while (s.length < 14) {
      const b = crypto.getRandomValues(new Uint8Array(1))[0];
      if (b < 248) s += a[b % 31];
    }
    $("room").value = s.slice(0, 7) + "-" + s.slice(7);
  };

  // ---------- состояние ----------
  let localStream = null, preview = null, peer = null, ending = false;
  let roomBase = "", hmacKey = null, mySlot = -1, myId = "";
  let session = null;          // текущий проверенный собеседник
  const links = new Map();     // peerId -> {dc, nonce, verified, call, mediaOk, ...}
  let dialTimer = null, tick = null, startedAt = 0, facing = "user";
  const want = { audio: true, video: true };
  const diagState = { server: "…", check: "—", ice: "—" };

  const setStatus = (main, sub = "", warn = false) => {
    const el = $("status");
    el.hidden = !main;
    el.classList.toggle("warn", warn);
    el.textContent = "";
    if (!main) return;
    el.append(main);
    if (sub) { const s = document.createElement("small"); s.textContent = sub; el.append(s); }
  };
  function diag(k, v) {
    if (k) diagState[k] = v;
    $("diag").textContent = `сервер: ${diagState.server} · место: ${mySlot < 0 ? "…" : mySlot + 1} · проверка: ${diagState.check} · соединение: ${diagState.ice}`;
  }

  // ---------- криптография ----------
  async function deriveRoom(code) {
    const norm = code.normalize("NFKC").trim().toLowerCase();
    const base = await crypto.subtle.importKey("raw", enc.encode(norm), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: enc.encode("dvoe/v2/room"), iterations: 310000 }, base, 512));
    const roomHex = [...bits.slice(0, 16)].map(b => b.toString(16).padStart(2, "0")).join("");
    const key = await crypto.subtle.importKey("raw", bits.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    bits.fill(0);
    return { roomBase: "dvoe2-" + roomHex, key };
  }
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => { try { return Uint8Array.from(atob(String(s)), c => c.charCodeAt(0)); } catch { return new Uint8Array(0); } };
  const sign = msg => crypto.subtle.sign("HMAC", hmacKey, enc.encode(msg)).then(b64);
  const verify = (mac, msg) => crypto.subtle.verify("HMAC", hmacKey, unb64(mac), enc.encode(msg)); // сравнение за постоянное время
  function fingerprints(pc) {
    const get = d => ((d && d.sdp || "").match(/^a=fingerprint:(.+)$/m) || [])[1] || "";
    const l = get(pc && pc.localDescription), r = get(pc && pc.remoteDescription);
    return l && r ? { l: l.trim().toLowerCase(), r: r.trim().toLowerCase() } : null;
  }

  // ---------- сеть ----------
  function iceConfig() {
    const list = [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: "stun:stun.cloudflare.com:3478" }
    ];
    const url = $("turnUrl").value.trim();
    const hasTurn = /^turns?:/i.test(url);
    if (hasTurn) {
      const urls = [url];
      if (/^turn:global\.relay\.metered\.ca/i.test(url)) urls.push("turn:global.relay.metered.ca:443?transport=tcp", "turns:global.relay.metered.ca:443?transport=tcp");
      list.push({ urls, username: $("turnUser").value.trim(), credential: $("turnPass").value });
    }
    const relay = hasTurn && $("relayOnly").checked;
    return { iceServers: relay ? list.filter(s => /^turns?:/.test([].concat(s.urls)[0])) : list, iceTransportPolicy: relay ? "relay" : "all" };
  }

  function gate() {
    if (!localStream) return;
    const ok = !!(session && session.mediaOk);
    for (const t of localStream.getAudioTracks()) t.enabled = ok && want.audio;
    for (const t of localStream.getVideoTracks()) t.enabled = ok && want.video;
    if (preview) for (const t of preview.getVideoTracks()) t.enabled = want.video;
  }
  function setPreview() {
    if (preview) preview.getTracks().forEach(t => t.stop());
    preview = localStream ? new MediaStream(localStream.getVideoTracks().map(t => { const c = t.clone(); c.enabled = true; return c; })) : null;
    $("local").srcObject = preview;
  }

  async function start() {
    $("err").textContent = "";
    const code = $("room").value.trim();
    if (code.length < MIN_CODE) { $("err").textContent = `Код должен быть не короче ${MIN_CODE} символов. Нажмите «Новый», чтобы получить надёжный.`; return; }
    if (!window.Peer) { $("err").textContent = "Не загрузилась библиотека связи. Обновите страницу."; return; }
    if (!window.isSecureContext || !navigator.mediaDevices || !crypto.subtle) { $("err").textContent = "Откройте ссылку в Chrome по адресу https:// (не внутри Telegram/WhatsApp)."; return; }
    if ($("relayOnly").checked && !/^turns?:/i.test($("turnUrl").value.trim())) { $("err").textContent = "«Скрыть мой IP» работает только с TURN-сервером. Заполните его данные или снимите галочку."; return; }

    store.set("dvoe_room", $("remember").checked ? code : "");
    for (const id of ["turnUrl", "turnUser", "turnPass"]) store.set("dvoe_" + id, $(id).value);
    store.set("dvoe_audioOnly", $("audioOnly").checked ? "1" : "");
    store.set("dvoe_relayOnly", $("relayOnly").checked ? "1" : "");

    $("go").disabled = true;
    try {
      ({ roomBase, key: hmacKey } = await deriveRoom(code));
      try {
        localStream = await navigator.mediaDevices.getUserMedia({
          audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
          video: $("audioOnly").checked ? false : { facingMode: facing, width: { ideal: 1280 }, height: { ideal: 720 } }
        });
      } catch { $("err").textContent = "Нет доступа к микрофону или камере. Разрешите доступ в настройках сайта в Chrome."; return; }
    } finally { $("go").disabled = false; }

    if (!$("remember").checked) $("room").value = "";
    ending = false; want.audio = true; want.video = true;
    setPreview(); gate();
    $("start").hidden = true; $("call").hidden = false;
    const hasVideo = localStream.getVideoTracks().length > 0;
    $("local").hidden = $("cam").hidden = $("flip").hidden = !hasVideo;
    try { await navigator.wakeLock?.request("screen"); } catch {}
    mySlot = -1; Object.assign(diagState, { server: "подключаемся", check: "—", ice: "—" }); diag();
    setStatus("Подключаемся…");
    claim(0);
  }

  function claim(i) {
    if (ending) return;
    const id = roomBase + "-" + SLOTS[i];
    const p = new Peer(id, { config: iceConfig(), debug: 0 });
    peer = p;
    p.on("open", () => {
      mySlot = i; myId = id;
      diag("server", "есть");
      if (i === 0) setStatus("Ждём второго человека…", "Пусть откроет приложение с тем же кодом. Не сворачивайте Chrome.");
      else dialRound();
    });
    p.on("connection", dc => { if (!isTaken()) setupLink(dc); else dc.close(); });
    p.on("call", call => {
      const link = links.get(call.peer);
      if (!link || link.call || isTaken(link)) { call.close(); return; }
      link.call = call;
      if (link.verified) answerCall(link);
      else link.answerTimer = setTimeout(() => { if (!link.verified) dropLink(link); }, 10000);
    });
    p.on("error", err => {
      if (ending) return;
      if (err.type === "unavailable-id") {
        p.destroy();
        if (i + 1 < SLOTS.length) claim(i + 1);
        else setStatus("Код занят", "Закройте лишние вкладки с приложением на обоих телефонах или выберите новый код.");
      } else if (err.type === "peer-unavailable") {
        // на этом месте пока никого — повторим в следующем круге
      } else if (["network", "server-error", "socket-error", "socket-closed", "disconnected"].includes(err.type)) {
        diag("server", "нет связи");
        if (!session) setStatus("Нет связи с сервером", "Проверьте интернет. Пробуем снова…");
        clearTimeout(dialTimer);
        dialTimer = setTimeout(() => { if (!ending) { resetLinks(); p.destroy(); mySlot = -1; claim(0); } }, 4000);
      } else {
        diag("server", "ошибка");
      }
    });
    p.on("disconnected", () => { diag("server", "переподключаемся"); if (!ending && !p.destroyed) try { p.reconnect(); } catch {} });
  }

  const isTaken = except => {
    if (!session || session === except || !session.mediaOk) return false;
    const pc = session.call && session.call.peerConnection;
    const st = pc ? pc.iceConnectionState : "closed";
    if (st === "failed" || st === "closed") { onLinkClosed(session); return false; }
    return true;
  };

  // Звонит тот, у кого место больше: открывает защищённый канал ко всем меньшим местам.
  function dialRound() {
    clearTimeout(dialTimer);
    if (ending || !peer || peer.destroyed || mySlot <= 0 || isTaken()) return;
    for (const l of [...links.values()]) if (!l.verified) dropLink(l);
    if (peer.disconnected) { try { peer.reconnect(); } catch {} }
    else {
      setStatus("Звоним…", "Ждём, пока второй телефон ответит");
      for (let j = 0; j < mySlot; j++) {
        const dc = peer.connect(roomBase + "-" + SLOTS[j], { reliable: true, serialization: "json" });
        if (dc) setupLink(dc);
      }
    }
    dialTimer = setTimeout(dialRound, 9000);
  }

  function setupLink(dc) {
    const old = links.get(dc.peer);
    if (old) dropLink(old);
    const link = { dc, peerId: dc.peer, nonce: b64(crypto.getRandomValues(new Uint8Array(32))), verified: false, sentProof: false, call: null, mediaOk: false, theirMediaOk: false, sentMedia: false };
    links.set(dc.peer, link);
    dc.on("open", () => { diag("check", "идёт"); send(link, { t: "hello", n: link.nonce }); });
    dc.on("data", m => onMessage(link, m).catch(() => fail(link)));
    dc.on("close", () => onLinkClosed(link));
    dc.on("error", () => onLinkClosed(link));
    link.authTimer = setTimeout(() => { if (!link.verified) dropLink(link); }, 15000);
  }

  const send = (link, msg) => { try { link.dc.send(msg); } catch {} };

  async function onMessage(link, m) {
    if (!m || typeof m !== "object" || typeof m.t !== "string") return;
    if ("mac" in m && (typeof m.mac !== "string" || m.mac.length > 100)) return fail(link);
    if (m.t === "hello" && typeof m.n === "string" && m.n.length <= 64 && !link.sentProof) {
      const fp = fingerprints(link.dc.peerConnection);
      if (!fp) return fail(link);
      link.sentProof = true;
      // Подписываем: их случайное число + оба ID + оба отпечатка шифрования.
      send(link, { t: "proof", mac: await sign(`auth|${m.n}|${myId}|${link.peerId}|${fp.l}|${fp.r}`) });
    } else if (m.t === "proof" && !link.verified) {
      const fp = fingerprints(link.dc.peerConnection);
      if (!fp || !(await verify(m.mac, `auth|${link.nonce}|${link.peerId}|${myId}|${fp.r}|${fp.l}`))) return fail(link);
      link.verified = true;
      clearTimeout(link.authTimer);
      diag("check", "канал ✓");
      // Звонящий (большее место) начинает видеозвонок; принимающий ждёт.
      if (myId > link.peerId && !link.call) {
        clearTimeout(dialTimer);
        const call = peer.call(link.peerId, localStream);
        if (call) { link.call = call; watchCall(link); }
      } else if (link.call && !link.answered) answerCall(link);
    } else if (m.t === "media" && link.verified && link.call && !link.theirMediaOk) {
      link.pendingMediaMac = m.mac;   // может прийти раньше, чем закончится обмен описаниями звонка
      await checkMediaProof(link);
    } else if (m.t === "bye") {
      onLinkClosed(link);
    }
  }

  async function checkMediaProof(link) {
    if (!link.pendingMediaMac || link.theirMediaOk || link.checkingMedia || link.dead) return;
    const fp = fingerprints(link.call && link.call.peerConnection);
    if (!fp) return; // повторим, когда появятся оба описания
    link.checkingMedia = true;
    const ok = await verify(link.pendingMediaMac, `media|${link.peerId}|${myId}|${fp.r}|${fp.l}`);
    link.checkingMedia = false;
    if (!ok) return fail(link);
    link.theirMediaOk = true;
    maybeMediaOk(link);
  }

  function answerCall(link) {
    clearTimeout(link.answerTimer);
    link.answered = true;
    link.call.answer(localStream);
    watchCall(link);
  }

  function watchCall(link) {
    const call = link.call;
    call.on("stream", remote => { link.remote = remote; sendMediaProof(link); checkMediaProof(link); });
    call.on("close", () => onLinkClosed(link));
    call.on("error", () => onLinkClosed(link));
    const pc = call.peerConnection;
    if (pc) pc.addEventListener("iceconnectionstatechange", () => {
      const st = pc.iceConnectionState;
      diag("ice", { new: "начало", checking: "проверка пути", connected: "есть", completed: "есть", disconnected: "прервалось", failed: "не удалось", closed: "закрыто" }[st] || st);
      if (st === "connected" || st === "completed") { sendMediaProof(link); checkMediaProof(link); }
      if (st === "checking") { sendMediaProof(link); checkMediaProof(link); }
      if (st === "failed" && session === link) { onLinkClosed(link); return; }
      if (st === "failed") setStatus("Телефоны нашли друг друга, но сеть не пропускает звонок",
        "Попробуйте оба подключиться к Wi-Fi или добавьте TURN-сервер (раздел внизу главного экрана).", true);
    });
  }

  async function sendMediaProof(link) {
    if (link.sentMedia || !link.call) return;
    const fp = fingerprints(link.call.peerConnection);
    if (!fp) return;
    link.sentMedia = true;
    send(link, { t: "media", mac: await sign(`media|${myId}|${link.peerId}|${fp.l}|${fp.r}`) });
    await checkMediaProof(link);
    maybeMediaOk(link);
  }

  function maybeMediaOk(link) {
    if (!link.sentMedia || !link.theirMediaOk || !link.remote || link.mediaOk) return;
    link.mediaOk = true;
    session = link;
    clearTimeout(dialTimer);
    for (const l of [...links.values()]) if (l !== link) dropLink(l);
    diag("check", "✓ это ваш собеседник");
    gate();
    $("remote").srcObject = link.remote;
    $("remote").play().catch(() => {});
    const hasVideo = link.remote.getVideoTracks().length > 0;
    setStatus(hasVideo ? "" : "На связи", hasVideo ? "" : "Голосовой звонок");
    startTimer();
  }

  function fail(link) {
    dropLink(link);
    diag("check", "НЕ ПРОЙДЕНА");
    if (!session) setStatus("Подключился кто-то чужой", "Проверка кода не пройдена, звонок не начат. Если это повторяется, смените код.", true);
  }

  function dropLink(link) {
    clearTimeout(link.authTimer); clearTimeout(link.answerTimer);
    if (links.get(link.peerId) === link) links.delete(link.peerId);
    link.dead = true;
    try { link.call && link.call.close(); } catch {}
    try { link.dc && link.dc.close(); } catch {}
  }

  function onLinkClosed(link) {
    if (link.dead) return;
    const wasSession = session === link;
    dropLink(link);
    if (!wasSession || ending) return;
    session = null; gate();
    $("remote").srcObject = null;
    stopTimer();
    Object.assign(diagState, { check: "—", ice: "—" }); diag();
    setStatus("Собеседник отключился", "Ждём, когда вернётся…");
    if (mySlot > 0) dialTimer = setTimeout(dialRound, 2000);
  }

  function resetLinks() { for (const l of [...links.values()]) dropLink(l); session = null; gate(); }

  function startTimer() {
    if (tick) return;
    startedAt = Date.now();
    $("timer").hidden = false;
    tick = setInterval(() => {
      const s = Math.floor((Date.now() - startedAt) / 1000);
      const h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, ss = s % 60;
      $("timer").textContent = (h ? h + ":" : "") + String(m).padStart(2, "0") + ":" + String(ss).padStart(2, "0");
    }, 1000);
  }
  function stopTimer() { clearInterval(tick); tick = null; $("timer").hidden = true; $("timer").textContent = "00:00"; }

  function hangUp() {
    ending = true;
    clearTimeout(dialTimer);
    stopTimer();
    if (session) send(session, { t: "bye" });
    setTimeout(() => {
      resetLinks();
      try { peer && peer.destroy(); } catch {}
      peer = null;
    }, 150);
    mySlot = -1; hmacKey = null; roomBase = ""; myId = "";
    if (localStream) localStream.getTracks().forEach(t => t.stop());
    localStream = null; setPreview();
    $("remote").srcObject = $("local").srcObject = null;
    for (const b of ["mic", "cam"]) $(b).classList.remove("off");
    $("call").hidden = true; $("start").hidden = false;
  }

  $("go").onclick = start;
  $("room").addEventListener("keydown", e => { if (e.key === "Enter") start(); });
  $("hang").onclick = hangUp;
  $("mic").onclick = () => { want.audio = !want.audio; $("mic").classList.toggle("off", !want.audio); gate(); };
  $("cam").onclick = () => { want.video = !want.video; $("cam").classList.toggle("off", !want.video); gate(); };
  $("flip").onclick = async () => {
    if (!localStream || !localStream.getVideoTracks().length) return;
    const next = facing === "user" ? "environment" : "user";
    try {
      const fresh = await navigator.mediaDevices.getUserMedia({ video: { facingMode: next, width: { ideal: 1280 }, height: { ideal: 720 } } });
      const nt = fresh.getVideoTracks()[0], old = localStream.getVideoTracks()[0];
      const pc = session && session.call && session.call.peerConnection;
      const sender = pc && pc.getSenders().find(s => s.track && s.track.kind === "video");
      if (sender) await sender.replaceTrack(nt);
      localStream.removeTrack(old); old.stop(); localStream.addTrack(nt);
      facing = next; setPreview(); gate();
      $("local").classList.toggle("back", facing === "environment");
    } catch {}
  };

  document.addEventListener("visibilitychange", async () => {
    if (document.visibilityState !== "visible" || !localStream) return;
    try { await navigator.wakeLock?.request("screen"); } catch {}
    if (peer && peer.disconnected && !peer.destroyed) { try { peer.reconnect(); } catch {} }
    if (mySlot > 0 && !session) setTimeout(dialRound, 800);
  });
  window.addEventListener("pagehide", () => { if (session) send(session, { t: "bye" }); });
})();
