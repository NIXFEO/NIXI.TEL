/* NIXI SBC — WebRTC demo client built on SIP.js (loaded from CDN in index.html).
 * Register / call / hang up / DTMF keypad. No build step. */
/* global SIP */

const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const logEl = $("log");

let userAgent = null;
let registerer = null;
let session = null;

function log(msg) {
  console.log(msg);
  logEl.textContent += `${new Date().toISOString().slice(11, 19)} ${msg}\n`;
  logEl.scrollTop = logEl.scrollHeight;
}

function setStatus(text) {
  statusEl.textContent = text;
}

function iceServers() {
  try {
    return JSON.parse($("ice").value);
  } catch {
    log("Invalid ICE servers JSON — using none");
    return [];
  }
}

function setupRemoteMedia(sipSession) {
  const remote = new MediaStream();
  sipSession.sessionDescriptionHandler.peerConnection
    .getReceivers()
    .forEach((r) => r.track && remote.addTrack(r.track));
  $("remoteAudio").srcObject = remote;
}

function sessionButtons(active) {
  $("call").disabled = active;
  $("hangup").disabled = !active;
  $("keypad").hidden = !active;
}

function watchSession(sipSession) {
  session = sipSession;
  sipSession.stateChange.addListener((state) => {
    log(`call state: ${state}`);
    if (state === SIP.SessionState.Established) {
      setupRemoteMedia(sipSession);
      setStatus("in call");
      sessionButtons(true);
    }
    if (state === SIP.SessionState.Terminated) {
      setStatus("registered");
      sessionButtons(false);
      session = null;
    }
  });
}

$("register").onclick = async () => {
  const server = $("wss").value.trim();
  const uri = SIP.UserAgent.makeURI($("uri").value.trim());
  if (!uri) return log("Invalid SIP URI");

  userAgent = new SIP.UserAgent({
    uri,
    transportOptions: { server },
    authorizationUsername: uri.user,
    authorizationPassword: $("password").value,
    sessionDescriptionHandlerFactoryOptions: {
      peerConnectionConfiguration: { iceServers: iceServers() },
    },
    delegate: {
      onInvite(invitation) {
        log(`incoming call from ${invitation.remoteIdentity.uri}`);
        watchSession(invitation);
        invitation.accept({
          sessionDescriptionHandlerOptions: {
            constraints: { audio: true, video: false },
          },
        });
      },
      onDisconnect(error) {
        setStatus("disconnected");
        $("register").disabled = false;
        $("unregister").disabled = true;
        sessionButtons(false);
        if (error) log(`transport error: ${error}`);
      },
    },
  });

  setStatus("connecting…");
  try {
    await userAgent.start();
    registerer = new SIP.Registerer(userAgent, { expires: 300 });
    registerer.stateChange.addListener((s) => {
      log(`registration: ${s}`);
      if (s === SIP.RegistererState.Registered) {
        setStatus("registered");
        $("register").disabled = true;
        $("unregister").disabled = false;
        $("call").disabled = false;
      }
    });
    await registerer.register();
  } catch (e) {
    setStatus("failed");
    log(`register failed: ${e}`);
  }
};

$("unregister").onclick = async () => {
  if (registerer) await registerer.unregister().catch(() => {});
  if (userAgent) await userAgent.stop().catch(() => {});
  setStatus("disconnected");
  $("register").disabled = false;
  $("unregister").disabled = true;
  sessionButtons(false);
  $("call").disabled = true;
};

$("call").onclick = async () => {
  const raw = $("target").value.trim();
  const domain = SIP.UserAgent.makeURI($("uri").value.trim()).host;
  const target = SIP.UserAgent.makeURI(
    raw.startsWith("sip:") ? raw : `sip:${raw}@${domain}`
  );
  if (!target) return log("Invalid destination");

  const inviter = new SIP.Inviter(userAgent, target, {
    sessionDescriptionHandlerOptions: {
      constraints: { audio: true, video: false },
    },
  });
  watchSession(inviter);
  setStatus("calling…");
  sessionButtons(true);
  try {
    await inviter.invite();
  } catch (e) {
    log(`call failed: ${e}`);
    setStatus("registered");
    sessionButtons(false);
  }
};

$("hangup").onclick = async () => {
  if (!session) return;
  switch (session.state) {
    case SIP.SessionState.Initial:
    case SIP.SessionState.Establishing:
      if (session instanceof SIP.Inviter) await session.cancel();
      else await session.reject();
      break;
    case SIP.SessionState.Established:
      await session.bye();
      break;
  }
};

// DTMF keypad — sends RFC 4733 telephone-event via the media path
for (const key of ["1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"]) {
  const btn = document.createElement("button");
  btn.textContent = key;
  btn.onclick = () => {
    if (!session || session.state !== SIP.SessionState.Established) return;
    const dtmfSender = session.sessionDescriptionHandler.peerConnection
      .getSenders()
      .find((s) => s.dtmf)?.dtmf;
    if (dtmfSender) {
      dtmfSender.insertDTMF(key, 120, 70);
      log(`DTMF: ${key}`);
    }
  };
  $("keypad").appendChild(btn);
}
