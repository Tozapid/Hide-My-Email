// Hide My Email: the addresses of the alias domains, the log of forwarded
// messages and the account. In the public demo (config.demo) the sign-in is
// published and filled in, and the settings hide the password and two-step
// sign-in, which visitors share. The page signs in with Cognito and calls /api
// with the ID token; the API is in lambda/hide_my_email.py. The texts are in
// i18n.js.
(function () {
  const config = window.HIDE_MY_EMAIL_CONFIG || {};
  const i18n = window.HIDE_MY_EMAIL_I18N;
  const root = document.getElementById("root");
  const state = {
    email: "",
    domain: "",
    // Every alias domain, the page's first.
    domains: [],
    forwardTo: "",
    production: true,
    // Whether this installation receives and sends mail at all.
    mail: true,
    tab: "aliases",
    items: [],
    destinations: {},
    filter: "",
    sort: { field: "created_at", dir: "desc" },
    // The conversation behind a relay address typed into the search.
    relay: null,
    messages: { items: [], cursor: "", q: "", alias: "", loaded: false },
  };
  // A relay address in the current form (office_at_shop_test_<code>) or the
  // older one (r-<code>), with or without the domain.
  const RELAY_RE = /^(r-[a-z0-9]+|[a-z0-9_]+_[a-z2-7]{12})(@\S*)?$/i;
  const ISSUER = "Hide My Email";
  const REPOSITORY = "https://github.com/Tozapid/Hide-My-Email";
  // The language is the Cognito attribute "locale" of the user; the browser
  // keeps a copy so that the sign-in page speaks it too.
  const LANGUAGE_KEY = "hide-my-email-language";
  // The order of the address list, kept in the browser: a field of the API
  // and the direction. Dates and counts start with the largest, comments
  // with A.
  const SORT_KEY = "hide-my-email-sort";
  const SORT_FIELDS = { created_at: "desc", comment: "asc", last_at: "desc", forwarded: "desc" };
  let language = i18n.fallback;
  let pool = null;
  let toastTimer = null;
  let relayTimer = null;
  let messagesTimer = null;

  // Language ---------------------------------------------------------------

  function known(code) {
    return Boolean(code && i18n.strings[code]);
  }

  // The text of a key in the current language with its {name} parts filled.
  function t(key, params) {
    let text = i18n.strings[language][key] ?? i18n.strings[i18n.fallback][key] ?? key;
    if (typeof text === "object") {
      text = text[new Intl.PluralRules(language).select(params.count)] ?? text.other;
    }
    return text.replace(/\{(\w+)\}/g, (part, name) => (params && name in params ? String(params[name]) : part));
  }

  // The same with nodes in place of the {name} parts.
  function tNodes(key, nodes) {
    return t(key).split(/\{(\w+)\}/).map((part, index) => (index % 2 ? nodes[part] : part));
  }

  function setLanguage(code) {
    if (!known(code)) return;
    language = code;
    document.documentElement.lang = code;
    try {
      localStorage.setItem(LANGUAGE_KEY, code);
    } catch (error) {
      // Private windows may refuse storage; the language holds until reload.
    }
  }

  function storedLanguage() {
    try {
      return localStorage.getItem(LANGUAGE_KEY);
    } catch (error) {
      return null;
    }
  }

  async function loadLanguage() {
    try {
      const { user } = await currentUser();
      const attributes = await cognito((done) => user.getUserAttributes(done));
      const locale = (attributes || []).find((attribute) => attribute.getName() === "locale");
      if (locale) setLanguage(locale.getValue());
    } catch (error) {
      // The language of this browser stays.
    }
  }

  async function saveLanguage(code) {
    setLanguage(code);
    try {
      const { user } = await currentUser();
      await cognito((done) => user.updateAttributes([{ Name: "locale", Value: code }], done));
      toast(t("language.saved"));
    } catch (error) {
      toast(authMessage(error));
    }
  }

  // Page helpers -----------------------------------------------------------

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([key, value]) => {
      if (value == null || value === false) return;
      if (key === "class") node.className = value;
      else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
      else if (key === "value") node.value = value;
      else node.setAttribute(key, value === true ? "" : value);
    });
    [].concat(children || []).forEach((child) => {
      if (child == null || child === false) return;
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    });
    return node;
  }

  // replaceChildren() turns null into the text "null"; empty parts are left out.
  function fill(node, children) {
    node.replaceChildren(...children.filter(Boolean));
  }

  function toast(message) {
    let node = document.querySelector(".toast");
    if (!node) {
      node = el("div", { class: "toast", role: "status" });
      document.body.append(node);
    }
    node.textContent = message;
    node.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.add("hidden"), 3500);
  }

  function when(value) {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString(language, { dateStyle: "short", timeStyle: "short" });
  }

  function size(bytes) {
    if (bytes < 1024) return t("unit.b", { n: bytes });
    if (bytes < 1024 * 1024) return t("unit.kb", { n: Math.round(bytes / 1024) });
    return t("unit.mb", { n: (bytes / 1024 / 1024).toLocaleString(language, { maximumFractionDigits: 1 }) });
  }

  function person(name, address) {
    return name ? `${name} <${address}>` : address;
  }

  // A modal window over the page. The page below may re-render; the dialog
  // stays and fill() replaces its contents.
  function dialog(title, onClose) {
    const body = el("div", { class: "modal-body" });
    const node = el("dialog", { class: "modal" }, [
      el("div", { class: "modal-head" }, [
        el("h2", {}, title),
        el("button", { type: "button", class: "ghost close", "aria-label": t("close"), onclick: () => node.close() }, "×"),
      ]),
      body,
    ]);
    node.addEventListener("close", () => {
      node.remove();
      if (onClose) onClose();
    });
    node.addEventListener("click", (event) => {
      if (event.target === node) node.close();
    });
    document.body.append(node);
    node.showModal();
    return { node, close: () => node.close(), fill: (children) => fill(body, [].concat(children)) };
  }

  // Sign-in ----------------------------------------------------------------

  function userPool() {
    if (!pool) {
      pool = new window.AmazonCognitoIdentity.CognitoUserPool({ UserPoolId: config.userPoolId, ClientId: config.clientId });
    }
    return pool;
  }

  // The signed-in user with a valid session, which the account calls need.
  function currentUser() {
    return new Promise((resolve, reject) => {
      const user = userPool().getCurrentUser();
      if (!user) return reject(new Error("auth"));
      user.getSession((error, session) => {
        if (error || !session || !session.isValid()) reject(error || new Error("auth"));
        else resolve({ user, session });
      });
    });
  }

  async function currentSession() {
    return (await currentUser()).session;
  }

  // Wraps a callback-style call of the Cognito library.
  function cognito(call) {
    return new Promise((resolve, reject) => call((error, result) => (error ? reject(error) : resolve(result))));
  }

  function authMessage(error) {
    const code = error && (error.code || error.name);
    if (code === "NotAuthorizedException" || code === "UserNotFoundException") return t("auth.wrong");
    if (code === "InvalidPasswordException") return t("auth.passwordRules");
    if (code === "CodeMismatchException" || code === "EnableSoftwareTokenMFAException") return t("auth.wrongCode");
    if (code === "ExpiredCodeException") return t("auth.expiredCode");
    if (code === "LimitExceededException" || code === "TooManyRequestsException") return t("auth.tooMany");
    return (error && error.message) || t("failed");
  }

  function loginCard(children, onsubmit) {
    root.replaceChildren(el("main", { class: "login" }, el("form", {
      class: "card",
      onsubmit: (event) => {
        event.preventDefault();
        onsubmit();
      },
    }, children)));
  }

  function signInCallbacks(user, error) {
    return {
      onSuccess: () => boot(),
      onFailure: (failure) => { error.textContent = authMessage(failure); },
      newPasswordRequired: () => showNewPassword(user),
      totpRequired: () => showTotp(user),
    };
  }

  // The language menu of the sign-in page and of the account settings.
  function languagePicker(onchange) {
    return el("select", { "aria-label": t("language.title"), onchange: (event) => onchange(event.target.value) },
      i18n.languages.map(([code, name]) => el("option", { value: code, selected: code === language }, name)));
  }

  function showLogin(message) {
    const demo = config.demo || {};
    const error = el("p", { class: "error", role: "alert" }, message || "");
    const email = el("input", { type: "email", autocomplete: "username", required: true, value: demo.email || "" });
    const password = el("input", { type: "password", autocomplete: "current-password", required: true, value: demo.password || "" });
    loginCard([
      el("div", { class: "login-head" }, [
        el("h1", {}, "Hide My Email"),
        languagePicker((code) => {
          setLanguage(code);
          showLogin();
        }),
      ]),
      el("label", {}, [t("login.email"), email]),
      el("label", {}, [t("login.password"), password]),
      el("button", { class: "primary", type: "submit" }, t("login.signIn")),
      error,
      demo.email ? el("p", { class: "demo-note" }, [
        t("demo.signIn", { email: demo.email, password: demo.password }),
        demo.reset ? " " + t("demo.reset") : "",
      ]) : null,
      el("p", { class: "source" }, el("a", { href: REPOSITORY, rel: "noopener" }, t("login.source"))),
    ].filter(Boolean), () => {
      error.textContent = "";
      const user = new window.AmazonCognitoIdentity.CognitoUser({ Username: email.value.trim(), Pool: userPool() });
      user.authenticateUser(new window.AmazonCognitoIdentity.AuthenticationDetails({
        Username: email.value.trim(),
        Password: password.value,
      }), signInCallbacks(user, error));
    });
    email.focus();
  }

  function showNewPassword(user) {
    const error = el("p", { class: "error", role: "alert" });
    const password = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
    loginCard([
      el("h1", {}, t("newPassword.title")),
      el("p", { class: "muted" }, t("newPassword.hint")),
      el("label", {}, [t("password.new"), password]),
      el("button", { class: "primary", type: "submit" }, t("newPassword.submit")),
      error,
    ], () => user.completeNewPasswordChallenge(password.value, {}, signInCallbacks(user, error)));
    password.focus();
  }

  // The second step when two-factor sign-in is on: the code of the
  // authenticator app.
  function showTotp(user) {
    const error = el("p", { class: "error", role: "alert" });
    const code = el("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: "6", required: true });
    loginCard([
      el("h1", {}, t("totp.title")),
      el("p", { class: "muted" }, t("totp.hint")),
      el("label", {}, [t("totp.code"), code]),
      el("button", { class: "primary", type: "submit" }, t("login.signIn")),
      error,
    ], () => {
      error.textContent = "";
      user.sendMFACode(code.value.trim(), signInCallbacks(user, error), "SOFTWARE_TOKEN_MFA");
    });
    code.focus();
  }

  // The API clears the attachment cookie first, while the token still works;
  // the browser cannot, the cookie is HttpOnly.
  async function signOut() {
    const user = pool && pool.getCurrentUser();
    const session = await currentSession().catch(() => null);
    if (session) {
      await fetch(config.apiBase + "/session", {
        method: "DELETE",
        headers: { Authorization: "Bearer " + session.getIdToken().getJwtToken() },
      }).catch(() => null);
    }
    if (user) user.signOut();
    document.querySelectorAll("dialog.modal").forEach((node) => node.close());
    showLogin();
  }

  async function api(path, options) {
    const session = await currentSession().catch(() => null);
    if (!session) {
      showLogin(t("sessionEnded"));
      throw new Error(t("sessionEnded"));
    }
    const response = await fetch(config.apiBase + path, {
      method: (options && options.method) || "GET",
      headers: {
        Authorization: "Bearer " + session.getIdToken().getJwtToken(),
        ...(options && options.body ? { "Content-Type": "application/json" } : {}),
      },
      body: options && options.body ? JSON.stringify(options.body) : undefined,
    });
    let data = {};
    const text = await response.text();
    if (text) {
      try { data = JSON.parse(text); } catch (error) { data = { error: text }; }
    }
    if (response.status === 401) {
      signOut();
      throw new Error(t("sessionEnded"));
    }
    if (!response.ok) {
      // The API names the error with a code; its own text is the English one.
      const translated = data.code && i18n.strings[i18n.fallback]["api." + data.code];
      throw new Error(translated ? t("api." + data.code) : data.error || t("requestFailed"));
    }
    return data;
  }

  function query(params) {
    const search = new URLSearchParams(Object.entries(params).filter(([, value]) => value));
    return search.toString() ? "?" + search : "";
  }

  // Data -------------------------------------------------------------------

  async function load() {
    const data = await api("/aliases");
    state.items = data.items || [];
    state.destinations = data.destinations || {};
    state.production = Boolean(data.production);
  }

  async function reload() {
    try {
      await load();
    } catch (error) {
      toast(error.message);
    }
    render();
  }

  async function change(item, changes, done) {
    try {
      await api("/aliases/" + encodeURIComponent(item.local), { method: "PATCH", body: changes });
      if (done) toast(done);
    } catch (error) {
      toast(error.message);
    }
    await reload();
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast(t("copied", { text }));
    } catch (error) {
      toast(text);
    }
  }

  async function loadMessages(more) {
    const box = state.messages;
    try {
      const data = await api("/messages" + query({ q: box.q.trim(), alias: box.alias, cursor: more ? box.cursor : "" }));
      box.items = more ? box.items.concat(data.items || []) : data.items || [];
      box.cursor = data.cursor || "";
      box.loaded = true;
    } catch (error) {
      toast(error.message);
    }
    renderMessages();
  }

  // Page -------------------------------------------------------------------

  function render() {
    root.replaceChildren(el("div", { class: "app" }, [
      el("header", { class: "top" }, [
        el("div", { class: "brand" }, [el("strong", {}, "Hide My Email"), el("span", {}, state.domains.includes(location.hostname) ? location.hostname : state.domain)]),
        el("nav", { class: "tabs" }, [
          tabButton("aliases", t("tab.aliases")),
          tabButton("messages", t("tab.messages")),
        ]),
        accountMenu(),
      ]),
      el("main", { class: "content" }, [
        sandboxNote(),
        state.tab === "aliases" ? aliasesSection() : messagesSection(),
      ]),
    ]));
    if (state.tab === "aliases") {
      renderAliases();
    } else {
      renderMessages();
      loadMessages(false);
    }
  }

  function tabButton(tab, title) {
    return el("button", {
      type: "button",
      class: "tab" + (state.tab === tab ? " current" : ""),
      "aria-current": state.tab === tab ? "page" : null,
      onclick: () => {
        state.tab = tab;
        render();
      },
    }, title);
  }

  function accountMenu() {
    const menu = el("details", { class: "menu" }, [
      el("summary", {}, [el("span", { class: "who" }, state.email), " ▾"]),
      el("div", { class: "menu-items" }, [
        el("button", { type: "button", onclick: () => { menu.open = false; showAccount(); } }, t("menu.account")),
        el("button", { type: "button", onclick: signOut }, t("menu.signOut")),
      ]),
    ]);
    return menu;
  }

  function sandboxNote() {
    if (!state.mail) {
      return el("p", { class: "note" }, [el("strong", {}, t("noMail.title")), t(config.demo && config.demo.reset ? "noMail.textReset" : "noMail.text")]);
    }
    if (state.production) return null;
    return el("p", { class: "note" }, [
      el("strong", {}, t("sandbox.title")),
      t("sandbox.text"),
    ]);
  }

  // Addresses --------------------------------------------------------------

  function aliasesSection() {
    const active = state.items.filter((item) => item.active).length;
    return el("section", { class: "card" }, [
      el("div", { class: "list-head" }, [
        el("h2", {}, [t("tab.aliases") + " ", el("span", { class: "muted" }, t("aliases.count", { active, total: state.items.length }))]),
        el("div", { class: "tools" }, [
          el("input", {
            type: "search",
            placeholder: t("aliases.search"),
            value: state.filter,
            oninput: (event) => {
              state.filter = event.target.value;
              lookupRelay();
              renderAliases();
            },
          }),
          el("button", { type: "button", class: "primary", onclick: showCreate }, t("aliases.new")),
        ]),
      ]),
      sortTools(),
      el("div", { id: "aliases" }),
    ]);
  }

  function sortTools() {
    const button = el("button", {
      type: "button",
      class: "ghost",
      title: t(state.sort.dir === "asc" ? "sort.asc" : "sort.desc"),
      "aria-label": t(state.sort.dir === "asc" ? "sort.asc" : "sort.desc"),
      onclick: () => setSort(state.sort.field, state.sort.dir === "asc" ? "desc" : "asc"),
    }, state.sort.dir === "asc" ? "↑" : "↓");
    return el("div", { class: "sort" }, [
      el("label", {}, [
        t("sort.label"),
        el("select", { onchange: (event) => setSort(event.target.value, SORT_FIELDS[event.target.value]) },
          Object.keys(SORT_FIELDS).map((field) => el("option", { value: field, selected: field === state.sort.field }, t("sort." + field)))),
      ]),
      button,
    ]);
  }

  function setSort(field, dir) {
    state.sort = { field, dir };
    try {
      localStorage.setItem(SORT_KEY, (dir === "desc" ? "-" : "") + field);
    } catch (error) {
      // The order holds until reload.
    }
    render();
  }

  function storedSort() {
    let value = "";
    try {
      value = localStorage.getItem(SORT_KEY) || "";
    } catch (error) {
      return null;
    }
    const field = value.replace(/^-/, "");
    return SORT_FIELDS[field] ? { field, dir: value.startsWith("-") ? "desc" : "asc" } : null;
  }

  // No mail yet counts as the oldest date, so it goes first ascending and last
  // descending; addresses with no comment go last either way. Equal ones keep
  // the newest first.
  function sorted(items) {
    const { field, dir } = state.sort;
    const sign = dir === "asc" ? 1 : -1;
    const value = (item) => (field === "forwarded" ? item.forwarded || 0 : item[field] || "");
    return items.slice().sort((a, b) => {
      const x = value(a);
      const y = value(b);
      if (field === "comment" && Boolean(x) !== Boolean(y)) return x ? -1 : 1;
      let order = 0;
      if (field === "forwarded") order = x - y;
      else if (field === "comment") order = x.localeCompare(y, language, { sensitivity: "base", numeric: true });
      else order = x < y ? -1 : x > y ? 1 : 0;
      return sign * order || (b.created_at || "").localeCompare(a.created_at || "");
    });
  }

  // A relay address in the search names one conversation; the API says
  // which alias and sender it belongs to.
  function lookupRelay() {
    clearTimeout(relayTimer);
    const value = state.filter.trim();
    if (!RELAY_RE.test(value)) {
      state.relay = null;
      return;
    }
    state.relay = { value, loading: true };
    relayTimer = setTimeout(async () => {
      let found;
      try {
        found = { value, ...(await api("/relays/" + encodeURIComponent(value))) };
      } catch (error) {
        found = { value, error: error.message };
      }
      if (state.filter.trim() !== value) return;
      state.relay = found;
      renderAliases();
    }, 300);
  }

  function renderAliases() {
    const box = document.getElementById("aliases");
    if (!box) return;
    const relay = state.relay;
    const query = state.filter.trim().toLowerCase();
    let items;
    if (relay) {
      items = relay.alias ? state.items.filter((item) => item.local === relay.alias) : [];
    } else {
      items = state.items.filter((item) => !query
        || [item.address, item.comment, item.destination, item.sender_name].some((text) => (text || "").toLowerCase().includes(query)));
    }
    fill(box, [
      relay ? relayNote(relay) : null,
      items.length
        ? el("ul", { class: "rows" }, sorted(items).map(aliasRow))
        : el("p", { class: "muted" }, relay ? null : state.items.length ? t("nothingFound") : t("aliases.empty")),
    ]);
  }

  function relayNote(relay) {
    if (relay.loading) return el("p", { class: "relay muted" }, t("relay.loading"));
    if (relay.error) return el("p", { class: "relay muted" }, t("relay.error", { value: relay.value, error: relay.error }));
    return el("div", { class: "relay" }, [
      el("p", {}, tNodes("relay.found", {
        person: el("strong", {}, person(relay.name, relay.sender)),
        alias: el("strong", {}, relay.address),
      })),
      el("p", { class: "muted mono" }, relay.relay),
      el("button", {
        type: "button",
        class: "ghost",
        onclick: () => showMessages({ q: relay.relay, alias: "" }),
      }, t("relay.messages")),
    ]);
  }

  function aliasRow(item) {
    return el("li", { class: "row alias" + (item.active ? "" : " off") }, [
      el("label", { class: "switch", title: item.active ? t("alias.on") : t("alias.off") }, el("input", {
        type: "checkbox",
        checked: item.active,
        "aria-label": t(item.active ? "alias.turnOff" : "alias.turnOn", { address: item.address }),
        onchange: (event) => change(item, { active: event.target.checked }, t(event.target.checked ? "alias.turnedOn" : "alias.turnedOff")),
      })),
      el("div", { class: "row-main" }, [
        el("button", { type: "button", class: "address", title: t("copy"), onclick: () => copy(item.address) }, item.address),
        el("span", { class: "row-sub muted" }, [
          item.comment || t("alias.noComment"),
          item.forward_to ? " · → " + item.forward_to : "",
        ]),
      ]),
      el("span", { class: "row-stat muted" }, [
        el("span", {}, item.forwarded ? t("alias.forwarded", { count: item.forwarded }) : t("alias.noMail")),
        item.last_at ? el("span", {}, t("alias.lastAt", { date: when(item.last_at) })) : null,
        el("span", {}, t("alias.createdAt", { date: when(item.created_at) })),
      ]),
      el("button", { type: "button", class: "ghost", onclick: () => showAlias(item.local) }, t("alias.details")),
    ]);
  }

  function showCreate() {
    const view = dialog(t("create.title"));
    const comment = el("input", { type: "text", maxlength: "500", placeholder: t("create.commentHint") });
    const forward = el("input", { type: "email", placeholder: state.forwardTo, autocomplete: "email" });
    const local = el("input", { type: "text", maxlength: "40", placeholder: t("field.localHint"), autocomplete: "off" });
    const senderName = el("input", { type: "text", maxlength: "100", placeholder: t("field.senderNameHint"), autocomplete: "off" });
    // With one domain there is nothing to choose.
    const domain = state.domains.length > 1
      ? el("select", { "aria-label": t("field.domain") }, state.domains.map((name) => el("option", { value: name, selected: name === location.hostname }, name)))
      : null;
    const button = el("button", { class: "primary", type: "submit" }, t("create.submit"));
    view.fill(el("form", {
      class: "fields",
      onsubmit: async (event) => {
        event.preventDefault();
        button.disabled = true;
        try {
          const created = await api("/aliases", {
            method: "POST",
            body: {
              comment: comment.value,
              forward_to: forward.value.trim(),
              sender_name: senderName.value.trim(),
              local: local.value.trim() || undefined,
              domain: domain ? domain.value : undefined,
            },
          });
          view.close();
          await copy(created.address);
          await reload();
        } catch (error) {
          toast(error.message);
          button.disabled = false;
        }
      },
    }, [
      el("label", { class: "wide" }, [t("field.comment"), comment]),
      el("label", {}, [t("field.forward"), forward]),
      el("label", {}, [t("field.senderName"), senderName]),
      el("label", { class: domain ? "wide" : null }, [
        domain ? t("field.local") : el("span", {}, [t("field.local") + " ", el("span", { class: "muted" }, "@" + state.domain)]),
        domain ? el("span", { class: "local-domain" }, [local, "@", domain]) : local,
      ]),
      el("div", { class: "actions wide" }, [button]),
    ]));
    comment.focus();
  }

  // The details of one alias; every field saves on change and the dialog
  // shows the saved state.
  function showAlias(local) {
    const view = dialog(t("alias.title"));
    const fill = () => {
      const item = state.items.find((entry) => entry.local === local);
      if (!item) return view.close();
      const save = async (changes, done) => {
        await change(item, changes, done);
        fill();
      };
      view.fill([
        el("div", { class: "alias-head" }, [
          el("button", { type: "button", class: "address big", title: t("copy"), onclick: () => copy(item.address) }, item.address),
          el("label", { class: "switch" }, [
            el("input", {
              type: "checkbox",
              checked: item.active,
              onchange: (event) => save({ active: event.target.checked }, t(event.target.checked ? "alias.turnedOn" : "alias.turnedOff")),
            }),
            t(item.active ? "alias.onShort" : "alias.offShort"),
          ]),
        ]),
        el("div", { class: "fields" }, [
          el("label", { class: "wide" }, [t("field.comment"), el("input", {
            type: "text",
            maxlength: "500",
            value: item.comment,
            placeholder: t("field.comment"),
            onchange: (event) => save({ comment: event.target.value }, t("saved.comment")),
          })]),
          el("label", {}, [el("span", {}, [t("field.forward") + " ", status(item.destination, fill)]), el("input", {
            type: "email",
            value: item.forward_to,
            placeholder: state.forwardTo,
            onchange: (event) => save({ forward_to: event.target.value.trim() }, t("saved.forward")),
          })]),
          // Shown with the alias in replies; empty takes the name from the reply.
          el("label", {}, [t("field.senderName"), el("input", {
            type: "text",
            maxlength: "100",
            value: item.sender_name,
            placeholder: t("field.senderNameHint"),
            onchange: (event) => save({ sender_name: event.target.value.trim() }, t("saved.senderName")),
          })]),
        ]),
        el("dl", { class: "facts" }, [
          el("dt", {}, t("facts.created")), el("dd", {}, when(item.created_at)),
          el("dt", {}, t("facts.forwarded")), el("dd", {}, String(item.forwarded)),
          el("dt", {}, t("facts.last")), el("dd", {}, item.last_at ? when(item.last_at) : "—"),
        ]),
        el("div", { class: "modal-actions" }, [
          el("button", {
            type: "button",
            class: "ghost",
            onclick: () => {
              view.close();
              showMessages({ q: "", alias: item.local });
            },
          }, t("alias.messages")),
          el("button", {
            type: "button",
            class: "danger",
            onclick: async () => {
              if (!window.confirm(t("alias.deleteConfirm", { address: item.address }))) return;
              try {
                await api("/aliases/" + encodeURIComponent(item.local), { method: "DELETE" });
                toast(t("alias.deleted", { address: item.address }));
                view.close();
              } catch (error) {
                toast(error.message);
              }
              await reload();
            },
          }, t("alias.delete")),
        ]),
      ]);
    };
    fill();
  }

  // Whether SES may send to the address; in the sandbox an address has to be
  // verified first, and the page can ask SES to send the link.
  function status(address, after) {
    if (state.production || !state.mail) return null;
    const value = state.destinations[address] || "none";
    if (value === "verified") return el("span", { class: "badge ok" }, t("dest.verified"));
    return el("span", { class: "badge warn" }, [
      t(value === "pending" ? "dest.pending" : "dest.none"),
      el("button", {
        type: "button",
        class: "link",
        onclick: async () => {
          try {
            await api("/destinations", { method: "POST", body: { address } });
            toast(t("dest.sent", { address }));
          } catch (error) {
            toast(error.message);
          }
          await reload();
          if (after) after();
        },
      }, t(value === "pending" ? "dest.resend" : "dest.verify")),
    ]);
  }

  // Messages ---------------------------------------------------------------

  function showMessages(filter) {
    Object.assign(state.messages, filter, { loaded: false, items: [], cursor: "" });
    state.tab = "messages";
    render();
  }

  function messagesSection() {
    const box = state.messages;
    return el("section", { class: "card" }, [
      el("div", { class: "list-head" }, [
        el("h2", {}, t("tab.messages")),
        el("div", { class: "tools" }, [
          el("input", {
            type: "search",
            placeholder: t("messages.search"),
            value: box.q,
            oninput: (event) => {
              box.q = event.target.value;
              clearTimeout(messagesTimer);
              messagesTimer = setTimeout(() => loadMessages(false), 300);
            },
          }),
          el("button", {
            type: "button",
            class: "danger",
            onclick: async () => {
              if (!window.confirm(t(box.alias || box.q.trim() ? "messages.clearFiltered" : "messages.clearAll"))) return;
              try {
                const done = await api("/messages" + query({ q: box.q.trim(), alias: box.alias }), { method: "DELETE" });
                toast(t("messages.deleted", { count: done.deleted }));
              } catch (error) {
                toast(error.message);
              }
              await loadMessages(false);
            },
          }, t("messages.clear")),
        ]),
      ]),
      box.alias ? el("p", { class: "chips" }, el("span", { class: "chip" }, [
        t("messages.aliasFilter", { address: (state.items.find((item) => item.local === box.alias) || {}).address || box.alias }),
        el("button", {
          type: "button",
          class: "link",
          "aria-label": t("messages.removeFilter"),
          onclick: () => {
            box.alias = "";
            render();
          },
        }, "×"),
      ])) : null,
      el("div", { id: "messages" }),
    ]);
  }

  function renderMessages() {
    const box = document.getElementById("messages");
    if (!box) return;
    const data = state.messages;
    if (!data.loaded) {
      box.replaceChildren(el("p", { class: "muted" }, t("loading")));
      return;
    }
    fill(box, [
      data.items.length
        ? el("ul", { class: "rows" }, data.items.map(messageRow))
        : el("p", { class: "muted" }, data.q || data.alias ? t("nothingFound") : t("messages.empty")),
      data.cursor ? el("div", { class: "more" }, el("button", { type: "button", class: "ghost", onclick: () => loadMessages(true) }, t("messages.more"))) : null,
    ]);
  }

  function messageRow(item) {
    const incoming = item.direction === "in";
    return el("li", { class: "row message" }, el("button", { type: "button", class: "row-button", onclick: () => showMessage(item) }, [
      el("span", { class: "dir " + item.direction, title: t(incoming ? "message.in" : "message.out") }, incoming ? "↓" : "↑"),
      el("span", { class: "row-main" }, [
        el("span", { class: "row-title" }, [
          el("strong", {}, incoming ? item.from_name || item.from_address : item.to_name || item.to_address),
          item.spam ? el("span", { class: "badge warn" }, t("message.spam")) : null,
        ]),
        el("span", { class: "row-sub" }, item.subject || t("message.noSubject")),
        el("span", { class: "row-sub muted" }, t(incoming ? "message.toAlias" : "message.fromAlias", { alias: item.alias })),
      ]),
      el("span", { class: "row-stat muted" }, when(item.at)),
    ]));
  }

  async function showMessage(item) {
    const view = dialog(item.subject || t("message.noSubject"));
    view.fill(el("p", { class: "muted" }, t("loading")));
    let message;
    try {
      message = await api("/messages/" + encodeURIComponent(item.id));
    } catch (error) {
      view.fill(el("p", { class: "error" }, error.message));
      return;
    }
    const incoming = message.direction === "in";
    const facts = [
      [t("message.from"), person(message.from_name, message.from_address)],
      [t("message.to"), person(message.to_name, message.to_address)],
      [t(incoming ? "message.forwardedTo" : "message.sentTo"), message.delivered_to],
      [t("message.relay"), message.relay],
      [t("message.date"), when(message.at)],
      [t("message.size"), size(message.size)],
    ].filter(([, value]) => value);
    view.fill([
      el("dl", { class: "facts" }, facts.flatMap(([name, value]) => [el("dt", {}, name), el("dd", {}, value)])),
      message.spam ? el("p", { class: "note" }, t("message.spamNote")) : null,
      message.missing ? el("p", { class: "note" }, t("message.missing")) : null,
      message.attachments.length ? el("div", { class: "attachments" }, [
        el("strong", {}, t("message.attachments")),
        // CloudFront serves the file at the same origin; the signed cookie the
        // API has just set lets the request through.
        ...message.attachments.map((file) => el("a", {
          href: file.url,
          download: file.name || "",
          title: t("message.download", { name: file.name || file.type }),
        }, `${file.name || file.type} (${size(file.size)})`)),
      ]) : null,
      message.missing ? null : el("pre", { class: "mail-text" }, message.text || t("message.noText")),
      el("div", { class: "modal-actions" }, [
        el("button", {
          type: "button",
          class: "ghost",
          onclick: () => {
            const local = message.alias.split("@")[0];
            if (!state.items.some((entry) => entry.local === local)) return toast(t("message.aliasGone", { alias: message.alias }));
            view.close();
            state.tab = "aliases";
            render();
            showAlias(local);
          },
        }, t("message.openAlias")),
        el("button", {
          type: "button",
          class: "danger",
          onclick: async () => {
            if (!window.confirm(t("message.deleteConfirm"))) return;
            try {
              await api("/messages/" + encodeURIComponent(message.id), { method: "DELETE" });
              toast(t("message.deleted"));
              view.close();
            } catch (error) {
              toast(error.message);
            }
            await loadMessages(false);
          },
        }, t("message.delete")),
      ]),
    ]);
  }

  // Account ----------------------------------------------------------------

  function showAccount() {
    const view = dialog(t("account.title"));
    const mfa = el("section", { class: "account-part" }, el("p", { class: "muted" }, t("loading")));
    const tokens = el("section", { class: "account-part" }, el("p", { class: "muted" }, t("loading")));
    view.fill([
      el("p", { class: "muted" }, t("account.signedIn", { email: state.email })),
      el("section", { class: "account-part" }, [
        el("h3", {}, t("language.title")),
        languagePicker(async (code) => {
          await saveLanguage(code);
          // Everything on screen is redrawn in the new language.
          render();
          view.close();
          showAccount();
        }),
      ]),
      // Visitors of the demo share one account: none may change its password
      // or lock it behind their own authenticator app.
      config.demo ? null : passwordForm(),
      config.demo ? null : mfa,
      tokens,
    ]);
    if (!config.demo) showMfa(mfa);
    showTokens(tokens);
  }

  // API keys for the addy.io API at /api/v1, which Bitwarden's generator
  // calls. A new key is shown once; the API keeps only its hash.
  async function showTokens(part, created) {
    const head = el("h3", {}, t("tokens.title"));
    let items;
    try {
      items = (await api("/tokens")).items || [];
    } catch (error) {
      part.replaceChildren(head, el("p", { class: "error" }, error.message));
      return;
    }
    const name = el("input", { type: "text", maxlength: "100", placeholder: "Bitwarden", required: true });
    const button = el("button", { class: "primary", type: "submit" }, t("tokens.create"));
    fill(part, [
      head,
      el("p", { class: "muted small" }, t("tokens.hint", { domain: state.domain, site: location.origin })),
      el("p", { class: "muted small" }, t("tokens.addyHint", { domain: state.domain, site: location.origin })),
      created ? el("div", { class: "note" }, [
        el("p", {}, t("tokens.createdNote")),
        el("button", { type: "button", class: "address", title: t("copy"), onclick: () => copy(created.token) }, created.token),
      ]) : null,
      items.length ? el("ul", { class: "rows" }, items.map((item) => el("li", { class: "row token" }, [
        el("div", { class: "row-main" }, [
          el("strong", {}, item.name),
          el("span", { class: "row-sub muted" }, [
            t("tokens.createdAt", { date: when(item.created_at) }),
            " · ",
            item.last_used_at ? t("tokens.lastUsed", { date: when(item.last_used_at) }) : t("tokens.never"),
          ]),
        ]),
        el("button", {
          type: "button",
          class: "danger",
          onclick: async () => {
            if (!window.confirm(t("tokens.deleteConfirm", { name: item.name }))) return;
            try {
              await api("/tokens/" + encodeURIComponent(item.id), { method: "DELETE" });
              toast(t("tokens.deleted"));
            } catch (error) {
              toast(error.message);
            }
            showTokens(part);
          },
        }, t("tokens.delete")),
      ]))) : el("p", { class: "muted" }, t("tokens.empty")),
      el("form", {
        class: "token-form",
        onsubmit: async (event) => {
          event.preventDefault();
          button.disabled = true;
          try {
            const made = await api("/tokens", { method: "POST", body: { name: name.value.trim() } });
            await copy(made.token);
            showTokens(part, made);
          } catch (error) {
            toast(error.message);
            button.disabled = false;
          }
        },
      }, [el("label", {}, [t("tokens.name"), name]), button]),
    ]);
  }

  function passwordForm() {
    const error = el("p", { class: "error", role: "alert" });
    const current = el("input", { type: "password", autocomplete: "current-password", required: true });
    const next = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
    const again = el("input", { type: "password", autocomplete: "new-password", required: true, minlength: "12" });
    const button = el("button", { class: "primary", type: "submit" }, t("password.submit"));
    const form = el("form", {
      class: "account-part",
      onsubmit: async (event) => {
        event.preventDefault();
        error.textContent = "";
        if (next.value !== again.value) {
          error.textContent = t("password.mismatch");
          return;
        }
        button.disabled = true;
        try {
          const { user } = await currentUser();
          await cognito((done) => user.changePassword(current.value, next.value, done));
          form.reset();
          toast(t("password.changed"));
        } catch (failure) {
          error.textContent = authMessage(failure);
        }
        button.disabled = false;
      },
    }, [
      el("h3", {}, t("password.title")),
      el("label", {}, [t("password.current"), current]),
      el("label", {}, [t("password.new"), next]),
      el("label", {}, [t("password.again"), again]),
      el("p", { class: "muted small" }, t("password.rules")),
      el("div", { class: "actions" }, [button]),
      error,
    ]);
    return form;
  }

  // Two-factor sign-in with an authenticator app (TOTP): Cognito gives a
  // secret, the app shows codes, one code confirms the pairing.
  async function showMfa(part) {
    const head = el("h3", {}, t("mfa.title"));
    let enabled;
    try {
      const { user } = await currentUser();
      const data = await cognito((done) => user.getUserData(done, { bypassCache: true }));
      enabled = (data.UserMFASettingList || []).includes("SOFTWARE_TOKEN_MFA");
    } catch (error) {
      part.replaceChildren(head, el("p", { class: "error" }, authMessage(error)));
      return;
    }
    if (enabled) {
      part.replaceChildren(head,
        el("p", {}, [el("span", { class: "badge ok" }, t("mfa.on")), t("mfa.onText")]),
        el("div", { class: "actions" }, el("button", {
          type: "button",
          class: "danger",
          onclick: async () => {
            if (!window.confirm(t("mfa.disableConfirm"))) return;
            try {
              const { user } = await currentUser();
              await cognito((done) => user.setUserMfaPreference(null, { PreferredMfa: false, Enabled: false }, done));
              toast(t("mfa.disabled"));
            } catch (error) {
              toast(authMessage(error));
            }
            showMfa(part);
          },
        }, t("mfa.disable"))));
      return;
    }
    part.replaceChildren(head,
      el("p", { class: "muted" }, t("mfa.offText")),
      el("div", { class: "actions" }, el("button", { type: "button", class: "primary", onclick: () => pairApp(part, head) }, t("mfa.enable"))));
  }

  async function pairApp(part, head) {
    let user;
    let secret;
    try {
      user = (await currentUser()).user;
      secret = await new Promise((resolve, reject) => user.associateSoftwareToken({
        associateSecretCode: resolve,
        onFailure: reject,
      }));
    } catch (error) {
      toast(authMessage(error));
      return;
    }
    const uri = `otpauth://totp/${encodeURIComponent(ISSUER + ":" + state.email)}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}`;
    const qr = window.qrcode(0, "M");
    qr.addData(uri);
    qr.make();
    const error = el("p", { class: "error", role: "alert" });
    const code = el("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9]{6}", maxlength: "6", required: true });
    const button = el("button", { class: "primary", type: "submit" }, t("mfa.submit"));
    part.replaceChildren(head, el("form", {
      class: "pair",
      onsubmit: async (event) => {
        event.preventDefault();
        error.textContent = "";
        button.disabled = true;
        try {
          await new Promise((resolve, reject) => user.verifySoftwareToken(code.value.trim(), ISSUER, { onSuccess: resolve, onFailure: reject }));
          await cognito((done) => user.setUserMfaPreference(null, { PreferredMfa: true, Enabled: true }, done));
          toast(t("mfa.enabled"));
          showMfa(part);
        } catch (failure) {
          error.textContent = authMessage(failure);
          button.disabled = false;
        }
      },
    }, [
      el("p", {}, t("mfa.step1")),
      el("img", { class: "qr", src: qr.createDataURL(5, 2), alt: t("mfa.qrAlt"), width: "205", height: "205" }),
      el("p", { class: "mono secret" }, secret),
      el("label", {}, [t("mfa.step2"), code]),
      el("div", { class: "actions" }, [button]),
      error,
    ]));
    code.focus();
  }

  async function boot() {
    if (!window.AmazonCognitoIdentity || !config.userPoolId || !config.clientId) {
      root.textContent = t("noAuth");
      return;
    }
    try {
      await currentSession();
      await loadLanguage();
      const me = await api("/me");
      state.email = me.email;
      state.domain = me.domain;
      state.domains = me.domains && me.domains.length ? me.domains : [me.domain];
      state.forwardTo = me.forward_to;
      state.mail = me.mail !== false;
      await load();
      render();
    } catch (error) {
      if (!document.querySelector(".login")) showLogin();
    }
  }

  setLanguage(known(storedLanguage()) ? storedLanguage() : i18n.fallback);
  state.sort = storedSort() || state.sort;
  boot();
})();
