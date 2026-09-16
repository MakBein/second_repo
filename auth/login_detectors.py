# xss_security_gui/auth/login_detectors.py
"""
login_detectors 12.0 OMNI‑MODE
Рівень Burp / ZAP:
- AI‑подобный детектор login‑форм
- Fallback без <form> (SPA / div‑based логин)
- AJAX‑login детектор (до/после DOM, cookies, URL)
- OAuth / SSO детектор
"""

from typing import Any, Dict, List, Optional


# ============================
#  AI‑DETECTOR LOGIN FORM (WITH <form>)
# ============================

def detect_login_form_ai(page: Any) -> Optional[Dict[str, Any]]:
    """
    AI‑детектор login‑форм 12.0 OMNI‑MODE:
    - анализирует все <form>
    - учитывает React/Vue/Angular формы
    - учитывает Shadow DOM
    - учитывает кастомные кнопки
    - учитывает aria-label, role, data-* атрибуты
    - использует расширенный скоринг
    """

    try:
        forms = page.query_selector_all("form")
    except Exception:
        forms = []

    html_lower = (page.content() or "").lower()
    candidates: List[Dict[str, Any]] = []

    # Если форм нет — fallback на SPA‑детектор
    if not forms:
        return detect_login_form_without_form(page)

    for form in forms:
        try:
            form_html = (form.inner_html() or "").lower()
        except Exception:
            form_html = ""

        # Базовый селектор формы
        try:
            form_sel = form.evaluate(
                """
                e => {
                    if (e.id) return "form#" + e.id;
                    if (e.name) return "form[name='" + e.name + "']";
                    return "form";
                }
                """
            )
        except Exception:
            form_sel = "form"

        # Расширенный поиск input'ов
        input_selectors = [
            "input",
            "textarea",
            "input[type='text']",
            "input[type='email']",
            "input[type='password']",
            "input[autocomplete='username']",
            "input[autocomplete='current-password']",
            "input[data-type='password']",
            "input[data-type='username']",
        ]

        inputs = []
        for sel in input_selectors:
            try:
                inputs.extend(form.query_selector_all(sel))
            except Exception:
                pass

        # Расширенный поиск кнопок
        button_selectors = [
            "button",
            "input[type='submit']",
            "input[type='button']",
            "div[role='button']",
            "span[role='button']",
            "a[href*='login']",
            "a[href*='signin']",
            "a[href*='auth']",
            "img[alt*='login']",
            "svg[alt*='login']",
        ]

        buttons = []
        for sel in button_selectors:
            try:
                buttons.extend(form.query_selector_all(sel))
            except Exception:
                pass

        username_fields: List[tuple[str, int]] = []
        password_fields: List[str] = []
        submit_buttons: List[tuple[str, int]] = []

        # --- Анализ input'ов ---
        for inp in inputs:
            try:
                t = (inp.get_attribute("type") or "").lower()
                name = (inp.get_attribute("name") or "").lower()
                ph = (inp.get_attribute("placeholder") or "").lower()
                ac = (inp.get_attribute("autocomplete") or "").lower()
                aria = (inp.get_attribute("aria-label") or "").lower()
                role = (inp.get_attribute("role") or "").lower()
                data_type = (inp.get_attribute("data-type") or "").lower()
            except Exception:
                continue

            try:
                sel = inp.evaluate(
                    """
                    e => {
                        if (e.id) return "#" + e.id;
                        if (e.name) return e.tagName.toLowerCase() + "[name='" + e.name + "']";
                        return e.tagName.toLowerCase();
                    }
                    """
                )
            except Exception:
                sel = None

            if not sel:
                continue

            # Пароль
            if t == "password" or "password" in data_type or "парол" in ph:
                password_fields.append(sel)

            # Логин
            score_u = 0
            if t in ("text", "email"):
                score_u += 2
            if any(k in name for k in ["user", "login", "email", "account"]):
                score_u += 3
            if any(k in ph for k in ["user", "email", "логин", "аккаунт"]):
                score_u += 3
            if ac == "username":
                score_u += 4
            if "username" in aria:
                score_u += 4
            if role == "textbox":
                score_u += 2

            if score_u > 0:
                username_fields.append((sel, score_u))

        # --- Анализ кнопок ---
        for b in buttons:
            try:
                text = (b.inner_text() or "").lower()
                onclick = (b.get_attribute("onclick") or "").lower()
                aria = (b.get_attribute("aria-label") or "").lower()
                role = (b.get_attribute("role") or "").lower()
            except Exception:
                continue

            try:
                sel = b.evaluate(
                    """
                    e => {
                        if (e.id) return "#" + e.id;
                        if (e.name) return e.tagName.toLowerCase() + "[name='" + e.name + "']";
                        return e.tagName.toLowerCase();
                    }
                    """
                )
            except Exception:
                sel = None

            if not sel:
                continue

            score_s = 0

            # Текст кнопки
            if any(k in text for k in ["login", "sign in", "войти", "авторизация"]):
                score_s += 5

            # onclick
            if any(k in onclick for k in ["login", "auth", "signin"]):
                score_s += 4

            # aria-label
            if any(k in aria for k in ["login", "sign in", "войти"]):
                score_s += 3

            # role
            if role == "button":
                score_s += 2

            # SVG / IMG кнопки
            tag = b.evaluate("e => e.tagName.toLowerCase()")
            if tag in ("svg", "img"):
                score_s += 2

            if score_s > 0:
                submit_buttons.append((sel, score_s))

        # --- Подсчёт score формы ---
        score = 0

        if password_fields:
            score += 10
        if username_fields:
            score += 5
        if submit_buttons:
            score += 4

        # Ключевые слова в HTML формы
        if any(k in form_html for k in ["login", "signin", "вход", "авторизация"]):
            score += 4

        # React/Vue/Angular формы
        if any(k in form_html for k in ["react", "vue", "angular", "next", "nuxt"]):
            score += 2

        # Shadow DOM
        if "<shadow-root" in form_html:
            score += 2

        if not password_fields:
            continue

        username_sel = None
        if username_fields:
            username_sel = sorted(username_fields, key=lambda x: x[1], reverse=True)[0][0]

        password_sel = password_fields[0]
        submit_sel = None
        if submit_buttons:
            submit_sel = sorted(submit_buttons, key=lambda x: x[1], reverse=True)[0][0]

        candidates.append(
            {
                "form_selector": form_sel,
                "username": username_sel,
                "password": password_sel,
                "submit": submit_sel,
                "score": score,
            }
        )

    if not candidates:
        return detect_login_form_without_form(page)

    best = sorted(candidates, key=lambda x: x["score"], reverse=True)[0]
    if best["score"] < 10:
        return None

    return best


# ============================
#  LOGIN DETECTOR WITHOUT <form> (SPA / DIV‑LOGIN)
# ============================

def detect_login_form_without_form(page: Any) -> Optional[Dict[str, Any]]:
    """
    Fallback‑детектор login‑форм для SPA / div‑based логина:
    - ищет поля username/password по атрибутам
    - ищет кнопки login/sign in
    - ищет кастомные кнопки (div/button/span/a/img/svg)
    - ищет Shadow DOM
    - ищет React/Vue/Angular компоненты
    - ищет модальные окна логина
    """

    html_lower = (page.content() or "").lower()

    username_sel = None
    password_sel = None
    submit_sel = None

    # ============================================================
    # 1) Поиск password‑поля (включая кастомные)
    # ============================================================

    pw_selectors = [
        "input[type='password']",
        "input[data-type='password']",
        "input[autocomplete='current-password']",
        "input[placeholder*='парол']",
        "input[placeholder*='pass']",
        "input[id*='pass']",
        "input[name*='pass']",
    ]

    pw_inputs = []
    for sel in pw_selectors:
        try:
            pw_inputs.extend(page.query_selector_all(sel))
        except Exception:
            pass

    if pw_inputs:
        inp = pw_inputs[0]
        try:
            password_sel = inp.evaluate(
                """
                e => {
                    if (e.id) return "#" + e.id;
                    if (e.name) return "input[name='" + e.name + "']";
                    return e.tagName.toLowerCase();
                }
                """
            )
        except Exception:
            password_sel = "input[type='password']"

    # ============================================================
    # 2) Поиск username/email‑поля (расширенный)
    # ============================================================

    username_selectors = [
        "input[type='text']",
        "input[type='email']",
        "input[autocomplete='username']",
        "input[placeholder*='логин']",
        "input[placeholder*='email']",
        "input[placeholder*='user']",
        "input[name*='user']",
        "input[id*='user']",
        "input[name*='login']",
        "input[id*='login']",
    ]

    text_inputs = []
    for sel in username_selectors:
        try:
            text_inputs.extend(page.query_selector_all(sel))
        except Exception:
            pass

    candidates_u: List[tuple[str, int]] = []

    for inp in text_inputs:
        try:
            name = (inp.get_attribute("name") or "").lower()
            ph = (inp.get_attribute("placeholder") or "").lower()
            ac = (inp.get_attribute("autocomplete") or "").lower()
        except Exception:
            continue

        try:
            sel = inp.evaluate(
                """
                e => {
                    if (e.id) return "#" + e.id;
                    if (e.name) return "input[name='" + e.name + "']";
                    return e.tagName.toLowerCase();
                }
                """
            )
        except Exception:
            sel = None

        if not sel:
            continue

        score_u = 0
        if any(k in name for k in ["user", "login", "email", "account"]):
            score_u += 3
        if any(k in ph for k in ["user", "email", "логин", "аккаунт"]):
            score_u += 3
        if ac == "username":
            score_u += 4

        if score_u > 0:
            candidates_u.append((sel, score_u))

    if candidates_u:
        username_sel = sorted(candidates_u, key=lambda x: x[1], reverse=True)[0][0]

    # ============================================================
    # 3) Поиск submit‑кнопки (расширенный)
    # ============================================================

    button_selectors = [
        "button",
        "input[type='submit']",
        "input[type='button']",
        "div[role='button']",
        "span[role='button']",
        "a[href*='login']",
        "a[href*='signin']",
        "a[href*='auth']",
        "img[alt*='login']",
        "svg[alt*='login']",
    ]

    buttons = []
    for sel in button_selectors:
        try:
            buttons.extend(page.query_selector_all(sel))
        except Exception:
            pass

    candidates_s: List[tuple[str, int]] = []

    for b in buttons:
        try:
            text = (b.inner_text() or "").lower()
            onclick = (b.get_attribute("onclick") or "").lower()
            aria = (b.get_attribute("aria-label") or "").lower()
        except Exception:
            continue

        try:
            sel = b.evaluate(
                """
                e => {
                    if (e.id) return "#" + e.id;
                    if (e.name) return e.tagName.toLowerCase() + "[name='" + e.name + "']";
                    return e.tagName.toLowerCase();
                }
                """
            )
        except Exception:
            sel = None

        if not sel:
            continue

        score_s = 0

        # Текст кнопки
        if any(k in text for k in ["login", "sign in", "войти", "авторизация"]):
            score_s += 5

        # onclick
        if any(k in onclick for k in ["login", "auth", "signin"]):
            score_s += 4

        # aria-label
        if any(k in aria for k in ["login", "sign in", "войти"]):
            score_s += 3

        # SVG / IMG кнопки
        if b.evaluate("e => e.tagName.toLowerCase()") in ("svg", "img"):
            score_s += 2

        if score_s > 0:
            candidates_s.append((sel, score_s))

    if candidates_s:
        submit_sel = sorted(candidates_s, key=lambda x: x[1], reverse=True)[0][0]

    # ============================================================
    # 4) Дополнительные эвристики
    # ============================================================

    score = 0
    if password_sel:
        score += 10
    if username_sel:
        score += 5
    if submit_sel:
        score += 4

    # Ключевые слова в HTML
    if any(k in html_lower for k in ["login", "signin", "вход", "авторизация"]):
        score += 4

    # Модальные окна логина
    if any(k in html_lower for k in ["modal-login", "login-modal", "auth-modal"]):
        score += 3

    # React/Vue/Angular компоненты
    if any(k in html_lower for k in ["react", "vue", "angular", "next", "nuxt"]):
        score += 2

    # Shadow DOM
    if "<shadow-root" in html_lower:
        score += 2

    # ============================================================
    # 5) Финальное решение
    # ============================================================

    if score < 10 or not password_sel:
        return None

    return {
        "form_selector": None,
        "username": username_sel,
        "password": password_sel,
        "submit": submit_sel,
        "score": score,
    }



# ============================
#  AJAX LOGIN DETECTOR
# ============================

def detect_ajax_login(
    page: Any,
    before_url: str,
    before_cookies: List[Dict[str, Any]],
    before_dom: str,
) -> bool:
    """
    AJAX‑login детектор 12.0 OMNI‑MODE:
    - сравнивает URL, cookies, DOM
    - проверяет localStorage/sessionStorage
    - проверяет наличие новых токенов (JWT, Bearer)
    - проверяет новые API‑вызовы
    - проверяет GraphQL‑mutation login()
    - проверяет появление sessionId/userId
    - проверяет появление logout‑кнопки
    """

    try:
        after_url = page.url
        after_cookies = page.context.cookies()
        after_dom = page.content()
    except Exception:
        return False

    # === 1. URL изменился ===
    if after_url != before_url:
        return True

    # === 2. Cookies изменились ===
    if after_cookies != before_cookies:
        return True

    # === 3. DOM изменился ===
    if after_dom != before_dom:
        return True

    # === 4. localStorage / sessionStorage ===
    try:
        ls_before = page.evaluate("() => JSON.stringify(window.localStorage)")
        ss_before = page.evaluate("() => JSON.stringify(window.sessionStorage)")
        ls_after = page.evaluate("() => JSON.stringify(window.localStorage)")
        ss_after = page.evaluate("() => JSON.stringify(window.sessionStorage)")

        if ls_before != ls_after:
            return True
        if ss_before != ss_after:
            return True
    except Exception:
        pass

    # === 5. Появление токенов в localStorage/sessionStorage ===
    try:
        tokens = page.evaluate("""
            () => {
                const out = [];
                for (let i = 0; i < localStorage.length; i++) {
                    const k = localStorage.key(i);
                    const v = localStorage.getItem(k);
                    out.push(k + ":" + v);
                }
                for (let i = 0; i < sessionStorage.length; i++) {
                    const k = sessionStorage.key(i);
                    const v = sessionStorage.getItem(k);
                    out.push(k + ":" + v);
                }
                return out;
            }
        """)
        for t in tokens:
            if "jwt" in t.lower():
                return True
            if "token" in t.lower():
                return True
            if "session" in t.lower():
                return True
            if "auth" in t.lower():
                return True
    except Exception:
        pass

    # === 6. Появление userId / sessionId в DOM ===
    try:
        if "userid" in after_dom.lower():
            return True
        if "sessionid" in after_dom.lower():
            return True
        if "profile" in after_dom.lower():
            return True
        if "account" in after_dom.lower():
            return True
    except Exception:
        pass

    # === 7. Появление logout‑кнопки ===
    try:
        if "logout" in after_dom.lower():
            return True
        if "sign out" in after_dom.lower():
            return True
        if "log out" in after_dom.lower():
            return True
    except Exception:
        pass

    # === 8. GraphQL login mutation ===
    try:
        if "mutation" in after_dom.lower() and "login" in after_dom.lower():
            return True
    except Exception:
        pass

    # === 9. Появление Bearer‑токена ===
    try:
        if "bearer " in after_dom.lower():
            return True
    except Exception:
        pass

    # === 10. Появление новых API‑вызовов ===
    try:
        if "fetch(" in after_dom.lower() and "auth" in after_dom.lower():
            return True
        if "axios" in after_dom.lower() and "login" in after_dom.lower():
            return True
    except Exception:
        pass

    return False



# ============================
#  OAUTH / SSO DETECTOR
# ============================

def detect_oauth(html: str) -> List[str]:
    """
    Максимально расширенный детектор OAuth / SSO / IAM / FedAuth провайдеров.
    """

    html = (html or "").lower()
    providers: List[str] = []

    keywords = {
        # === Базовые протоколы ===
        "oauth": "OAuth",
        "oauth2": "OAuth2",
        "openid": "OpenID Connect",
        "oidc": "OpenID Connect",
        "saml": "SAML",
        "ws-fed": "WS-Federation",
        "wsfederation": "WS-Federation",
        "cas": "CAS",
        "kerberos": "Kerberos",
        "ntlm": "NTLM",
        "ldap": "LDAP",
        "radius": "RADIUS",

        # === Мировые провайдеры ===
        "auth0": "Auth0",
        "okta": "Okta",
        "keycloak": "Keycloak",
        "forgerock": "ForgeRock",
        "pingidentity": "Ping Identity",
        "pingfederate": "PingFederate",
        "onelogin": "OneLogin",
        "jumpcloud": "JumpCloud",
        "centrify": "Centrify",
        "sailpoint": "SailPoint",
        "cyberark": "CyberArk",
        "duo": "Duo Security",
        "secureauth": "SecureAuth",
        "oracle identity": "Oracle Identity",
        "ibm security verify": "IBM Security Verify",

        # === Облачные провайдеры ===
        "azure ad": "Azure AD",
        "login.microsoftonline.com": "Azure AD",
        "microsoft identity": "Microsoft Identity Platform",
        "msal": "Microsoft Identity Platform",
        "google sign-in": "Google",
        "accounts.google.com": "Google",
        "firebase auth": "Firebase Auth",
        "aws cognito": "AWS Cognito",
        "cognito": "AWS Cognito",
        "amazon cognito": "AWS Cognito",
        "appleid": "Apple ID",
        "sign in with apple": "Apple ID",

        # === Социальные сети ===
        "facebook login": "Facebook",
        "fb-login": "Facebook",
        "graph.facebook.com": "Facebook",
        "vk.com": "VK",
        "oauth.vk.com": "VK",
        "vkid": "VK ID",
        "vkid-connect": "VK ID",
        "odnoklassniki": "Odnoklassniki",
        "ok.ru": "Odnoklassniki",
        "mail.ru login": "Mail.ru",
        "my.mail.ru": "Mail.ru",
        "yandex id": "Yandex ID",
        "passport.yandex": "Yandex ID",
        "yandex oauth": "Yandex ID",
        "github.com/login": "GitHub",
        "github oauth": "GitHub",
        "gitlab oauth": "GitLab",
        "twitter login": "Twitter",
        "x.com/oauth": "Twitter/X",
        "linkedin login": "LinkedIn",
        "login.live.com": "Microsoft Live",
        "steamcommunity.com/openid": "Steam",
        "twitch oauth": "Twitch",
        "discord oauth": "Discord",

        # === Российские корпоративные SSO / Госуслуги ===
        "gosuslugi": "Госуслуги",
        "esia": "ЕСИА",
        "esia.gosuslugi": "ЕСИА",
        "smev": "СМЭВ",
        "minsvyaz": "Минцифры РФ",
        "mincifry": "Минцифры РФ",
        "rosreestr": "Росреестр",
        "nalog.ru": "ФНС",
        "fns": "ФНС",
        "sberid": "Сбер ID",
        "sberbank id": "Сбер ID",
        "sberbank oauth": "Сбер ID",
        "tinkoff id": "Тинькофф ID",
        "alfabank id": "Альфа ID",
        "vtb id": "ВТБ ID",
        "gazprombank id": "Газпромбанк ID",
        "mts id": "МТС ID",
        "beeline id": "Билайн ID",
        "megafon id": "Мегафон ID",

        # === Корпоративные SSO / Enterprise IAM ===
        "adfs": "ADFS",
        "active directory federation": "ADFS",
        "active directory": "Active Directory",
        "azure b2c": "Azure AD B2C",
        "azure b2b": "Azure AD B2B",
        "ldap auth": "LDAP",
        "kerberos auth": "Kerberos",
        "sso enterprise": "Enterprise SSO",
        "federation": "Federated Identity",
        "identityserver": "Duende IdentityServer",
        "identity server": "Duende IdentityServer",
        "authentik": "Authentik",
        "zitadel": "Zitadel",
        "fusionauth": "FusionAuth",

        # === Банковские / Финансовые SSO ===
        "openbanking": "OpenBanking",
        "psd2": "PSD2",
        "fintech login": "FinTech SSO",
        "bankid": "BankID",
        "bank id": "BankID",

        # === Университеты / Образование ===
        "shibboleth": "Shibboleth",
        "eduid": "EduID",
        "incommon": "InCommon Federation",

        # === Прочие ===
        "oauth redirect": "OAuth",
        "token endpoint": "OAuth",
        "authorize endpoint": "OAuth",
        "idp": "Identity Provider",
        "id provider": "Identity Provider",
        "identity provider": "Identity Provider",
        "login provider": "Identity Provider",
    }

    for key, name in keywords.items():
        if key in html:
            providers.append(name)

    return sorted(set(providers))


