import os


# ============================
#  PUBLIC API
# ============================

def perform_login(page, login_config: dict) -> None:
    """
    Высокоуровневый login-flow:
    - пытается восстановить сессию
    - переходит на login URL
    - запускает AI‑детектор формы
    - аккуратно заполняет и сабмитит
    - не роняет GUI при любых ошибках
    """
    try:
        # 0) Попытка восстановить сессию
        try:
            if load_session(page.context):
                print("[🔄] Сессия восстановлена — проверяю авторизацию...")
                page.reload()
                page.wait_for_timeout(1200)
        except Exception:
            pass

        login_url = login_config.get("url")
        if not login_url:
            print("[ℹ️] Login URL отсутствует — пропускаю авторизацию.")
            return

        # 1) Переход на страницу логина
        page.goto(login_url, timeout=15000)
        page.wait_for_timeout(800)

        # 2) AI‑детектор login‑форм
        form_info = detect_login_form_ai(page)
        if not form_info:
            print("[ℹ️] Login‑форма не обнаружена — пропускаю авторизацию.")
            return

        print(f"[🤖] Выбрана login‑форма: {form_info}")

        user_sel = form_info.get("username")
        pass_sel = form_info.get("password")
        submit_sel = form_info.get("submit")

        if not pass_sel:
            print("[⚠️] Не удалось определить поле пароля — пропускаю авторизацию.")
            return

        # 3) Заполнение полей
        if user_sel and page.query_selector(user_sel):
            page.fill(user_sel, login_config.get("username", "admin"))
        else:
            print("[⚠️] Поле username не найдено или не определено — продолжаю только с паролем.")

        if pass_sel and page.query_selector(pass_sel):
            page.fill(pass_sel, login_config.get("password", "admin123"))
        else:
            print("[⚠️] Поле пароля не найдено — прерываю авторизацию.")
            return

        # 4) Сабмит
        if submit_sel and page.query_selector(submit_sel):
            page.click(submit_sel)
        else:
            print("[ℹ️] Кнопка submit не найдена — пробую Enter по полю пароля.")
            if pass_sel and page.query_selector(pass_sel):
                page.press(pass_sel, "Enter")
            else:
                print("[⚠️] Невозможно выполнить Enter — прерываю авторизацию.")
                return

        # Снимки состояния для AJAX‑детектора
        before_url = page.url
        before_cookies = page.context.cookies()
        before_dom = page.content()

        page.wait_for_timeout(1500)

        # 5) AJAX‑логин
        if detect_ajax_login(page, before_url, before_cookies, before_dom):
            print("[✔️] AJAX‑логин подтверждён")

        # 6) OAuth / SSO
        html = page.content().lower()
        oauth = detect_oauth(html)
        if oauth:
            print(f"[ℹ️] Обнаружены OAuth/SSO провайдеры: {oauth}")

        # 7) Проверка успешного входа
        cookies = page.context.cookies()
        success_checks = [
            page.url != login_url,
            any("session" in c["name"].lower() for c in cookies),
            "logout" in html,
            "profile" in html,
            "account" in html,
        ]

        if any(success_checks):
            print("[🔐] Авторизация успешна.")
            save_session(page.context)
        else:
            print("[⚠️] Авторизация, вероятно, не удалась.")

    except Exception as e:
        print(f"[❌] Ошибка авторизации: {e}")


# ============================
#  AI‑DETECTOR LOGIN FORM
# ============================

def detect_login_form_ai(page) -> dict | None:
    """
    AI‑подобный детектор login‑форм:
    - собирает все формы
    - анализирует поля и подписи
    - считает score для каждой формы
    - выбирает лучшую
    Возвращает:
    {
        "form_selector": str | None,
        "username": str | None,
        "password": str | None,
        "submit": str | None,
        "score": int
    }
    или None, если ничего похожего на login‑форму нет.
    """

    forms = page.query_selector_all("form")
    html_lower = page.content().lower()

    candidates: list[dict] = []

    # Если форм нет — пробуем "форму без form" (SPA / дивы)
    if not forms:
        pseudo = detect_login_form_without_form(page)
        return pseudo

    for idx, form in enumerate(forms):
        try:
            form_html = (form.inner_html() or "").lower()
        except Exception:
            form_html = ""

        # Базовый селектор формы
        form_sel = form.evaluate("""
            e => {
                if (e.id) return "form#" + e.id;
                if (e.name) return "form[name='" + e.name + "']";
                return "form";
            }
        """)

        inputs = form.query_selector_all("input, textarea")
        buttons = form.query_selector_all("button, input[type='submit']")

        username_fields = []
        password_fields = []
        submit_buttons = []

        # --- Анализ input'ов ---
        for inp in inputs:
            try:
                t = (inp.get_attribute("type") or "").lower()
                name = (inp.get_attribute("name") or "").lower()
                ph = (inp.get_attribute("placeholder") or "").lower()
                ac = (inp.get_attribute("autocomplete") or "").lower()
            except Exception:
                continue

            sel = inp.evaluate("""
                e => {
                    if (e.id) return "#" + e.id;
                    if (e.name) return "input[name='" + e.name + "']";
                    return null;
                }
            """)

            if not sel:
                continue

            # Пароль
            if t == "password":
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

            if score_u > 0:
                username_fields.append((sel, score_u))

        # --- Анализ кнопок ---
        for b in buttons:
            try:
                text = (b.inner_text() or "").lower()
                onclick = (b.get_attribute("onclick") or "").lower()
            except Exception:
                continue

            sel = b.evaluate("""
                e => {
                    if (e.id) return "#" + e.id;
                    if (e.name) return "button[name='" + e.name + "']";
                    return e.tagName.toLowerCase();
                }
            """)

            if not sel:
                continue

            score_s = 0
            if any(k in text for k in ["login", "sign in", "войти", "авторизация"]):
                score_s += 4
            if any(k in onclick for k in ["login", "auth", "signin"]):
                score_s += 3

            if score_s > 0:
                submit_buttons.append((sel, score_s))

        # --- Подсчёт score формы ---
        score = 0

        # Наличие пароля — главный признак
        if password_fields:
            score += 10

        # Наличие username‑поля
        if username_fields:
            score += 5

        # Наличие submit‑кнопки
        if submit_buttons:
            score += 3

        # Ключевые слова в HTML формы
        if any(k in form_html for k in ["login", "signin", "вход", "авторизация"]):
            score += 4

        # Если нет пароля — это не login‑форма
        if not password_fields:
            continue

        # Выбор лучших полей
        username_sel = None
        if username_fields:
            username_sel = sorted(username_fields, key=lambda x: x[1], reverse=True)[0][0]

        password_sel = password_fields[0]
        submit_sel = None
        if submit_buttons:
            submit_sel = sorted(submit_buttons, key=lambda x: x[1], reverse=True)[0][0]

        candidates.append({
            "form_selector": form_sel,
            "username": username_sel,
            "password": password_sel,
            "submit": submit_sel,
            "score": score,
        })

    if not candidates:
        # Попробуем fallback‑детектор без <form>
        return detect_login_form_without_form(page)

    best = sorted(candidates, key=lambda x: x["score"], reverse=True)[0]
    if best["score"] < 10:
        # Слишком слабый кандидат
        return None

    return best


def detect_login_form_without_form(page) -> dict | None:
    """
    Fallback‑детектор для SPA / див‑форм без <form>.
    Ищет password‑поле + логин + кнопку на всей странице.
    """
    html_lower = page.content().lower()

    inputs = page.query_selector_all("input")
    buttons = page.query_selector_all("button, input[type='submit']")

    username_candidates: list[tuple[str, int]] = []
    password_candidates: list[str] = []
    submit_candidates: list[tuple[str, int]] = []

    for inp in inputs:
        try:
            t = (inp.get_attribute("type") or "").lower()
            name = (inp.get_attribute("name") or "").lower()
            ph = (inp.get_attribute("placeholder") or "").lower()
            ac = (inp.get_attribute("autocomplete") or "").lower()
        except Exception:
            continue

        sel = inp.evaluate("""
            e => {
                if (e.id) return "#" + e.id;
                if (e.name) return "input[name='" + e.name + "']";
                return null;
            }
        """)

        if not sel:
            continue

        if t == "password":
            password_candidates.append(sel)

        score_u = 0
        if t in ("text", "email"):
            score_u += 2
        if any(k in name for k in ["user", "login", "email", "account"]):
            score_u += 3
        if any(k in ph for k in ["user", "email", "логин", "аккаунт"]):
            score_u += 3
        if ac == "username":
            score_u += 4

        if score_u > 0:
            username_candidates.append((sel, score_u))

    for b in buttons:
        try:
            text = (b.inner_text() or "").lower()
            onclick = (b.get_attribute("onclick") or "").lower()
        except Exception:
            continue

        sel = b.evaluate("""
            e => {
                if (e.id) return "#" + e.id;
                if (e.name) return "button[name='" + e.name + "']";
                return e.tagName.toLowerCase();
            }
        """)

        if not sel:
            continue

        score_s = 0
        if any(k in text for k in ["login", "sign in", "войти", "авторизация"]):
            score_s += 4
        if any(k in onclick for k in ["login", "auth", "signin"]):
            score_s += 3

        if score_s > 0:
            submit_candidates.append((sel, score_s))

    if not password_candidates:
        return None

    username_sel = None
    if username_candidates:
        username_sel = sorted(username_candidates, key=lambda x: x[1], reverse=True)[0][0]

    submit_sel = None
    if submit_candidates:
        submit_sel = sorted(submit_candidates, key=lambda x: x[1], reverse=True)[0][0]

    score = 10
    if username_sel:
        score += 5
    if submit_sel:
        score += 3
    if any(k in html_lower for k in ["login", "signin", "вход", "авторизация"]):
        score += 4

    return {
        "form_selector": None,
        "username": username_sel,
        "password": password_candidates[0],
        "submit": submit_sel,
        "score": score,
    }


# ============================
#  AJAX Login Detector
# ============================

def detect_ajax_login(page, before_url=None, before_cookies=None, before_dom=None) -> bool:
    after_url = page.url
    after_cookies = page.context.cookies()
    after_dom = page.content()

    url_static = (before_url == after_url)

    new_session = False
    if before_cookies:
        before_names = {c["name"] for c in before_cookies}
        after_names = {c["name"] for c in after_cookies}
        diff = after_names - before_names
        new_session = any("session" in n.lower() for n in diff)

    dom_changed = before_dom != after_dom if before_dom else False

    ls = page.evaluate("Object.keys(localStorage)")
    ss = page.evaluate("Object.keys(sessionStorage)")
    storage_tokens = any(k.lower() in ["token", "auth", "jwt"] for k in ls + ss)

    xhr_detected = "fetch(" in after_dom or "xhr" in after_dom

    return url_static and (new_session or dom_changed or storage_tokens or xhr_detected)


# ============================
#  OAuth / SSO Detector
# ============================

def detect_oauth(html: str):
    html = html.lower()

    providers = {
        "Google OAuth": ["accounts.google.com", "oauth2", "google-signin"],
        "Facebook Login": ["facebook.com/login", "fb-login"],
        "GitHub OAuth": ["github.com/login/oauth"],
        "Microsoft OAuth": ["login.microsoftonline.com", "azuread"],
        "Okta": ["okta.com", "okta"],
        "Auth0": ["auth0.com", "auth0"],
        "Apple OAuth": ["appleid.apple.com/auth"],
        "GitLab OAuth": ["gitlab.com/oauth"],
        "Yandex OAuth": ["oauth.yandex.ru"],
        "Keycloak": ["/auth/realms/", "keycloak"],
        "OpenID Connect": ["openid-connect", "/.well-known/openid"],
        "SAML": ["saml/login", "samlp", "saml2"],
    }

    detected = [name for name, signs in providers.items() if any(s in html for s in signs)]
    return detected or None


# ============================
#  Session Load / Save
# ============================

def save_session(context):
    try:
        storage = context.storage_state()
        with open("session.json", "w", encoding="utf-8") as f:
            f.write(storage)
        print("[💾] Сессия сохранена.")
    except Exception as e:
        print(f"[❌] Ошибка сохранения сессии: {e}")


def load_session(context) -> bool:
    try:
        if not os.path.exists("session.json"):
            return False
        with open("session.json", "r", encoding="utf-8") as f:
            context.add_cookies([])
            context.set_storage_state(f.read())
        print("[🔄] Сессия загружена.")
        return True
    except Exception:
        return False