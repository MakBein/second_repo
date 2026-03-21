# xss_security_gui/auth/login_flow.py

def perform_login(page, login_config: dict) -> None:
    """
    Базовый логин‑флоу:
    - переход на login URL
    - поиск username/password
    - ввод данных
    - submit
    - проверка успешного входа
    """

    try:
        # 1) Переход на страницу логина
        page.goto(login_config["url"], timeout=20000)
        page.wait_for_timeout(1000)

        # 2) Поля username/password
        user_sel = login_config["selectors"].get("username")
        pass_sel = login_config["selectors"].get("password")

        if user_sel and page.query_selector(user_sel):
            page.fill(user_sel, login_config["username"])

        if pass_sel and page.query_selector(pass_sel):
            page.fill(pass_sel, login_config["password"])

        # 3) Submit
        submit_sel = login_config["selectors"].get("submit")
        if submit_sel and page.query_selector(submit_sel):
            page.click(submit_sel)
        else:
            # fallback
            if user_sel:
                page.press(user_sel, "Enter")

        page.wait_for_timeout(2000)

        # 4) Проверка успешного входа
        html = page.content().lower()
        cookies = page.context.cookies()

        success_checks = [
            page.url != login_config["url"],
            any("session" in c["name"].lower() for c in cookies),
            "logout" in html,
            "profile" in html,
            "account" in html,
        ]

        if any(success_checks):
            print("[🔐] Авторизация успешна.")
        else:
            print("[⚠️] Авторизация, вероятно, не удалась.")

    except Exception as e:
        print(f"[❌] Ошибка авторизации: {e}")