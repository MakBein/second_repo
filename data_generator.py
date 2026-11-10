# xss_security_gui/data_generator.py
"""
DataGenerator — библиотека генерации тестовых данных для форм и инпутов.

Генерирует:
• Кредитные карты (Visa, MasterCard, American Express)
• Email адреса
• Пароли
• Имена, фамилии
• Адреса
• Номера телефонов

Используется для тестирования форм, валидации и fuzzing.
"""

import random
import string
from typing import List, Dict, Optional
from datetime import datetime, timedelta


# ============================================================
#  БАЗОВЫЕ ДАННЫЕ ДЛЯ ГЕНЕРАЦИИ
# ============================================================

FIRST_NAMES = [
    "Александр", "Алексей", "Андрей", "Антон", "Артем", "Владимир", "Владислав", "Дмитрий",
    "Евгений", "Иван", "Игорь", "Кирилл", "Максим", "Михаил", "Николай", "Олег", "Павел",
    "Роман", "Сергей", "Станислав", "Тимур", "Федор", "Юрий", "Ярослав",
    "Анна", "Елена", "Ирина", "Кристина", "Мария", "Наталья", "Ольга", "Светлана",
    "Татьяна", "Юлия", "Яна", "Алина", "Виктория", "Дарья", "Екатерина", "Ксения"
]

LAST_NAMES = [
    "Иванов", "Петров", "Сидоров", "Кузнецов", "Смирнов", "Попов", "Васильев", "Михайлов",
    "Федоров", "Соколов", "Яковлев", "Алексеев", "Лебедев", "Егоров", "Павлов", "Семенов",
    "Григорьев", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин", "Зайцев"
]

CITIES = [
    "Москва", "Санкт-Петербург", "Новосибирск", "Екатеринбург", "Казань", "Нижний Новгород",
    "Челябинск", "Самара", "Омск", "Ростов-на-Дону", "Уфа", "Красноярск", "Воронеж",
    "Пермь", "Волгоград", "Краснодар", "Саратов", "Тюмень", "Тольятти", "Ижевск"
]

STREETS = [
    "Ленинская", "Пушкинская", "Гагарина", "Мира", "Советская", "Кирова", "Лермонтова",
    "Чехова", "Тургенева", "Гоголя", "Достоевского", "Толстого", "Некрасова", "Маяковского"
]

DOMAINS = [
    "gmail.com", "yandex.ru", "mail.ru", "outlook.com", "yahoo.com", "rambler.ru",
    "inbox.ru", "list.ru", "bk.ru", "hotmail.com", "live.com", "icloud.com"
]

PHONE_PREFIXES = [
    "+7", "+375", "+380", "+994", "+374", "+7-9", "+7-499", "+7-812", "+7-495"
]


# ============================================================
#  ГЕНЕРАТОРЫ ДАННЫХ
# ============================================================

def generate_credit_card(card_type: str = "random") -> str:
    """
    Генерирует номер кредитной карты с валидной контрольной суммой (Luhn algorithm).

    :param card_type: 'visa', 'mastercard', 'amex', 'random'
    :return: строка с номером карты
    """
    if card_type == "random":
        card_type = random.choice(["visa", "mastercard", "amex"])

    if card_type == "visa":
        prefix = random.choice(["4"])
        length = 16
    elif card_type == "mastercard":
        prefix = random.choice(["5", "2"])
        length = 16
    elif card_type == "amex":
        prefix = random.choice(["34", "37"])
        length = 15
    else:
        prefix = "4"
        length = 16

    # Генерируем цифры
    digits = [int(d) for d in prefix]
    while len(digits) < length - 1:
        digits.append(random.randint(0, 9))

    # Вычисляем контрольную сумму (Luhn)
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 0:
            doubled = digit * 2
            total += doubled if doubled < 10 else doubled - 9
        else:
            total += digit

    check_digit = (10 - (total % 10)) % 10
    digits.append(check_digit)

    return ''.join(map(str, digits))


def generate_email(name: Optional[str] = None, domain: Optional[str] = None) -> str:
    """
    Генерирует email адрес.

    :param name: опциональное имя пользователя
    :param domain: опциональный домен
    :return: email строка
    """
    if not name:
        first = random.choice(FIRST_NAMES).lower()
        last = random.choice(LAST_NAMES).lower()
        name = f"{first}.{last}{random.randint(1, 999)}"

    if not domain:
        domain = random.choice(DOMAINS)

    return f"{name}@{domain}"


def generate_password(length: int = 12, complexity: str = "mixed") -> str:
    """
    Генерирует пароль.

    :param length: длина пароля
    :param complexity: 'simple', 'mixed', 'complex'
    :return: пароль
    """
    if complexity == "simple":
        chars = string.ascii_lowercase + string.digits
    elif complexity == "mixed":
        chars = string.ascii_letters + string.digits
    else:  # complex
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"

    return ''.join(random.choice(chars) for _ in range(length))


def generate_name() -> str:
    """
    Генерирует полное имя (имя + фамилия).

    :return: строка с именем
    """
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    return f"{first} {last}"


def generate_address() -> str:
    """
    Генерирует адрес.

    :return: строка с адресом
    """
    city = random.choice(CITIES)
    street = random.choice(STREETS)
    building = random.randint(1, 200)
    apartment = random.randint(1, 999)

    return f"{city}, ул. {street}, д. {building}, кв. {apartment}"


def generate_phone_number(format_type: str = "international") -> str:
    """
    Генерирует номер телефона.

    :param format_type: 'international', 'local', 'formatted'
    :return: номер телефона
    """
    prefix = random.choice(PHONE_PREFIXES)

    if format_type == "international":
        if prefix == "+7":
            number = f"{prefix}{random.randint(9000000000, 9999999999)}"
        else:
            number = f"{prefix}{random.randint(10000000, 99999999)}"
    elif format_type == "local":
        number = f"8{random.randint(9000000000, 9999999999)}"
    else:  # formatted
        if prefix == "+7":
            number = f"{prefix} ({random.randint(900, 999)}) {random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(10, 99)}"
        else:
            number = f"{prefix} {random.randint(10000000, 99999999)}"

    return number


def generate_birth_date(min_age: int = 18, max_age: int = 80) -> str:
    """
    Генерирует дату рождения.

    :param min_age: минимальный возраст
    :param max_age: максимальный возраст
    :return: дата в формате YYYY-MM-DD
    """
    today = datetime.now()
    start_date = today - timedelta(days=max_age * 365)
    end_date = today - timedelta(days=min_age * 365)

    random_date = start_date + timedelta(days=random.randint(0, (end_date - start_date).days))
    return random_date.strftime("%Y-%m-%d")


# ============================================================
#  КОМПЛЕКСНЫЕ ГЕНЕРАТОРЫ
# ============================================================

def generate_user_profile() -> Dict[str, str]:
    """
    Генерирует полный профиль пользователя.

    :return: словарь с данными пользователя
    """
    name = generate_name()
    first_name, last_name = name.split()

    return {
        "first_name": first_name,
        "last_name": last_name,
        "full_name": name,
        "email": generate_email(f"{first_name.lower()}.{last_name.lower()}", None),
        "password": generate_password(),
        "phone": generate_phone_number(),
        "address": generate_address(),
        "birth_date": generate_birth_date(),
        "credit_card": generate_credit_card(),
    }


def generate_form_data(fields: List[str], count: int = 1) -> List[Dict[str, str]]:
    """
    Генерирует данные для формы на основе списка полей.

    :param fields: список названий полей
    :param count: количество записей для генерации
    :return: список словарей с данными
    """
    results = []

    for _ in range(count):
        data = {}
        for field in fields:
            field_lower = field.lower()

            if "email" in field_lower:
                data[field] = generate_email()
            elif "password" in field_lower or "pass" in field_lower:
                data[field] = generate_password()
            elif "name" in field_lower:
                if "first" in field_lower:
                    data[field] = random.choice(FIRST_NAMES)
                elif "last" in field_lower:
                    data[field] = random.choice(LAST_NAMES)
                else:
                    data[field] = generate_name()
            elif "phone" in field_lower or "tel" in field_lower:
                data[field] = generate_phone_number()
            elif "address" in field_lower:
                data[field] = generate_address()
            elif "credit" in field_lower or "card" in field_lower:
                data[field] = generate_credit_card()
            elif "birth" in field_lower or "date" in field_lower:
                data[field] = generate_birth_date()
            else:
                # Для неизвестных полей генерируем случайную строку
                data[field] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

        results.append(data)

    return results


# ============================================================
#  BATCH ГЕНЕРАЦИЯ
# ============================================================

def generate_credit_cards(count: int = 10, card_type: str = "random") -> List[str]:
    """Генерирует список номеров кредитных карт."""
    return [generate_credit_card(card_type) for _ in range(count)]


def generate_emails(count: int = 10) -> List[str]:
    """Генерирует список email адресов."""
    return [generate_email() for _ in range(count)]


def generate_passwords(count: int = 10, length: int = 12) -> List[str]:
    """Генерирует список паролей."""
    return [generate_password(length) for _ in range(count)]


def generate_names(count: int = 10) -> List[str]:
    """Генерирует список имен."""
    return [generate_name() for _ in range(count)]


def generate_addresses(count: int = 10) -> List[str]:
    """Генерирует список адресов."""
    return [generate_address() for _ in range(count)]


def generate_phone_numbers(count: int = 10) -> List[str]:
    """Генерирует список номеров телефонов."""
    return [generate_phone_number() for _ in range(count)]


# ============================================================
#  ЭКСПОРТ ДАННЫХ
# ============================================================

def export_to_json(data: List[Dict], filename: str) -> None:
    """
    Экспортирует сгенерированные данные в JSON файл.

    :param data: список словарей с данными
    :param filename: имя файла
    """
    import json
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def export_to_csv(data: List[Dict], filename: str) -> None:
    """
    Экспортирует сгенерированные данные в CSV файл.

    :param data: список словарей с данными
    :param filename: имя файла
    """
    import csv
    if not data:
        return

    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)


# ============================================================
#  ПРИМЕР ИСПОЛЬЗОВАНИЯ
# ============================================================

if __name__ == "__main__":
    # Примеры генерации
    print("Кредитная карта:", generate_credit_card())
    print("Email:", generate_email())
    print("Пароль:", generate_password())
    print("Имя:", generate_name())
    print("Адрес:", generate_address())
    print("Телефон:", generate_phone_number())
    print("Дата рождения:", generate_birth_date())

    print("\nПрофиль пользователя:")
    profile = generate_user_profile()
    for key, value in profile.items():
        print(f"  {key}: {value}")

    print("\nГенерация данных для формы:")
    form_data = generate_form_data(["name", "email", "password", "phone", "address"], 3)
    for i, data in enumerate(form_data, 1):
        print(f"Запись {i}: {data}")
