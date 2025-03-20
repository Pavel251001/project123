import bcrypt

# Глобальная переменная для хранения информации об аутентифицированном пользователе
current_user = None

def register_user():
    """Регистрирует нового пользователя с указанием роли."""
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")
    role = input("Введите роль пользователя (admin, moderator, user): ")

    # Проверка допустимости роли
    if role not in ["admin", "moderator", "user"]:
        print("Недопустимая роль. Регистрация отменена.")
        return

    # Хеширование пароля с использованием bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Сохранение информации о пользователе в файл
    with open("users.txt", "a") as f:
        f.write(f"{username}:{hashed_password.decode('utf-8')}:{role}\n")

    print(f"Пользователь {username} с ролью {role} успешно зарегистрирован.")


def authenticate_user():
    """Аутентифицирует пользователя и устанавливает его роль."""
    global current_user  # Используем глобальную переменную
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")

    try:
        with open("users.txt", "r") as f:
            for line in f:
                stored_username, stored_hashed_password, stored_role = line.strip().split(":")
                if username == stored_username:
                    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                        print("Аутентификация прошла успешно!")
                        # Сохраняем информацию о пользователе в глобальной переменной
                        current_user = {"username": username, "role": stored_role}
                        return
                    else:
                        print("Неверный пароль.")
                        return
        print("Пользователь не найден.")

    except FileNotFoundError:
        print("Файл с пользователями не найден. Сначала зарегистрируйтесь.")

def requires_role(role):
    """Декоратор для проверки прав доступа."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            global current_user
            if current_user and current_user["role"] == role:
                return func(*args, **kwargs)
            else:
                print("У вас нет прав для выполнения этой операции.")
        return wrapper
    return decorator


@requires_role("admin")
def admin_function():
    """Функция, доступная только администраторам."""
    print("Вы вошли как администратор.")

@requires_role("moderator")
def moderator_function():
    """Функция, доступная только модераторам."""
    print("Вы вошли как модератор.")

@requires_role("user")
def user_function():
    """Функция, доступная только пользователям."""
    print("Вы вошли как пользователь.")

def main():
    """Основная функция приложения."""
    while True:
        print("\nМеню:")
        print("1. Регистрация")
        print("2. Аутентификация")
        print("3. Админ-функция (только для admin)")
        print("4. Функция модератора (только для moderator)")
        print("5. Функция пользователя (только для user)")
        print("6. Выход")

        choice = input("Выберите действие: ")

        if choice == "1":
            register_user()
        elif choice == "2":
            authenticate_user()
        elif choice == "3":
            admin_function()
        elif choice == "4":
            moderator_function()
        elif choice == "5":
            user_function()
        elif choice == "6":
            break
        else:
            print("Неверный выбор. Попробуйте снова.")
            current_user = None

if __name__ == "__main__":
    main()